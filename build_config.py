#!/usr/bin/env python3
"""
build_config.py — финальный сборщик VPN-конфигов для xray-core клиентов.
Сборки: 🏳️LTE-1 (РУ-SNI, white+extra), 🏳️LTE-2(no-ru), 🏳️LTE-3 (extra), 🏴Wi-Fi-1 (black).
Чёрный список НЕ участвует в LTE-сборках — он только для вайфая.
Платные конфиги не сортируются — как пришли, так и лежат.
"""
from __future__ import annotations
import asyncio, base64, json, os, re, ssl, sys, time, urllib.parse, ipaddress
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple
import copy

# ===== КОНФИГУРАЦИЯ =====
PAID_SUB_URL = os.environ.get("PAID_SUB_URL", "")

WHITE_URLS = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
]
BLACK_URLS = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS_mobile.txt",
    "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/1.txt",
]
EXTRA_URLS = [
    "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/26.txt",
]

TCP_TIMEOUT = 7.0
PING_BATCH = 300
RETRY_ATTEMPTS = 3

MAX_LTE1 = 100    # 🏳️LTE-1
MAX_LTE2 = 100    # 🏳️LTE-2(no-ru) — как в старых рабочих версиях (80-150)
MAX_LTE3 = 100    # 🏳️LTE-3
MAX_WIFI = 100    # 🏴Wi-Fi-1

VALID_FINGERPRINTS = {"chrome", "firefox", "edge", "safari", "ios", "android", "qq", "random"}

# Транспорты, которые реально живут в xray-core. Всё остальное выкидываем —
# один кривой outbound убивает ВЕСЬ конфиг при парсе.
SUPPORTED_NETWORKS = {"tcp", "raw", "ws", "websocket", "grpc", "gun", "httpupgrade"}
NETWORK_NORMALIZE = {"raw": "tcp", "websocket": "ws", "gun": "grpc"}

EXCLUDE_PATTERN = re.compile(r"(Россия|anycast|Беларусь|🇷|🇧🇾|Russia|Belarus)", re.IGNORECASE)

_SECRET_PATTERN = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    r"|(?<=://)[^@/\s]{10,}(?=@)"
)

# ===== РУ-СЕРВИСЫ НАПРЯМУЮ (без Сбера/Тинькофф) =====
RU_DIRECT_DOMAINS = [
    "yandex.ru", "yandex.com", "ya.ru", "dzen.ru", "dzen.com",
    "maps.yandex.ru", "taxi.yandex.ru", "eda.yandex.ru",
    "market.yandex.ru", "music.yandex.ru", "weather.yandex.ru",
    "travel.yandex.ru", "kinopoisk.ru", "auto.ru", "realty.yandex.ru",
    "mail.ru", "vk.com", "vk.ru", "ok.ru", "rambler.ru",
    "rbc.ru", "rg.ru", "tass.ru", "lenta.ru",
    "ivi.ru", "okko.tv", "kion.ru", "rutube.ru",
    "bitrix24.ru", "kontur.ru", "sbis.ru", "getcourse.ru",
    "habr.com", "habr.ru",
    "2gis.ru", "2gis.com", "drom.ru",
    "wildberries.ru", "wildberries.com", "ozon.ru", "avito.ru", "cian.ru",
    "gosuslugi.ru",
    "vtb.ru", "alfabank.ru", "gazprombank.ru",
    "uchi.ru", "dnevnik.ru",
    "yoomoney.ru", "mvideo.ru", "eldorado.ru", "detmir.ru",
    "mos.ru", "nalog.ru",
]
RU_DOMAIN_SUFFIXES = [f".{d}" for d in RU_DIRECT_DOMAINS]

# ===== SNI, которые оператор пропускает на LTE (как у платных ОБХОД LTE) =====
LTE_SNI_WHITELIST = (
    "vk.com", "yandex.ru", "ya.ru", "x5.ru", "yandexcloud.net",
    "max.ru", "rutube.ru", "ozon.ru", "gosuslugi.ru", "mail.ru",
    "mediavitrina.ru", "trbcdn.net", "ngenix.net",
)


def mask_secret(t): return _SECRET_PATTERN.sub("<REDACTED>", t)
def log(msg): print(mask_secret(msg), flush=True)
def log_err(msg): print(mask_secret(msg), file=sys.stderr, flush=True)


def clean_fingerprint(fp):
    if not fp: return "chrome"
    cleaned = re.sub(r"[#|*].*", "", fp).strip().lower()
    return cleaned if cleaned in VALID_FINGERPRINTS else "chrome"

def is_excluded_region(remarks): return bool(remarks and EXCLUDE_PATTERN.search(remarks))

def normalize_address(addr):
    if addr.startswith("[") and addr.endswith("]"): return addr[1:-1]
    return addr

def bracket_if_ipv6(addr):
    if ":" in addr and not addr.startswith("["): return f"[{addr}]"
    return addr

def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

def is_lte_compatible(p) -> bool:
    """Живёт ли конфиг на LTE: смотрим SNI в reality/tls."""
    stream = p.outbound.get("streamSettings", {})
    sni = ""
    if stream.get("security") == "reality":
        sni = stream.get("realitySettings", {}).get("serverName", "")
    elif stream.get("security") == "tls":
        sni = stream.get("tlsSettings", {}).get("serverName", "")
    if not sni:
        return False
    sni = sni.lower()
    return any(sni == d or sni.endswith("." + d) for d in LTE_SNI_WHITELIST)


async def fetch_url(url, timeout=15.0):
    for attempt in range(RETRY_ATTEMPTS):
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sL", "--max-time", str(timeout), url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout + 5)
            if proc.returncode == 0:
                return stdout.decode(errors="ignore").strip()
            log_err(f"⚠️ curl error {proc.returncode} for {url} (attempt {attempt+1})")
        except Exception as e:
            log_err(f"⚠️ fetch error for {url}: {e} (attempt {attempt+1})")
        if attempt < RETRY_ATTEMPTS - 1:
            await asyncio.sleep(2 ** attempt)
    return None


def create_config_template(remarks_text):
    """Шаблон как в старых РАБОЧИХ версиях + expected 4 как у платных."""
    return {
        "log": {"loglevel": "warning"},
        "dns": {
            "servers": ["8.8.8.8", "9.9.9.9"],
            "queryStrategy": "UseIPv4"
        },
        "inbounds": [
            {
                "listen": "127.0.0.1", "port": 10808, "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True, "userLevel": 8},
                "sniffing": {"destOverride": ["http", "tls", "quic"], "enabled": True, "routeOnly": False},
                "tag": "socks"
            },
            {
                "listen": "127.0.0.1", "port": 10809, "protocol": "http",
                "settings": {"userLevel": 8},
                "tag": "http"
            },
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "domainMatcher": "hybrid",
            "rules": [
                {"type": "field", "protocol": ["bittorrent"], "outboundTag": "direct"},
                {"type": "field", "domain": RU_DIRECT_DOMAINS, "outboundTag": "direct"},
                {"type": "field", "domain": RU_DOMAIN_SUFFIXES, "outboundTag": "direct"},
                {"type": "field", "network": "tcp,udp", "balancerTag": "WL_Balancer"}
            ],
            "balancers": [{
                "tag": "WL_Balancer",
                "selector": [],
                "strategy": {
                    "type": "leastLoad",
                    "settings": {
                        "maxRTT": "7s",
                        "expected": 4,
                        "baselines": ["500ms", "1500ms", "3000ms"],
                        "tolerance": 0.1
                    }
                },
                "fallbackTag": "direct"
            }]
        },
        "burstObservatory": {
            "pingConfig": {
                "timeout": "7s",
                "interval": "2m",
                "sampling": 2,
                "destination": "http://www.gstatic.com/generate_204"
            },
            "subjectSelector": []
        },
        "outbounds": [],
        "remarks": remarks_text,
    }


def strip_balancer_for_empty(config):
    config["routing"]["rules"] = [
        {"type": "field", "protocol": ["bittorrent"], "outboundTag": "direct"},
        {"type": "field", "network": "tcp,udp", "outboundTag": "direct"}
    ]
    config["routing"].pop("balancers", None)
    config.pop("burstObservatory", None)
    config["outbounds"] = [
        {"protocol": "freedom", "settings": {"domainStrategy": "UseIPv4"}, "tag": "direct"},
        {"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"}
    ]
    return config


def create_single_outbound_config(outbound, remarks):
    if not remarks:
        remarks = (outbound.get("remarks") or outbound.get("serverName")
                   or outbound.get("address") or outbound.get("server") or "Платная подписка")
    config = create_config_template(remarks)
    ob_copy = copy.deepcopy(outbound)
    ob_copy["tag"] = "paid-1"
    config["outbounds"] = [
        ob_copy,
        {"protocol": "freedom", "settings": {"domainStrategy": "UseIPv4"}, "tag": "direct"},
        {"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"}
    ]
    config["routing"]["balancers"][0]["selector"] = ["paid-1"]
    config["burstObservatory"]["subjectSelector"] = ["paid-1"]
    return config


@dataclass
class ParsedProxy:
    outbound: Dict[str, Any]
    remarks: str
    address: str
    port: int


class ProtocolHandler(ABC):
    scheme: str
    @abstractmethod
    def parse(self, raw_url: str) -> Optional[ParsedProxy]: ...
    @abstractmethod
    def generate(self, outbound: Dict[str, Any], remarks: Optional[str]) -> Optional[str]: ...

    @staticmethod
    def split_remarks(raw_url):
        url_str = raw_url.strip(); remarks = ""
        if "#" in url_str:
            url_str, remarks = url_str.split("#", 1)
            remarks = urllib.parse.unquote(remarks.strip())
        return url_str, remarks

    @staticmethod
    def norm_network(raw: str) -> Optional[str]:
        n = (raw or "tcp").lower()
        n = NETWORK_NORMALIZE.get(n, n)
        return n if n in SUPPORTED_NETWORKS else None


class VlessHandler(ProtocolHandler):
    scheme = "vless://"

    def parse(self, raw_url):
        url_str, remarks = self.split_remarks(raw_url)
        if not url_str.startswith(self.scheme): return None
        try:
            parsed = urllib.parse.urlparse(url_str)
            user_id, address_raw, port = parsed.username, parsed.hostname, parsed.port or 443
            if not user_id or not address_raw: return None
            address = normalize_address(address_raw)
            params = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items() if v}

            network = self.norm_network(params.get("type"))
            if network is None: return None

            fingerprint = clean_fingerprint(params.get("fp") or params.get("fingerprint"))
            is_reality = ("pbk" in params) or ("publicKey" in params) or (params.get("security") == "reality")
            if is_reality and not (params.get("pbk") or params.get("publicKey")): return None

            stream: Dict[str, Any] = {"network": network,
                                      "security": "reality" if is_reality else "tls"}
            if network == "tcp":
                stream["tcpSettings"] = {"header": {"type": params.get("headerType", "none")}}
            elif network == "ws":
                ws = {"path": params.get("path", "/")}
                if params.get("host"): ws["headers"] = {"Host": params["host"]}
                stream["wsSettings"] = ws
            elif network == "grpc":
                stream["grpcSettings"] = {"serviceName": params.get("serviceName", "")}
            elif network == "httpupgrade":
                stream["httpUpgradeSettings"] = {"path": params.get("path", "/"),
                                                 "host": params.get("host", "")}

            outbound = {
                "tag": None, "protocol": "vless",
                "settings": {"vnext": [{
                    "address": address, "port": port,
                    "users": [{"id": user_id, "encryption": "none",
                               "flow": params.get("flow", ""), "level": 8}]
                }]},
                "streamSettings": stream,
            }

            if is_reality:
                reality = {
                    "allowInsecure": False,
                    "fingerprint": fingerprint,
                    "publicKey": params.get("pbk") or params.get("publicKey") or "",
                    "serverName": params.get("sni", address),
                    "shortId": params.get("sid", ""),
                    "show": False,
                }
                if params.get("spx"): reality["spiderX"] = params["spx"]
                stream["realitySettings"] = reality
            else:
                stream["tlsSettings"] = {
                    "allowInsecure": False,
                    "serverName": params.get("sni", address),
                    "fingerprint": fingerprint
                }

            outbound["remarks"] = remarks
            return ParsedProxy(outbound, remarks, address, port)
        except Exception:
            return None

    def generate(self, outbound, remarks):
        try:
            vnext = outbound["settings"]["vnext"][0]
            address, port = vnext["address"], vnext["port"]
            user = vnext["users"][0]
            stream = outbound.get("streamSettings", {})
            network, security = stream.get("network", "tcp"), stream.get("security", "")

            params = {"encryption": user.get("encryption", "none")}
            if user.get("flow"): params["flow"] = user["flow"]
            if security: params["security"] = security
            if network != "tcp": params["type"] = network

            if network == "ws":
                ws = stream.get("wsSettings", {})
                if ws.get("path"): params["path"] = ws["path"]
                if ws.get("headers", {}).get("Host"): params["host"] = ws["headers"]["Host"]
            elif network == "grpc":
                svc = stream.get("grpcSettings", {}).get("serviceName")
                if svc: params["serviceName"] = svc
            elif network == "httpupgrade":
                hu = stream.get("httpUpgradeSettings", {})
                if hu.get("path"): params["path"] = hu["path"]
                if hu.get("host"): params["host"] = hu["host"]

            if security == "reality":
                r = stream.get("realitySettings", {})
                for k, v in {"sni": r.get("serverName"), "fp": r.get("fingerprint"),
                             "pbk": r.get("publicKey"), "sid": r.get("shortId"),
                             "spx": r.get("spiderX")}.items():
                    if v: params[k] = v
            elif security == "tls":
                t = stream.get("tlsSettings", {})
                for k, v in {"sni": t.get("serverName"), "fp": t.get("fingerprint")}.items():
                    if v: params[k] = v

            url = f"vless://{user['id']}@{bracket_if_ipv6(address)}:{port}"
            if params: url += "?" + "&".join(f"{k}={urllib.parse.quote(str(v))}" for k, v in params.items())
            if remarks: url += "#" + urllib.parse.quote(remarks)
            return url
        except Exception:
            return None


class Hysteria2Handler(ProtocolHandler):
    scheme = "hysteria2://"

    def parse(self, raw_url):
        url_str, remarks = self.split_remarks(raw_url)
        if not url_str.startswith(self.scheme): return None
        try:
            parsed = urllib.parse.urlparse(url_str)
            auth, address_raw, port = parsed.username, parsed.hostname, parsed.port or 443
            if not auth or not address_raw: return None
            address = normalize_address(address_raw)
            params = urllib.parse.parse_qs(parsed.query)
            alpn = params.get("alpn", [None])[0]
            outbound = {
                "tag": None, "protocol": "hysteria2",
                "settings": {"servers": [{
                    "address": address, "port": port, "auth": auth,
                    "sni": params.get("sni", [address])[0],
                    "fingerprint": params.get("fingerprint", ["chrome"])[0],
                    "insecure": params.get("insecure", ["0"])[0] == "1",
                    "alpn": alpn.split(",") if alpn else [],
                }]},
            }
            outbound["remarks"] = remarks
            return ParsedProxy(outbound, remarks, address, port)
        except Exception:
            return None

    def generate(self, outbound, remarks):
        try:
            s = outbound["settings"]["servers"][0]
            address, port, auth = s.get("address"), s.get("port"), s.get("auth")
            if not (address and port and auth): return None
            params = {}
            if s.get("sni"): params["sni"] = s["sni"]
            if s.get("fingerprint"): params["fingerprint"] = s["fingerprint"]
            if s.get("insecure"): params["insecure"] = "1"
            if s.get("alpn"): params["alpn"] = ",".join(s["alpn"])
            url = f"hysteria2://{auth}@{bracket_if_ipv6(address)}:{port}"
            if params: url += "?" + "&".join(f"{k}={urllib.parse.quote(str(v))}" for k, v in params.items())
            if remarks: url += "#" + urllib.parse.quote(remarks)
            return url
        except Exception:
            return None


class TrojanHandler(ProtocolHandler):
    scheme = "trojan://"

    def parse(self, raw_url):
        url_str, remarks = self.split_remarks(raw_url)
        if not url_str.startswith(self.scheme): return None
        try:
            parsed = urllib.parse.urlparse(url_str)
            password, address_raw, port = parsed.username, parsed.hostname, parsed.port or 443
            if not password or not address_raw: return None
            params = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items() if v}
            network = self.norm_network(params.get("type"))
            if network is None: return None
            address = normalize_address(address_raw)
            stream: Dict[str, Any] = {"network": network, "security": "tls"}
            if network == "ws":
                ws = {"path": params.get("path", "/")}
                if params.get("host"): ws["headers"] = {"Host": params["host"]}
                stream["wsSettings"] = ws
            elif network == "grpc":
                stream["grpcSettings"] = {"serviceName": params.get("serviceName", "")}
            stream["tlsSettings"] = {
                "allowInsecure": params.get("allowInsecure", "0") == "1",
                "serverName": params.get("sni", address),
                "fingerprint": clean_fingerprint(params.get("fingerprint")),
            }
            outbound = {
                "tag": None, "protocol": "trojan",
                "settings": {"servers": [{"address": address, "port": port, "password": password}]},
                "streamSettings": stream,
            }
            outbound["remarks"] = remarks
            return ParsedProxy(outbound, remarks, address, port)
        except Exception:
            return None

    def generate(self, outbound, remarks):
        try:
            s = outbound["settings"]["servers"][0]
            address, port, password = s.get("address"), s.get("port"), s.get("password")
            if not (address and port and password): return None
            stream = outbound.get("streamSettings", {})
            t = stream.get("tlsSettings", {})
            params = {}
            if stream.get("network") and stream["network"] != "tcp": params["type"] = stream["network"]
            if stream.get("network") == "ws":
                ws = stream.get("wsSettings", {})
                if ws.get("path"): params["path"] = ws["path"]
                if ws.get("headers", {}).get("Host"): params["host"] = ws["headers"]["Host"]
            elif stream.get("network") == "grpc":
                svc = stream.get("grpcSettings", {}).get("serviceName")
                if svc: params["serviceName"] = svc
            if t.get("serverName"): params["sni"] = t["serverName"]
            if t.get("fingerprint"): params["fp"] = t["fingerprint"]
            if t.get("allowInsecure"): params["allowInsecure"] = "1"
            url = f"trojan://{password}@{bracket_if_ipv6(address)}:{port}"
            if params: url += "?" + "&".join(f"{k}={urllib.parse.quote(str(v))}" for k, v in params.items())
            if remarks: url += "#" + urllib.parse.quote(remarks)
            return url
        except Exception:
            return None


class ShadowsocksHandler(ProtocolHandler):
    scheme = "ss://"

    def parse(self, raw_url):
        url_str, remarks = self.split_remarks(raw_url)
        if not url_str.startswith(self.scheme): return None
        try:
            content = url_str[len(self.scheme):]
            if "@" in content:
                userinfo, hostport = content.split("@", 1)
                decoded = base64.urlsafe_b64decode(userinfo + "=" * (-len(userinfo) % 4)).decode()
                method, password = decoded.split(":", 1)
            else:
                decoded = base64.urlsafe_b64decode(content + "=" * (-len(content) % 4)).decode()
                userinfo, hostport = decoded.split("@", 1)
                method, password = userinfo.split(":", 1)
            address_raw, port_str = hostport.rsplit(":", 1)
            address, port = normalize_address(address_raw), int(port_str)
            outbound = {
                "tag": None, "protocol": "shadowsocks",
                "settings": {"servers": [{"address": address, "port": port,
                                          "method": method, "password": password}]},
            }
            outbound["remarks"] = remarks
            return ParsedProxy(outbound, remarks, address, port)
        except Exception:
            return None

    def generate(self, outbound, remarks):
        try:
            s = outbound["settings"]["servers"][0]
            address, port, method, password = s.get("address"), s.get("port"), s.get("method"), s.get("password")
            if not all([address, port, method, password]): return None
            b64 = base64.urlsafe_b64encode(f"{method}:{password}".encode()).decode().rstrip("=")
            url = f"ss://{b64}@{bracket_if_ipv6(address)}:{port}"
            if remarks: url += "#" + urllib.parse.quote(remarks)
            return url
        except Exception:
            return None


class VmessHandler(ProtocolHandler):
    scheme = "vmess://"

    def parse(self, raw_url):
        url_str, remarks = self.split_remarks(raw_url)
        if not url_str.startswith(self.scheme): return None
        try:
            b64 = url_str[len(self.scheme):]
            b64 += "=" * (-len(b64) % 4)
            cfg = json.loads(base64.urlsafe_b64decode(b64).decode())
            address, uuid = cfg.get("add", ""), cfg.get("id", "")
            if not address or not uuid: return None
            port = int(cfg.get("port", 443))
            address = normalize_address(address)

            network = self.norm_network(cfg.get("net"))
            if network is None: return None
            tls = cfg.get("tls", "")

            stream: Dict[str, Any] = {"network": network, "security": "tls" if tls == "tls" else "none"}
            host, path = cfg.get("host", ""), cfg.get("path", "")
            if network == "ws":
                ws = {"path": path}
                if host: ws["headers"] = {"Host": host}
                stream["wsSettings"] = ws
            elif network == "grpc":
                stream["grpcSettings"] = {"serviceName": path.lstrip("/")}
            if tls == "tls":
                stream["tlsSettings"] = {
                    "serverName": cfg.get("sni") or address,
                    "fingerprint": clean_fingerprint(cfg.get("fp")),
                    "allowInsecure": False,
                }

            outbound = {
                "tag": None, "protocol": "vmess",
                "settings": {"vnext": [{
                    "address": address, "port": port,
                    "users": [{"id": uuid, "alterId": int(cfg.get("aid", 0)),
                               "security": cfg.get("scy", "auto"), "level": 8}]
                }]},
                "streamSettings": stream,
            }
            outbound["remarks"] = remarks
            return ParsedProxy(outbound, remarks, address, port)
        except Exception:
            return None

    def generate(self, outbound, remarks):
        try:
            vnext = outbound["settings"]["vnext"][0]
            user = vnext["users"][0]
            stream = outbound.get("streamSettings", {})
            network, tls = stream.get("network", "tcp"), stream.get("security", "none")
            cfg = {
                "v": "2", "ps": remarks or "", "add": vnext["address"], "port": vnext["port"],
                "id": user["id"], "aid": user.get("alterId", 0), "scy": user.get("security", "auto"),
                "net": network, "type": "none", "host": "", "path": "",
                "tls": "tls" if tls == "tls" else "", "sni": "", "fp": "chrome",
            }
            if network == "ws":
                ws = stream.get("wsSettings", {})
                cfg["path"] = ws.get("path", "")
                cfg["host"] = ws.get("headers", {}).get("Host", "")
            elif network == "grpc":
                cfg["path"] = stream.get("grpcSettings", {}).get("serviceName", "")
            if tls == "tls":
                t = stream.get("tlsSettings", {})
                cfg["sni"], cfg["fp"] = t.get("serverName", ""), t.get("fingerprint", "chrome")
            b64 = base64.urlsafe_b64encode(json.dumps(cfg).encode()).decode().rstrip("=")
            url = f"vmess://{b64}"
            if remarks: url += "#" + urllib.parse.quote(remarks)
            return url
        except Exception:
            return None


PROTOCOL_REGISTRY = [
    VlessHandler(), Hysteria2Handler(), TrojanHandler(), ShadowsocksHandler(), VmessHandler(),
]


def parse_proxy_url(raw_url):
    url = raw_url.strip()
    for handler in PROTOCOL_REGISTRY:
        if url.startswith(handler.scheme):
            return handler.parse(url)
    return None


async def get_links_from_urls(urls):
    all_links = []
    schemes = tuple(h.scheme for h in PROTOCOL_REGISTRY)
    for url in urls:
        log(f"📥 Downloading: {url}")
        content = await fetch_url(url)
        if content:
            for line in content.splitlines():
                line = line.strip()
                if line.startswith(schemes):
                    all_links.append(line)
    return list(dict.fromkeys(all_links))


# ===== ПИНГ (только LTE-3 и Wi-Fi-1) =====
async def tcp_ping(host, port, timeout=TCP_TIMEOUT):
    start = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        try: await asyncio.wait_for(writer.wait_closed(), timeout=1)
        except Exception: pass
        return time.monotonic() - start
    except Exception:
        return None


async def tls_ping(host, port, timeout=TCP_TIMEOUT):
    start = time.monotonic()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sni = "" if _is_ip(host) else host
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=sni), timeout=timeout)
        writer.close()
        try: await asyncio.wait_for(writer.wait_closed(), timeout=1)
        except Exception: pass
        return time.monotonic() - start
    except Exception:
        return None


async def check_server(p: ParsedProxy):
    if p.outbound.get("protocol") in ("vless", "vmess", "trojan"):
        return await tls_ping(p.address, p.port)
    return await tcp_ping(p.address, p.port)


async def ping_candidates(parsed_candidates):
    """Уникальные (address,port), батчами, с прогрессом и второй попыткой."""
    uniq: Dict[Tuple[str, int], ParsedProxy] = {}
    for p in parsed_candidates:
        uniq.setdefault((p.address, p.port), p)
    items = list(uniq.values())
    total = len(items)
    log(f"   🌐 Unique servers: {total} (from {len(parsed_candidates)} links)")

    rtt_map: Dict[Tuple[str, int], Optional[float]] = {}
    for i in range(0, total, PING_BATCH):
        batch = items[i:i + PING_BATCH]
        results = await asyncio.gather(*(check_server(p) for p in batch))
        for p, rtt in zip(batch, results):
            rtt_map[(p.address, p.port)] = rtt
        log(f"   ⏳ Progress: {min(i + PING_BATCH, total)}/{total}")

    dead = [uniq[k] for k, rtt in rtt_map.items() if rtt is None]
    if dead:
        log(f"   🔄 Retry: {len(dead)} не ответили, второй шанс")
        for i in range(0, len(dead), PING_BATCH):
            batch = dead[i:i + PING_BATCH]
            results = await asyncio.gather(*(check_server(p) for p in batch))
            for p, rtt in zip(batch, results):
                if rtt is not None:
                    rtt_map[(p.address, p.port)] = rtt
    return rtt_map


@dataclass
class Candidate:
    outbound: Dict[str, Any]
    remarks: str
    address: str
    port: int
    rtt: float = 0.0
    source: str = ""


async def check_and_create_balancer(
    parsed_candidates, source_name, max_servers,
    remarks_ok_template, remarks_fail,
    reserve_candidates=None, reserve_filter=None,
    use_ping=True,
):
    log(f"\n🔍 Checking source: {source_name} (total {len(parsed_candidates)})")
    fail_config = strip_balancer_for_empty(create_config_template(remarks_fail))
    if not parsed_candidates:
        return fail_config, []

    if use_ping:
        rtt_map = await ping_candidates(parsed_candidates)
        alive = [Candidate(p.outbound, p.remarks, p.address, p.port,
                           rtt_map[(p.address, p.port)], source_name)
                 for p in parsed_candidates if rtt_map.get((p.address, p.port)) is not None]
    else:
        # Как в старых рабочих версиях: без пинга, клиент сам выберет с телефона
        log(f"   ⏭️ Без пинга — проверку оставлю балансировщику клиента")
        alive = [Candidate(p.outbound, p.remarks, p.address, p.port, 0.0, source_name)
                 for p in parsed_candidates]

    log(f"   ✅ Alive: {len(alive)}")
    if not alive:
        return fail_config, []

    alive.sort(key=lambda c: c.rtt)
    best = alive[:max_servers]
    used_addrs = {(c.address, c.port) for c in best}

    # Добор из резерва: резервные сохраняют СВОЁ имя источника (например LTE-3)
    if reserve_candidates:
        added = 0
        for c in sorted(reserve_candidates, key=lambda c: c.rtt):
            if len(best) >= max_servers: break
            if (c.address, c.port) in used_addrs: continue
            if reserve_filter is not None and not reserve_filter(c): continue
            best.append(c)
            used_addrs.add((c.address, c.port))
            added += 1
        if added: log(f"   ➕ Added from reserve: {added}")

    src_count: Dict[str, int] = {}
    for c in best: src_count[c.source] = src_count.get(c.source, 0) + 1
    for src, cnt in src_count.items(): log(f"   📍 {src}: {cnt}")
    log(f"   🏆 Final: {len(best)}")

    outbounds, tags = [], []
    for idx, cand in enumerate(best, start=1):
        # Теги как договорились: LTE-1-3, LTE-2-14, резервные — LTE-3-1 и т.д.
        tag = f"{cand.source}-{idx}"
        ob_copy = copy.deepcopy(cand.outbound)
        ob_copy["tag"] = tag
        outbounds.append(ob_copy)
        tags.append(tag)

    config = create_config_template(remarks_ok_template.format(count=len(best)))
    config["outbounds"] = outbounds + [
        {"protocol": "freedom", "settings": {"domainStrategy": "UseIPv4"}, "tag": "direct"},
        {"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"},
    ]
    config["routing"]["balancers"][0]["selector"] = tags
    config["burstObservatory"]["subjectSelector"] = tags
    return config, alive


# ===== ПЛАТНАЯ ПОДПИСКА (без сортировки — как приходит) =====
def _extract_server_from_dict(item):
    address = item.get("server") or item.get("address") or item.get("host")
    port = item.get("port") or item.get("port_number")
    if address and port:
        return {"address": normalize_address(address), "port": int(port),
                "protocol": item.get("type") or item.get("protocol") or "unknown",
                "remarks": item.get("remarks") or item.get("name") or ""}
    return None


def _filter_paid_configs(configs):
    """Только выкидываем НАШИ сгенерированные маркеры, порядок НЕ трогаем."""
    exclude_markers = ("🏳️", "🏴", "📦", "✅", "⛔")
    filtered = [c for c in configs if not any(m in c.get("remarks", "") for m in exclude_markers)]
    log(f"📊 После фильтрации осталось {len(filtered)} платных конфигов")
    return filtered


async def load_paid_subscription() -> List[Dict[str, Any]]:
    if not PAID_SUB_URL:
        log_err("⚠️ PAID_SUB_URL не задан")
        return []
    raw = await fetch_url(PAID_SUB_URL)

    if not raw:
        log("⚠️ Не удалось загрузить подписку, восстанавливаем из subscription.json...")
        try:
            with open("subscription.json", "r", encoding="utf-8") as f:
                old = json.load(f)
            if isinstance(old, list):
                paid_only = _filter_paid_configs(old)
                log(f"🔄 Восстановлено {len(paid_only)} платных конфигов")
                return paid_only
        except Exception as e:
            log_err(f"⚠️ Ошибка чтения subscription.json: {e}")
        return []

    try:
        data = json.loads(raw)
        if isinstance(data, list):
            ready, obs = [], []
            for item in data:
                if isinstance(item, dict):
                    if "outbounds" in item and "routing" in item:
                        ready.append(item)
                    elif "protocol" in item or "settings" in item:
                        obs.append((item, item.get("remarks", "")))
                    else:
                        srv = _extract_server_from_dict(item)
                        if srv:
                            obs.append(({
                                "protocol": srv["protocol"],
                                "settings": {"servers": [{"address": srv["address"], "port": srv["port"]}]},
                                "remarks": srv["remarks"]}, srv["remarks"]))
            if ready: return _filter_paid_configs(ready)
            if obs:
                return _filter_paid_configs(
                    [create_single_outbound_config(ob, rm or ob.get("remarks", "")) for ob, rm in obs])
            log_err("⚠️ Не удалось распознать элементы списка")
        elif isinstance(data, dict):
            if "outbounds" in data and "routing" in data:
                return _filter_paid_configs([data])
            if "outbounds" in data:
                return _filter_paid_configs([
                    create_single_outbound_config(ob, ob.get("remarks", "") or data.get("remarks", "Платная подписка"))
                    for ob in data["outbounds"]])
            srv = _extract_server_from_dict(data)
            if srv:
                return _filter_paid_configs([create_single_outbound_config({
                    "protocol": srv["protocol"],
                    "settings": {"servers": [{"address": srv["address"], "port": srv["port"]}]},
                    "remarks": srv["remarks"]}, srv["remarks"])])
            log_err("⚠️ Неизвестный формат JSON")
        else:
            log_err("⚠️ Неожиданный тип JSON")
    except json.JSONDecodeError:
        try:
            decoded = base64.b64decode(raw).decode("utf-8")
        except Exception:
            decoded = raw
        items = [(pp.outbound, pp.remarks) for line in decoded.splitlines()
                 if line.strip() and (pp := parse_proxy_url(line))]
        if items:
            return _filter_paid_configs(
                [create_single_outbound_config(ob, rm or ob.get("remarks", "")) for ob, rm in items])
        log_err("⚠️ Не удалось распарсить ссылки")
    return []


# ===== MAIN =====
async def main_async():
    paid_configs = await load_paid_subscription()
    log(f"Итого платных конфигов: {len(paid_configs)}\n")

    white_links, black_links, extra_links = await asyncio.gather(
        get_links_from_urls(WHITE_URLS),
        get_links_from_urls(BLACK_URLS),
        get_links_from_urls(EXTRA_URLS),
    )
    log(f"Найдено ссылок: белые={len(white_links)}, чёрные={len(black_links)}, extra={len(extra_links)}")

    def parse_all(links):
        out = []
        for link in links:
            p = parse_proxy_url(link)
            # hysteria2 не поддерживается xray-core — выкидываем
            if p is not None and p.outbound.get("protocol") != "hysteria2":
                out.append(p)
        return out

    white_parsed = parse_all(white_links)
    black_parsed = parse_all(black_links)
    extra_parsed = parse_all(extra_links)
    white_without_ru = [p for p in white_parsed if not is_excluded_region(p.remarks)]

    # 🏳️LTE-3 (EXTRA) — первым, его живые пойдут в резерв для LTE-2
    config_lte3, alive_lte3 = await check_and_create_balancer(
        extra_parsed, "LTE-3", MAX_LTE3,
        remarks_ok_template="🏳️LTE-3 ✅ {count}",
        remarks_fail="🏳️LTE-3 ⛔ Временно не работает",
    )

    # 🏳️LTE-1: база — ТОЛЬКО igareck с РУ-SNI.
    # Если igareck не набрал MAX_LTE1 — добираем из живых LTE-3 (тоже только РУ-SNI)
    lte1_parsed = [p for p in white_parsed if is_lte_compatible(p)]
    log(f"📱 LTE-совместимых у igareck (РУ SNI): {len(lte1_parsed)}")
    config_lte1, _ = await check_and_create_balancer(
        lte1_parsed, "LTE-1", MAX_LTE1,
        remarks_ok_template="🏳️LTE-1 ✅ {count}",
        remarks_fail="🏳️LTE-1 ⛔ Временно не работает",
        reserve_candidates=alive_lte3,
        reserve_filter=lambda c: is_lte_compatible(c),
        use_ping=False,
    )

    # 🏳️LTE-2(no-ru): белые без РФ/РБ, без пинга (как старые рабочие),
    # добор из живых LTE-3 — резервные получат теги LTE-3-x
    config_lte2, _ = await check_and_create_balancer(
        white_without_ru, "LTE-2", MAX_LTE2,
        remarks_ok_template="🏳️LTE-2(no-ru) ✅ {count}",
        remarks_fail="🏳️LTE-2(no-ru) ⛔ Временно не работает",
        reserve_candidates=alive_lte3,
        reserve_filter=lambda c: not is_excluded_region(c.remarks),
        use_ping=False,
    )

    # 🏴Wi-Fi-1: чёрный список, только для вайфая, с пингом
    config_wifi1, _ = await check_and_create_balancer(
        black_parsed, "Wi-Fi-1", MAX_WIFI,
        remarks_ok_template="🏴Wi-Fi-1 ✅ {count}",
        remarks_fail="🏴Wi-Fi-1 ⛔ Временно не работает",
    )

    final_configs = [config_lte1, config_lte2, config_lte3, config_wifi1] + paid_configs

    with open("subscription.json", "w", encoding="utf-8") as f:
        json.dump(final_configs, f, indent=2, ensure_ascii=False)
    with open("subscription.txt", "w", encoding="utf-8") as f:
        json.dump(final_configs, f, indent=2, ensure_ascii=False)

    def selector_len(cfg):
        return len(cfg.get("routing", {}).get("balancers", [{}])[0].get("selector", []))

    log("\n✅ Успешно обновлено!")
    log(f"   • 🏳️LTE-1: {selector_len(config_lte1)} серверов")
    log(f"   • 🏳️LTE-2(no-ru): {selector_len(config_lte2)} серверов")
    log(f"   • 🏳️LTE-3: {selector_len(config_lte3)} серверов")
    log(f"   • 🏴Wi-Fi-1: {selector_len(config_wifi1)} серверов")
    log(f"   • Платных конфигов: {len(paid_configs)} (без сортировки)")
    log(f"   • Всего записей: {len(final_configs)}")


def main():
    try:
        asyncio.run(main_async())
    except Exception as e:
        log_err(f"❌ Критическая ошибка: {mask_secret(str(e))}")
        import traceback
        log_err(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()
