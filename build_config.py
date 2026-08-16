#!/usr/bin/env python3
"""
build_config.py — сборщик и проверщик VPN-конфигураций для sing-box.
"""
from __future__ import annotations
import asyncio, base64, json, os, re, sys, time, urllib.parse
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

# ===== Конфигурация =====
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
TCP_TIMEOUT = 5.0
MAX_FOR_SINGBOX = 150
MAX_SERVERS_PER_BALANCER = 100
VALID_FINGERPRINTS = {"chrome", "firefox", "edge", "safari", "ios", "android", "qq", "random"}
EXCLUDE_PATTERN = re.compile(r"(Россия|anycast|Беларусь|🇷🇺|🇧🇾|Russia|Belarus)", re.IGNORECASE)
_SECRET_PATTERN = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    r"|(?<=://)[^@/\s]{10,}(?=@)"
)

def mask_secret(t): return _SECRET_PATTERN.sub("<REDACTED>", t)
def log(msg): print(mask_secret(msg))
def log_err(msg): print(mask_secret(msg), file=sys.stderr)

# ===== Вспомогательные функции =====
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

async def fetch_url(url, timeout=15.0):
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sL", "--max-time", str(int(timeout)), url,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout+5)
        if proc.returncode != 0:
            log_err(f"⚠️ curl error {proc.returncode} for {url}")
            return None
        return stdout.decode(errors="ignore").strip()
    except Exception as e:
        log_err(f"⚠️ fetch error: {e}")
        return None

def create_config_template(remarks_text):
    return {
        "dns": {"servers": ["https://8.8.8.8/dns-query", "https://8.8.4.4/dns-query"], "queryStrategy": "UseIP"},
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": {"auth": "noauth", "udp": True, "userLevel": 8}, "sniffing": {"destOverride": ["http", "tls"], "enabled": True, "routeOnly": False}, "tag": "socks"},
            {"listen": "127.0.0.1", "port": 10809, "protocol": "http", "settings": {"userLevel": 8}, "tag": "http"},
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "domainMatcher": "hybrid",
            "rules": [{"type": "field", "protocol": ["bittorrent"], "outboundTag": "direct"},
                       {"type": "field", "network": "tcp,udp", "balancerTag": "WL_Balancer"}],
            "balancers": [{"tag": "WL_Balancer", "selector": [],
                           "strategy": {"type": "leastLoad", "settings": {"maxRTT": "10s", "expected": 1, "baselines": ["500ms", "1500ms", "3000ms"], "tolerance": 0.1}},
                           "fallbackTag": "direct"}]
        },
        "burstObservatory": {"pingConfig": {"timeout": "10s", "interval": "1m", "sampling": 2, "destination": "http://www.gstatic.com/generate_204"}, "subjectSelector": []},
        "outbounds": [],
        "remarks": remarks_text,
    }

def strip_balancer_for_empty(config):
    config["routing"]["rules"] = [{"type": "field", "protocol": ["bittorrent"], "outboundTag": "direct"},
                                   {"type": "field", "network": "tcp,udp", "outboundTag": "direct"}]
    config["routing"].pop("balancers", None)
    config.pop("burstObservatory", None)
    config["outbounds"] = [{"protocol": "freedom", "settings": {"domainStrategy": "UseIP"}, "tag": "direct"},
                           {"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"}]
    return config

def create_single_outbound_config(outbound, remarks):
    """Создаёт конфиг для одного outbound'а с балансировщиком из одного сервера.
       Если remarks не передан, берёт из outbound.get('remarks') или ставит стандартный."""
    if not remarks:
        remarks = outbound.get("remarks", "Платная подписка")
    config = create_config_template(remarks)
    ob_copy = json.loads(json.dumps(outbound))
    tag = "paid-1"
    ob_copy["tag"] = tag
    config["outbounds"] = [ob_copy,
                           {"protocol": "freedom", "settings": {"domainStrategy": "UseIP"}, "tag": "direct"},
                           {"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"}]
    config["routing"]["balancers"][0]["selector"] = [tag]
    config["burstObservatory"]["subjectSelector"] = [tag]
    return config

# ===== Парсеры протоколов =====
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

# --- VlessHandler ---
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
            fingerprint = clean_fingerprint(params.get("fp") or params.get("fingerprint"))
            is_reality = ("pbk" in params) or ("publicKey" in params) or (params.get("security") == "reality")
            if is_reality and not (params.get("pbk") or params.get("publicKey")): return None
            outbound = {
                "tag": None, "protocol": "vless",
                "settings": {"vnext": [{"address": address, "port": port,
                                        "users": [{"id": user_id, "encryption": "none", "flow": params.get("flow", ""), "level": 8}]}]},
                "streamSettings": {"network": params.get("type", "tcp"), "security": "reality" if is_reality else "tls", "tcpSettings": {"header": {"type": "none"}}},
            }
            if is_reality:
                outbound["streamSettings"]["realitySettings"] = {
                    "allowInsecure": False, "fingerprint": fingerprint,
                    "publicKey": params.get("pbk") or params.get("publicKey") or "",
                    "serverName": params.get("sni", address), "shortId": params.get("sid", ""), "show": False,
                }
            else:
                outbound["streamSettings"]["tlsSettings"] = {"allowInsecure": False, "serverName": params.get("sni", address), "fingerprint": fingerprint}
            return ParsedProxy(outbound, remarks, address, port)
        except Exception: return None
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
            if security == "reality":
                r = stream.get("realitySettings", {})
                for k, v in {"sni": r.get("serverName"), "fp": r.get("fingerprint"), "pbk": r.get("publicKey"), "sid": r.get("shortId")}.items():
                    if v: params[k] = v
            elif security == "tls":
                t = stream.get("tlsSettings", {})
                for k, v in {"sni": t.get("serverName"), "fp": t.get("fingerprint")}.items():
                    if v: params[k] = v
            addr_out = bracket_if_ipv6(address)
            url = f"vless://{user['id']}@{addr_out}:{port}"
            if params: url += "?" + "&".join(f"{k}={urllib.parse.quote(str(v))}" for k, v in params.items())
            if remarks: url += "#" + urllib.parse.quote(remarks)
            return url
        except Exception: return None

# --- Hysteria2Handler ---
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
            sni = params.get("sni", [address])[0]
            fingerprint = params.get("fingerprint", ["chrome"])[0]
            insecure = params.get("insecure", ["0"])[0] == "1"
            alpn = params.get("alpn", [None])[0]
            alpn_list = alpn.split(",") if alpn else []
            outbound = {
                "tag": None, "protocol": "hysteria2",
                "settings": {"servers": [{
                    "address": address, "port": port, "auth": auth, "sni": sni,
                    "fingerprint": fingerprint, "insecure": insecure, "alpn": alpn_list,
                }]},
            }
            return ParsedProxy(outbound, remarks, address, port)
        except Exception: return None
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
            addr_out = bracket_if_ipv6(address)
            url = f"hysteria2://{auth}@{addr_out}:{port}"
            if params: url += "?" + "&".join(f"{k}={urllib.parse.quote(str(v))}" for k, v in params.items())
            if remarks: url += "#" + urllib.parse.quote(remarks)
            return url
        except Exception: return None

# --- TrojanHandler ---
class TrojanHandler(ProtocolHandler):
    scheme = "trojan://"
    def parse(self, raw_url):
        url_str, remarks = self.split_remarks(raw_url)
        if not url_str.startswith(self.scheme): return None
        try:
            parsed = urllib.parse.urlparse(url_str)
            password, address_raw, port = parsed.username, parsed.hostname, parsed.port or 443
            if not password or not address_raw: return None
            address = normalize_address(address_raw)
            params = urllib.parse.parse_qs(parsed.query)
            outbound = {
                "tag": None, "protocol": "trojan",
                "settings": {"servers": [{
                    "address": address, "port": port, "password": password,
                    "sni": params.get("sni", [address])[0],
                    "fingerprint": params.get("fingerprint", ["chrome"])[0],
                    "allowInsecure": params.get("allowInsecure", ["0"])[0] == "1",
                }]},
            }
            return ParsedProxy(outbound, remarks, address, port)
        except Exception: return None
    def generate(self, outbound, remarks):
        try:
            s = outbound["settings"]["servers"][0]
            address, port, password = s.get("address"), s.get("port"), s.get("password")
            if not (address and port and password): return None
            params = {}
            if s.get("sni"): params["sni"] = s["sni"]
            if s.get("fingerprint"): params["fingerprint"] = s["fingerprint"]
            if s.get("allowInsecure"): params["allowInsecure"] = "1"
            addr_out = bracket_if_ipv6(address)
            url = f"trojan://{password}@{addr_out}:{port}"
            if params: url += "?" + "&".join(f"{k}={urllib.parse.quote(str(v))}" for k, v in params.items())
            if remarks: url += "#" + urllib.parse.quote(remarks)
            return url
        except Exception: return None

# --- ShadowsocksHandler ---
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
                "settings": {"servers": [{"address": address, "port": port, "method": method, "password": password}]},
            }
            return ParsedProxy(outbound, remarks, address, port)
        except Exception: return None
    def generate(self, outbound, remarks):
        try:
            s = outbound["settings"]["servers"][0]
            address, port = s.get("address"), s.get("port")
            method, password = s.get("method"), s.get("password")
            if not all([address, port, method, password]): return None
            b64 = base64.urlsafe_b64encode(f"{method}:{password}".encode()).decode().rstrip("=")
            addr_out = bracket_if_ipv6(address)
            url = f"ss://{b64}@{addr_out}:{port}"
            if remarks: url += "#" + urllib.parse.quote(remarks)
            return url
        except Exception: return None

# --- VmessHandler ---
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
            network, tls = cfg.get("net", "tcp"), cfg.get("tls", "")
            outbound = {
                "tag": None, "protocol": "vmess",
                "settings": {"vnext": [{"address": address, "port": port,
                                        "users": [{"id": uuid, "alterId": int(cfg.get("aid", 0)),
                                                   "security": cfg.get("scy", "auto"), "level": 8}]}]},
                "streamSettings": {"network": network, "security": "tls" if tls == "tls" else "none"},
            }
            host, path = cfg.get("host", ""), cfg.get("path", "")
            if network == "ws":
                ws = {"path": path}
                if host: ws["headers"] = {"Host": host}
                outbound["streamSettings"]["wsSettings"] = ws
            elif network == "grpc":
                outbound["streamSettings"]["grpcSettings"] = {"serviceName": path.lstrip("/")}
            if tls == "tls":
                outbound["streamSettings"]["tlsSettings"] = {
                    "serverName": cfg.get("sni") or address,
                    "fingerprint": clean_fingerprint(cfg.get("fp")),
                    "allowInsecure": False,
                }
            return ParsedProxy(outbound, remarks, address, port)
        except Exception: return None
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
        except Exception: return None

# Реестр обработчиков (все протоколы)
PROTOCOL_REGISTRY = [
    VlessHandler(),
    Hysteria2Handler(),
    TrojanHandler(),
    ShadowsocksHandler(),
    VmessHandler(),
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

# ===== Проверка TCP =====
async def tcp_ping(host, port, timeout=TCP_TIMEOUT):
    start = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        try: await writer.wait_closed()
        except: pass
        return time.monotonic() - start
    except Exception: return None

@dataclass
class Candidate:
    outbound: Dict[str, Any]
    remarks: str
    address: str
    port: int
    rtt: float = field(default=0.0)

async def check_and_create_balancer(parsed_candidates, source_name, max_servers=MAX_SERVERS_PER_BALANCER,
                                    remarks_ok_template="✅ {name} (рабочих: {count})",
                                    remarks_fail="⛔ Временно не работает",
                                    reserve_candidates=None, reserve_filter=None):
    log(f"\n🔍 Checking source: {source_name} (total {len(parsed_candidates)})")
    fail_config = strip_balancer_for_empty(create_config_template(remarks_fail))
    if not parsed_candidates:
        return fail_config, []
    ping_tasks = [tcp_ping(p.address, p.port) for p in parsed_candidates]
    ping_results = await asyncio.gather(*ping_tasks)
    alive = [Candidate(p.outbound, p.remarks, p.address, p.port, rtt)
             for p, rtt in zip(parsed_candidates, ping_results) if rtt is not None]
    log(f"   ✅ After TCP ping: {len(alive)} alive")
    if not alive:
        return fail_config, []
    alive.sort(key=lambda c: c.rtt)
    shortlist = alive[:MAX_FOR_SINGBOX]
    best = shortlist[:max_servers]
    used_addrs = {(c.address, c.port) for c in best}
    if len(best) < max_servers and reserve_candidates:
        needed = max_servers - len(best)
        sorted_reserve = sorted(reserve_candidates, key=lambda c: c.rtt)
        for c in sorted_reserve:
            if len(best) >= max_servers: break
            if (c.address, c.port) in used_addrs: continue
            if reserve_filter is not None and not reserve_filter(c): continue
            best.append(c); used_addrs.add((c.address, c.port))
        log(f"   ➕ Added from reserve: {len(best) - len(shortlist[:max_servers])}")
    log(f"   🏆 Final count: {len(best)}")
    outbounds, tags = [], []
    for idx, cand in enumerate(best, start=1):
        tag = f"{source_name}-{idx}"
        ob_copy = json.loads(json.dumps(cand.outbound))
        ob_copy["tag"] = tag
        outbounds.append(ob_copy)
        tags.append(tag)
    config = create_config_template(remarks_ok_template.format(name=source_name, count=len(best)))
    config["outbounds"] = outbounds + [
        {"protocol": "freedom", "settings": {"domainStrategy": "UseIP"}, "tag": "direct"},
        {"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"},
    ]
    config["routing"]["balancers"][0]["selector"] = tags
    config["burstObservatory"]["subjectSelector"] = tags
    return config, alive

# ===== Загрузка платной подписки =====
def _extract_server_from_dict(item):
    address = item.get("server") or item.get("address") or item.get("host")
    port = item.get("port") or item.get("port_number")
    if address and port:
        return {
            "address": normalize_address(address),
            "port": int(port),
            "protocol": item.get("type") or item.get("protocol") or "unknown",
            "remarks": item.get("remarks") or item.get("name") or ""
        }
    return None

def _filter_and_sort_paid_configs(configs):
    exclude_markers = ("🏳️", "🏴", "📦", "✅", "⛔")
    filtered = []
    for c in configs:
        remarks = c.get("remarks", "")
        if not any(marker in remarks for marker in exclude_markers):
            filtered.append(c)
    filtered.sort(key=lambda c: c.get("remarks", "").lower())
    log(f"📊 После фильтрации и сортировки осталось {len(filtered)} платных конфигов")
    return filtered

async def load_paid_subscription() -> List[Dict[str, Any]]:
    if not PAID_SUB_URL:
        log_err("⚠️ PAID_SUB_URL не задан")
        return []
    raw = await fetch_url(PAID_SUB_URL) if PAID_SUB_URL else None
    if not raw:
        log("⚠️ Не удалось загрузить подписку, восстанавливаем из subscription.json...")
        try:
            with open("subscription.json", "r", encoding="utf-8") as f:
                old = json.load(f)
            if isinstance(old, list):
                log(f"🔄 Восстановлено {len(old)} конфигов")
                return _filter_and_sort_paid_configs(old)
        except Exception as e:
            log_err(f"⚠️ Ошибка чтения subscription.json: {e}")
        return []

    try:
        data = json.loads(raw)
        if isinstance(data, list):
            ready_configs = []
            outbound_list = []
            for item in data:
                if isinstance(item, dict):
                    if "outbounds" in item and "routing" in item:
                        ready_configs.append(item)
                    elif "protocol" in item or "settings" in item:
                        outbound_list.append(item)
                    else:
                        srv = _extract_server_from_dict(item)
                        if srv:
                            fake_ob = {
                                "protocol": srv.get("protocol", "unknown"),
                                "settings": {"servers": [{"address": srv["address"], "port": srv["port"]}]},
                                "remarks": srv.get("remarks", "")
                            }
                            outbound_list.append(fake_ob)
            if ready_configs:
                return _filter_and_sort_paid_configs(ready_configs)
            elif outbound_list:
                configs = []
                for ob in outbound_list:
                    remarks = ob.get("remarks", "") or "Платная подписка"
                    configs.append(create_single_outbound_config(ob, remarks))
                return _filter_and_sort_paid_configs(configs)
            else:
                log_err("⚠️ Не удалось распознать элементы списка")
        elif isinstance(data, dict):
            if "outbounds" in data and "routing" in data:
                return _filter_and_sort_paid_configs([data])
            elif "outbounds" in data:
                configs = []
                for ob in data["outbounds"]:
                    remarks = ob.get("remarks", "") or data.get("remarks", "Платная подписка")
                    configs.append(create_single_outbound_config(ob, remarks))
                return _filter_and_sort_paid_configs(configs)
            else:
                srv = _extract_server_from_dict(data)
                if srv:
                    fake_ob = {
                        "protocol": srv.get("protocol", "unknown"),
                        "settings": {"servers": [{"address": srv["address"], "port": srv["port"]}]},
                        "remarks": srv.get("remarks", "")
                    }
                    return _filter_and_sort_paid_configs([create_single_outbound_config(fake_ob, srv.get("remarks", "Платная подписка"))])
                else:
                    log_err("⚠️ Неизвестный формат JSON")
        else:
            log_err("⚠️ Неожиданный тип JSON")
    except json.JSONDecodeError:
        # Пробуем Base64
        try:
            decoded = base64.b64decode(raw).decode("utf-8")
            outbounds = []
            for line in decoded.splitlines():
                line = line.strip()
                if line:
                    pp = parse_proxy_url(line)
                    if pp:
                        outbounds.append(pp.outbound)
            if outbounds:
                configs = []
                for ob in outbounds:
                    remarks = ob.get("remarks", "") or "Платная подписка"
                    configs.append(create_single_outbound_config(ob, remarks))
                return _filter_and_sort_paid_configs(configs)
            else:
                log_err("⚠️ Base64 не содержит валидных ссылок")
        except Exception as e:
            log_err(f"⚠️ Ошибка декодирования Base64: {e}")
    return []

# ===== main =====
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
            if p is not None and p.outbound.get("protocol") != "hysteria2":
                out.append(p)
        return out

    white_parsed = parse_all(white_links)
    black_parsed = parse_all(black_links)
    extra_parsed = parse_all(extra_links)
    white_without_ru = [p for p in white_parsed if not is_excluded_region(p.remarks)]

    config_extra, alive_extra = await check_and_create_balancer(
        extra_parsed, "EXTRA", MAX_SERVERS_PER_BALANCER,
        remarks_ok_template="📦 EXTRA ✅ {count}",
        remarks_fail="📦 EXTRA ⛔ Временно не работает",
    )
    config_white_noru, _ = await check_and_create_balancer(
        white_without_ru, "WL-noRU", MAX_SERVERS_PER_BALANCER,
        remarks_ok_template="🏳️ WL-noRU ✅ {count}",
        remarks_fail="🏳️ WL-noRU ⛔ Временно не работает",
        reserve_candidates=alive_extra,
        reserve_filter=lambda c: not is_excluded_region(c.remarks)
    )
    config_black, _ = await check_and_create_balancer(
        black_parsed, "BL", MAX_SERVERS_PER_BALANCER,
        remarks_ok_template="🏴 BL ✅ {count}",
        remarks_fail="🏴 BL ⛔ Временно не работает",
    )

    final_configs = [config_white_noru, config_black, config_extra] + paid_configs

    with open("subscription.json", "w", encoding="utf-8") as f:
        json.dump(final_configs, f, indent=2, ensure_ascii=False)

    def selector_len(cfg): return len(cfg.get("routing", {}).get("balancers", [{}])[0].get("selector", []))
    log("\n✅ Успешно обновлено!")
    log(f"   • WL-noRU: {selector_len(config_white_noru)} серверов")
    log(f"   • BL: {selector_len(config_black)} серверов")
    log(f"   • EXTRA: {selector_len(config_extra)} серверов")
    log(f"   • Платных конфигов: {len(paid_configs)}")
    log(f"   • Всего записей в subscription.json: {len(final_configs)}")

def main():
    try:
        asyncio.run(main_async())
    except Exception as e:
        log_err(f"❌ Критическая ошибка: {mask_secret(str(e))}")
        sys.exit(1)

if __name__ == "__main__":
    main()
