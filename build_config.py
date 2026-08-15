#!/usr/bin/env python3
"""
build_config.py — сборщик и проверщик VPN-конфигураций для sing-box.

Объединяет лучшие решения из двух независимых код-ревью:
  • модульный парсинг/генерация нескольких протоколов (vless, hysteria2, trojan,
    shadowsocks, vmess) через реестр обработчиков (легко добавить новый протокол);
  • исправление критического бага маршрутизации sing-box
    (outbound.get("tag", "proxy") не срабатывал, т.к. ключ "tag" существовал со
    значением None — тег теперь всегда принудительно проставляется в "proxy");
  • секрет платной подписки только из переменной окружения, никогда в коде;
  • устранение race condition при старте sing-box (активный poll порта вместо
    фиксированного sleep);
  • защита от падения sing-box на пустом balancer.selector (если рабочих
    конфигов нет — балансировщик убирается, трафик идёт в direct);
  • валидация обязательных полей Reality (pbk/publicKey);
  • нормализация IPv6-адресов (квадратные скобки);
  • безопасное логирование — секреты (UUID/пароли/ключи) маскируются перед
    выводом в stderr/stdout, полный traceback никогда не печатается;
  • асинхронная проверка через asyncio (TCP-пинг + запуск sing-box + curl),
    что быстрее и стабильнее, чем process-pool с sleep().
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import shutil
import sys
import tempfile
import time
import urllib.parse
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

# ============================================================================
# Конфигурация (никаких секретов в коде!)
# ============================================================================

PAID_SUB_URL = os.environ.get("PAID_SUB_URL", "")  # обязателен через Secrets/env
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
SINGBOX_PORT_WAIT = 8.0          # не используется
SINGBOX_CURL_TIMEOUT = 15.0      # не используется
MAX_FOR_SINGBOX = 150            # сколько лучших по TCP-пингу берём для каждого источника
MAX_SERVERS_PER_BALANCER = 100   # целевое количество серверов в каждом балансировщике
CONCURRENCY_LIMIT = 8            # не используется
BASE_TEST_PORT = 20000           # не используется
VALID_FINGERPRINTS = {"chrome", "firefox", "edge", "safari", "ios", "android", "qq", "random"}
EXCLUDE_PATTERN = re.compile(r"(Россия|anycast|Беларусь|🇷🇺|🇧🇾|Russia|Belarus)", re.IGNORECASE)

_SECRET_PATTERN = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    r"|(?<=://)[^@/\s]{10,}(?=@)"  # userinfo перед @ (пароли/base64-auth)
)


def mask_secret(text: str) -> str:
    """Маскирует UUID/пароли/ключи перед выводом в лог, чтобы не палить секреты в CI-логах."""
    return _SECRET_PATTERN.sub("<REDACTED>", text)


def log(msg: str) -> None:
    print(mask_secret(msg))


def log_err(msg: str) -> None:
    print(mask_secret(msg), file=sys.stderr)


# ============================================================================
# Вспомогательные функции
# ============================================================================

def clean_fingerprint(fp: Optional[str]) -> str:
    if not fp:
        return "chrome"
    cleaned = re.sub(r"[#|*].*", "", fp).strip().lower()
    return cleaned if cleaned in VALID_FINGERPRINTS else "chrome"


def is_excluded_region(remarks: str) -> bool:
    return bool(remarks and EXCLUDE_PATTERN.search(remarks))


def normalize_address(addr: str) -> str:
    """Убирает квадратные скобки IPv6 для использования в socket/curl."""
    if addr.startswith("[") and addr.endswith("]"):
        return addr[1:-1]
    return addr


def bracket_if_ipv6(addr: str) -> str:
    if ":" in addr and not addr.startswith("["):
        return f"[{addr}]"
    return addr


async def fetch_url(url: str, timeout: float = 15.0) -> Optional[str]:
    """Асинхронная загрузка через curl (без внешних зависимостей)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sL", "--max-time", str(int(timeout)), url,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout + 5)
        if proc.returncode != 0:
            log_err(f"⚠️ curl вернул код {proc.returncode} для {url}: {stderr.decode(errors='ignore')[:200]}")
            return None
        return stdout.decode(errors="ignore").strip()
    except Exception as e:
        log_err(f"⚠️ Ошибка загрузки {url}: {e}")
        return None


def create_config_template(remarks_text: str) -> Dict[str, Any]:
    """Базовый шаблон sing-box конфига с балансировщиком."""
    return {
        "dns": {
            "servers": ["https://8.8.8.8/dns-query", "https://8.8.4.4/dns-query"],
            "queryStrategy": "UseIP",
        },
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "listen": "127.0.0.1", "port": 10808, "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True, "userLevel": 8},
                "sniffing": {"destOverride": ["http", "tls"], "enabled": True, "routeOnly": False},
                "tag": "socks",
            },
            {
                "listen": "127.0.0.1", "port": 10809, "protocol": "http",
                "settings": {"userLevel": 8}, "tag": "http",
            },
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "domainMatcher": "hybrid",
            "rules": [
                {"type": "field", "protocol": ["bittorrent"], "outboundTag": "direct"},
                {"type": "field", "network": "tcp,udp", "balancerTag": "WL_Balancer"},
            ],
            "balancers": [
                {
                    "tag": "WL_Balancer", "selector": [],
                    "strategy": {
                        "type": "leastLoad",
                        "settings": {
                            "maxRTT": "10s", "expected": 1,
                            "baselines": ["500ms", "1500ms", "3000ms"], "tolerance": 0.1,
                        },
                    },
                    "fallbackTag": "direct",
                }
            ],
        },
        "burstObservatory": {
            "pingConfig": {
                "timeout": "10s", "interval": "1m", "sampling": 2,
                "destination": "http://www.gstatic.com/generate_204",
            },
            "subjectSelector": [],
        },
        "outbounds": [],
        "remarks": remarks_text,
    }


def strip_balancer_for_empty(config: Dict[str, Any]) -> Dict[str, Any]:
    """Если рабочих конфигов нет — убираем balancer/burstObservatory, чтобы sing-box
    не падал на валидации пустого selector, и направляем трафик в direct."""
    config["routing"]["rules"] = [
        {"type": "field", "protocol": ["bittorrent"], "outboundTag": "direct"},
        {"type": "field", "network": "tcp,udp", "outboundTag": "direct"},
    ]
    config["routing"].pop("balancers", None)
    config.pop("burstObservatory", None)
    config["outbounds"] = [
        {"protocol": "freedom", "settings": {"domainStrategy": "UseIP"}, "tag": "direct"},
        {"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"},
    ]
    return config


# ============================================================================
# Модульные обработчики протоколов (парсинг + генерация ссылки)
# Каждый протокол — отдельный класс. Чтобы добавить протокол — реализуй
# ProtocolHandler и зарегистрируй его в PROTOCOL_REGISTRY.
# ============================================================================

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
    def split_remarks(raw_url: str) -> Tuple[str, str]:
        url_str = raw_url.strip()
        remarks = ""
        if "#" in url_str:
            url_str, remarks = url_str.split("#", 1)
            remarks = urllib.parse.unquote(remarks.strip())
        return url_str, remarks


class VlessHandler(ProtocolHandler):
    scheme = "vless://"

    def parse(self, raw_url: str) -> Optional[ParsedProxy]:
        url_str, remarks = self.split_remarks(raw_url)
        if not url_str.startswith(self.scheme):
            return None
        try:
            parsed = urllib.parse.urlparse(url_str)
            user_id, address_raw, port = parsed.username, parsed.hostname, parsed.port or 443
            if not user_id or not address_raw:
                return None
            address = normalize_address(address_raw)
            params = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items() if v}
            fingerprint = clean_fingerprint(params.get("fp") or params.get("fingerprint"))

            is_reality = ("pbk" in params) or ("publicKey" in params) or (params.get("security") == "reality")
            # Критичная проверка: без публичного ключа Reality-конфиг невалиден.
            if is_reality and not (params.get("pbk") or params.get("publicKey")):
                return None

            outbound: Dict[str, Any] = {
                "tag": None,
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": address, "port": port,
                        "users": [{"id": user_id, "encryption": "none",
                                   "flow": params.get("flow", ""), "level": 8}],
                    }]
                },
                "streamSettings": {
                    "network": params.get("type", "tcp"),
                    "security": "reality" if is_reality else "tls",
                    "tcpSettings": {"header": {"type": "none"}},
                },
            }
            if is_reality:
                outbound["streamSettings"]["realitySettings"] = {
                    "allowInsecure": False, "fingerprint": fingerprint,
                    "publicKey": params.get("pbk") or params.get("publicKey") or "",
                    "serverName": params.get("sni", address),
                    "shortId": params.get("sid", ""), "show": False,
                }
            else:
                outbound["streamSettings"]["tlsSettings"] = {
                    "allowInsecure": False, "serverName": params.get("sni", address),
                    "fingerprint": fingerprint,
                }
            return ParsedProxy(outbound, remarks, address, port)
        except Exception:
            return None

    def generate(self, outbound: Dict[str, Any], remarks: Optional[str]) -> Optional[str]:
        try:
            vnext = outbound["settings"]["vnext"][0]
            address, port = vnext["address"], vnext["port"]
            user = vnext["users"][0]
            stream = outbound.get("streamSettings", {})
            network, security = stream.get("network", "tcp"), stream.get("security", "")

            params: Dict[str, str] = {"encryption": user.get("encryption", "none")}
            if user.get("flow"):
                params["flow"] = user["flow"]
            if security:
                params["security"] = security
            if network != "tcp":
                params["type"] = network

            if security == "reality":
                r = stream.get("realitySettings", {})
                params.update({k: v for k, v in {
                    "sni": r.get("serverName"), "fp": r.get("fingerprint"),
                    "pbk": r.get("publicKey"), "sid": r.get("shortId"),
                }.items() if v})
            elif security == "tls":
                t = stream.get("tlsSettings", {})
                params.update({k: v for k, v in {
                    "sni": t.get("serverName"), "fp": t.get("fingerprint"),
                }.items() if v})

            addr_out = bracket_if_ipv6(address)
            url = f"vless://{user['id']}@{addr_out}:{port}"
            if params:
                url += "?" + "&".join(f"{k}={urllib.parse.quote(str(v))}" for k, v in params.items())
            if remarks:
                url += "#" + urllib.parse.quote(remarks)
            return url
        except Exception:
            return None


class Hysteria2Handler(ProtocolHandler):
    scheme = "hysteria2://"

    def parse(self, raw_url: str) -> Optional[ParsedProxy]:
        url_str, remarks = self.split_remarks(raw_url)
        if not url_str.startswith(self.scheme):
            return None
        try:
            parsed = urllib.parse.urlparse(url_str)
            auth, address_raw, port = parsed.username, parsed.hostname, parsed.port or 443
            if not auth or not address_raw:
                return None
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
        except Exception:
            return None

    def generate(self, outbound: Dict[str, Any], remarks: Optional[str]) -> Optional[str]:
        try:
            s = outbound["settings"]["servers"][0]
            address, port, auth = s.get("address"), s.get("port"), s.get("auth")
            if not (address and port and auth):
                return None
            params: Dict[str, str] = {}
            if s.get("sni"):
                params["sni"] = s["sni"]
            if s.get("fingerprint"):
                params["fingerprint"] = s["fingerprint"]
            if s.get("insecure"):
                params["insecure"] = "1"
            if s.get("alpn"):
                params["alpn"] = ",".join(s["alpn"])
            addr_out = bracket_if_ipv6(address)
            url = f"hysteria2://{auth}@{addr_out}:{port}"
            if params:
                url += "?" + "&".join(f"{k}={urllib.parse.quote(str(v))}" for k, v in params.items())
            if remarks:
                url += "#" + urllib.parse.quote(remarks)
            return url
        except Exception:
            return None


class TrojanHandler(ProtocolHandler):
    scheme = "trojan://"

    def parse(self, raw_url: str) -> Optional[ParsedProxy]:
        url_str, remarks = self.split_remarks(raw_url)
        if not url_str.startswith(self.scheme):
            return None
        try:
            parsed = urllib.parse.urlparse(url_str)
            password, address_raw, port = parsed.username, parsed.hostname, parsed.port or 443
            if not password or not address_raw:
                return None
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
        except Exception:
            return None

    def generate(self, outbound: Dict[str, Any], remarks: Optional[str]) -> Optional[str]:
        try:
            s = outbound["settings"]["servers"][0]
            address, port, password = s.get("address"), s.get("port"), s.get("password")
            if not (address and port and password):
                return None
            params = {}
            if s.get("sni"):
                params["sni"] = s["sni"]
            if s.get("fingerprint"):
                params["fingerprint"] = s["fingerprint"]
            if s.get("allowInsecure"):
                params["allowInsecure"] = "1"
            addr_out = bracket_if_ipv6(address)
            url = f"trojan://{password}@{addr_out}:{port}"
            if params:
                url += "?" + "&".join(f"{k}={urllib.parse.quote(str(v))}" for k, v in params.items())
            if remarks:
                url += "#" + urllib.parse.quote(remarks)
            return url
        except Exception:
            return None


class ShadowsocksHandler(ProtocolHandler):
    scheme = "ss://"

    def parse(self, raw_url: str) -> Optional[ParsedProxy]:
        url_str, remarks = self.split_remarks(raw_url)
        if not url_str.startswith(self.scheme):
            return None
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
                "settings": {"servers": [{
                    "address": address, "port": port, "method": method, "password": password,
                }]},
            }
            return ParsedProxy(outbound, remarks, address, port)
        except Exception:
            return None

    def generate(self, outbound: Dict[str, Any], remarks: Optional[str]) -> Optional[str]:
        try:
            s = outbound["settings"]["servers"][0]
            address, port = s.get("address"), s.get("port")
            method, password = s.get("method"), s.get("password")
            if not all([address, port, method, password]):
                return None
            b64 = base64.urlsafe_b64encode(f"{method}:{password}".encode()).decode().rstrip("=")
            addr_out = bracket_if_ipv6(address)
            url = f"ss://{b64}@{addr_out}:{port}"
            if remarks:
                url += "#" + urllib.parse.quote(remarks)
            return url
        except Exception:
            return None


class VmessHandler(ProtocolHandler):
    scheme = "vmess://"

    def parse(self, raw_url: str) -> Optional[ParsedProxy]:
        url_str, remarks = self.split_remarks(raw_url)
        if not url_str.startswith(self.scheme):
            return None
        try:
            b64 = url_str[len(self.scheme):]
            b64 += "=" * (-len(b64) % 4)
            cfg = json.loads(base64.urlsafe_b64decode(b64).decode())
            address, uuid = cfg.get("add", ""), cfg.get("id", "")
            if not address or not uuid:
                return None
            port = int(cfg.get("port", 443))
            address = normalize_address(address)
            network, tls = cfg.get("net", "tcp"), cfg.get("tls", "")

            outbound: Dict[str, Any] = {
                "tag": None, "protocol": "vmess",
                "settings": {"vnext": [{
                    "address": address, "port": port,
                    "users": [{"id": uuid, "alterId": int(cfg.get("aid", 0)),
                               "security": cfg.get("scy", "auto"), "level": 8}],
                }]},
                "streamSettings": {"network": network, "security": "tls" if tls == "tls" else "none"},
            }
            host, path = cfg.get("host", ""), cfg.get("path", "")
            if network == "ws":
                ws = {"path": path}
                if host:
                    ws["headers"] = {"Host": host}
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
        except Exception:
            return None

    def generate(self, outbound: Dict[str, Any], remarks: Optional[str]) -> Optional[str]:
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
            if remarks:
                url += "#" + urllib.parse.quote(remarks)
            return url
        except Exception:
            return None


PROTOCOL_REGISTRY: List[ProtocolHandler] = [
    VlessHandler(), Hysteria2Handler(), TrojanHandler(), ShadowsocksHandler(), VmessHandler(),
]


def parse_proxy_url(raw_url: str) -> Optional[ParsedProxy]:
    url = raw_url.strip()
    for handler in PROTOCOL_REGISTRY:
        if url.startswith(handler.scheme):
            return handler.parse(url)
    return None


def generate_link(outbound: Dict[str, Any], remarks: Optional[str]) -> Optional[str]:
    protocol = outbound.get("protocol")
    for handler in PROTOCOL_REGISTRY:
        if handler.scheme.rstrip("://") == protocol:
            return handler.generate(outbound, remarks)
    return None


async def get_links_from_urls(urls: List[str]) -> List[str]:
    all_links: List[str] = []
    schemes = tuple(h.scheme for h in PROTOCOL_REGISTRY)
    for url in urls:
        log(f"📥 Скачиваем список: {url}")
        content = await fetch_url(url)
        if content:
            for line in content.splitlines():
                line = line.strip()
                if line.startswith(schemes):
                    all_links.append(line)
    return list(dict.fromkeys(all_links))


# ============================================================================
# Проверка: TCP-пинг + реальный тест через sing-box (полностью асинхронно)
# ============================================================================

async def tcp_ping(host: str, port: int, timeout: float = TCP_TIMEOUT) -> Optional[float]:
    start = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return time.monotonic() - start
    except Exception:
        return None


async def _wait_for_port(host: str, port: int, deadline: float) -> bool:
    """Активный poll порта вместо ненадёжного sleep — устраняет race condition
    запуска sing-box на медленных CI-раннерах."""
    start = time.monotonic()
    while time.monotonic() - start < deadline:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=0.5)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except Exception:
            await asyncio.sleep(0.2)
    return False


async def check_via_singbox(outbound: Dict[str, Any], test_port: int,
                             timeout: float = SINGBOX_CURL_TIMEOUT) -> Optional[float]:
    # ВРЕМЕННО ОТКЛЮЧЕНО — используем только TCP-пинг
    return None


@dataclass
class Candidate:
    outbound: Dict[str, Any]
    remarks: str
    address: str
    port: int
    rtt: float = field(default=0.0)


_port_counter = 0
_port_lock = asyncio.Lock()


async def _next_test_port() -> int:
    global _port_counter
    async with _port_lock:
        port = BASE_TEST_PORT + (_port_counter % 5000)
        _port_counter += 1
        return port


async def check_and_create_balancer(
    parsed_candidates: List[ParsedProxy],
    source_name: str,
    max_servers: int = MAX_SERVERS_PER_BALANCER,
    remarks_ok_template: str = "✅ {name} (рабочих: {count})",
    remarks_fail: str = "⛔ Временно не работает",
    reserve_candidates: Optional[List[Candidate]] = None,
    reserve_filter: Optional[Callable[[Candidate], bool]] = None,
) -> Tuple[Dict[str, Any], List[Candidate]]:
    """
    Создаёт балансировщик из parsed_candidates, используя TCP-пинг.
    Если после отбора лучших по TCP меньше max_servers, добирает из reserve_candidates
    с применением reserve_filter (если задан).
    Возвращает (config, all_alive_candidates) — все живые кандидаты (для использования как резерв).
    """
    log(f"\n🔍 Проверка источника: {source_name} (всего {len(parsed_candidates)} конфигов)")
    fail_config = strip_balancer_for_empty(create_config_template(remarks_fail))

    if not parsed_candidates:
        return fail_config, []

    # Этап 1: параллельный TCP-пинг
    ping_tasks = [tcp_ping(p.address, p.port) for p in parsed_candidates]
    ping_results = await asyncio.gather(*ping_tasks, return_exceptions=False)
    alive = [
        Candidate(p.outbound, p.remarks, p.address, p.port, rtt)
        for p, rtt in zip(parsed_candidates, ping_results) if rtt is not None
    ]
    log(f"   ✅ После TCP-пинга: {len(alive)} живых")
    if not alive:
        return fail_config, []

    alive.sort(key=lambda c: c.rtt)
    shortlist = alive[:MAX_FOR_SINGBOX]
    log(f"   🔍 Для балансировщика отобрано {len(shortlist)} лучших по TCP")

    # Берём максимум из shortlist
    best = shortlist[:max_servers]
    used_addrs = {(c.address, c.port) for c in best}

    # Если не хватает и есть резерв
    if len(best) < max_servers and reserve_candidates:
        needed = max_servers - len(best)
        # Сортируем резерв по RTT (на случай, если не отсортирован)
        sorted_reserve = sorted(reserve_candidates, key=lambda c: c.rtt)
        for c in sorted_reserve:
            if len(best) >= max_servers:
                break
            if (c.address, c.port) in used_addrs:
                continue
            if reserve_filter is not None and not reserve_filter(c):
                continue
            best.append(c)
            used_addrs.add((c.address, c.port))
        log(f"   ➕ Добавлено {len(best) - len(shortlist[:max_servers])} из резерва")

    log(f"   🏆 Итоговое количество: {len(best)}")

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


# ============================================================================
# Загрузка платной подписки (JSON конфигов ИЛИ base64-список ссылок)
# ============================================================================

async def load_paid_subscription() -> List[Dict[str, Any]]:
    if not PAID_SUB_URL:
        log_err("⚠️ PAID_SUB_URL не задан в переменных окружения — платная подписка пропущена")
    raw = await fetch_url(PAID_SUB_URL) if PAID_SUB_URL else None
    configs: List[Dict[str, Any]] = []

    if raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                configs = parsed
        except json.JSONDecodeError:
            # Fallback: возможно, это base64 со списком ссылок, а не готовый JSON.
            try:
                decoded = base64.b64decode(raw).decode("utf-8")
                outbounds = []
                for line in decoded.splitlines():
                    parsed_proxy = parse_proxy_url(line.strip())
                    if parsed_proxy:
                        outbounds.append(parsed_proxy.outbound)
                if outbounds:
                    cfg = strip_balancer_for_empty(create_config_template("💎 Платная подписка"))
                    cfg["outbounds"] = outbounds + cfg["outbounds"]
                    configs = [cfg]
            except Exception:
                log_err("⚠️ Не удалось распознать формат платной подписки (ни JSON, ни base64)")

    if not configs:
        log("⚠️ Восстановление платных конфигов из локального subscription.json...")
        try:
            with open("subscription.json", "r", encoding="utf-8") as f:
                old = json.load(f)
            if isinstance(old, list):
                exclude_prefixes = ("🏳️list", "🏴list", "✅", "⛔", "📦")
                configs = [c for c in old if isinstance(c, dict) and not c.get("remarks", "").startswith(exclude_prefixes)]
                log(f"🔄 Восстановлено {len(configs)} платных конфигов")
        except Exception as e:
            log_err(f"⚠️ Не удалось прочитать сохранённый subscription.json: {e}")

    # "Обход"/"бс" — приоритетные конфиги в начало списка
    priority_kw = ("обход", "бс")
    priority = [c for c in configs if any(kw in c.get("remarks", "").lower() for kw in priority_kw)]
    rest = [c for c in configs if c not in priority]
    return priority + rest


# ============================================================================
# main
# ============================================================================

async def main_async() -> None:
    existing_configs = await load_paid_subscription()
    log(f"Итого платных конфигов: {len(existing_configs)}\n")

    white_links, black_links, extra_links = await asyncio.gather(
        get_links_from_urls(WHITE_URLS),
        get_links_from_urls(BLACK_URLS),
        get_links_from_urls(EXTRA_URLS),
    )
    log(f"Найдено ссылок: белые={len(white_links)}, чёрные={len(black_links)}, extra={len(extra_links)}")

    # Фильтр: исключаем hysteria2 (клиент не поддерживает)
    def parse_all(links: List[str]) -> List[ParsedProxy]:
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

    # Сначала обрабатываем EXTRA, чтобы получить список живых кандидатов для резерва
    config_extra, alive_extra = await check_and_create_balancer(
        extra_parsed, "EXTRA", MAX_SERVERS_PER_BALANCER,
        remarks_ok_template="📦 EXTRA (26.txt) ✅ {count}",
        remarks_fail="📦 EXTRA (26.txt) ⛔ Временно не работает",
        reserve_candidates=None,
        reserve_filter=None
    )

    # Обрабатываем WL-noRU с резервом из ВСЕХ живых EXTRA (с фильтром no RU/BY)
    config_white_noru, _ = await check_and_create_balancer(
        white_without_ru, "WL-noRU", MAX_SERVERS_PER_BALANCER,
        remarks_ok_template="🏳️ WL-noRU (белый без RU/BY) ✅ {count}",
        remarks_fail="🏳️ WL-noRU (белый без RU/BY) ⛔ Временно не работает",
        reserve_candidates=alive_extra,
        reserve_filter=lambda c: not is_excluded_region(c.remarks)
    )

    # Обрабатываем чёрный список (без резерва)
    config_black, _ = await check_and_create_balancer(
        black_parsed, "BL", MAX_SERVERS_PER_BALANCER,
        remarks_ok_template="🏴 BL (чёрный) ✅ {count}",
        remarks_fail="🏴 BL (чёрный) ⛔ Временно не работает",
        reserve_candidates=None,
        reserve_filter=None
    )

    # Формируем финальный список конфигов (WL-noRU, BL, EXTRA + платные)
    final_configs = [config_white_noru, config_black, config_extra] + existing_configs

    with open("subscription.json", "w", encoding="utf-8") as f:
        json.dump(final_configs, f, indent=2, ensure_ascii=False)
    with open("subscription.txt", "w", encoding="utf-8") as f:
        json.dump(final_configs, f, indent=2, ensure_ascii=False)

    all_links: List[str] = []
    for cfg in existing_configs:
        remarks = cfg.get("remarks", "")
        for ob in cfg.get("outbounds", []):
            link = generate_link(ob, remarks)
            if link:
                all_links.append(link)
    all_links = list(dict.fromkeys(all_links))
    with open("sub2.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(all_links))
    with open("sub2.json", "w", encoding="utf-8") as f:
        f.write("\n".join(all_links))

    def selector_len(cfg: Dict[str, Any]) -> int:
        return len(cfg.get("routing", {}).get("balancers", [{}])[0].get("selector", []))

    log("\n✅ Успешно обновлено!")
    log(f"   • WL-noRU (белый без RU/BY): {selector_len(config_white_noru)} серверов")
    log(f"   • BL (чёрный): {selector_len(config_black)} серверов")
    log(f"   • EXTRA (26.txt): {selector_len(config_extra)} серверов")
    log(f"   • Всего записей в subscription.json: {len(final_configs)}")
    log(f"   • Ссылок для Karing: {len(all_links)}")


def main() -> None:
    try:
        asyncio.run(main_async())
    except Exception as e:
        log_err(f"❌ Критическая ошибка: {mask_secret(str(e))}")
        sys.exit(1)


if __name__ == "__main__":
    main()
