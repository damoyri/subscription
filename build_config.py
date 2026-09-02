#!/usr/bin/env python3
"""
build_config.py — сборщик VPN-конфигов для xray-core клиентов.

Особенности:
- Обычный массив конфигов в subscription.json, без SIP008-обёртки.
- Нарезка серверов по 100 штук: LTE-1, LTE-2, LTE-3... Wi-Fi-1, Wi-Fi-2...
- Пустые конфиги не создаются.
- В каждом конфиге пишется время обновления по Омску.
- Лимиты пинга настраиваются ниже: 0 = без лимита.
"""

from __future__ import annotations

import asyncio
import base64
import copy
import ipaddress
import json
import os
import random
import re
import ssl
import sys
import time
import urllib.parse
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

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

# Сколько серверов в одном конфиге
CHUNK_SIZE = 100

# Лимиты пинга.
# 0 = без лимита.
# Если GitHub Actions убивает джобу, поставь, например, 2500 или 4000.
MAX_PING_EXTRA = 0
MAX_PING_WIFI = 0

# Повторный пинг после первого прохода.
# Если включить, будет дольше, но найдёт чуть больше живых серверов.
PING_RETRY = False

TCP_TIMEOUT = 6.0
PING_BATCH = 300
RETRY_ATTEMPTS = 3
SCRIPT_TIMEOUT = 25 * 60

OMS_TZ = timezone(timedelta(hours=6))

VALID_FINGERPRINTS = {
    "chrome",
    "firefox",
    "edge",
    "safari",
    "ios",
    "android",
    "qq",
    "random",
}

SUPPORTED_NETWORKS = {
    "tcp",
    "raw",
    "ws",
    "websocket",
    "grpc",
    "gun",
    "httpupgrade",
}

NETWORK_NORMALIZE = {
    "raw": "tcp",
    "websocket": "ws",
    "gun": "grpc",
}

EXCLUDE_PATTERN = re.compile(
    r"(Россия|anycast|Беларусь|🇷🇺|🇧🇾|Russia|Belarus)",
    re.IGNORECASE,
)

_SECRET_PATTERN = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    r"|(?<=://)[^@/\s]{10,}(?=@)"
)

# ===== РУ-СЕРВИСЫ НАПРЯМУЮ =====

RU_DIRECT_DOMAINS = [
    "yandex.ru",
    "yandex.com",
    "ya.ru",
    "dzen.ru",
    "dzen.com",
    "maps.yandex.ru",
    "taxi.yandex.ru",
    "eda.yandex.ru",
    "market.yandex.ru",
    "music.yandex.ru",
    "weather.yandex.ru",
    "travel.yandex.ru",
    "kinopoisk.ru",
    "auto.ru",
    "realty.yandex.ru",
    "mail.ru",
    "vk.com",
    "vk.ru",
    "ok.ru",
    "rambler.ru",
    "rbc.ru",
    "rg.ru",
    "tass.ru",
    "lenta.ru",
    "ivi.ru",
    "okko.tv",
    "kion.ru",
    "rutube.ru",
    "bitrix24.ru",
    "kontur.ru",
    "sbis.ru",
    "getcourse.ru",
    "habr.com",
    "habr.ru",
    "2gis.ru",
    "2gis.com",
    "drom.ru",
    "wildberries.ru",
    "wildberries.com",
    "ozon.ru",
    "avito.ru",
    "cian.ru",
    "gosuslugi.ru",
    "vtb.ru",
    "alfabank.ru",
    "gazprombank.ru",
    "uchi.ru",
    "dnevnik.ru",
    "yoomoney.ru",
    "mvideo.ru",
    "eldorado.ru",
    "detmir.ru",
    "mos.ru",
    "nalog.ru",
]

RU_DOMAIN_SUFFIXES = [f".{d}" for d in RU_DIRECT_DOMAINS]

# Wi-Fi: вся зона .ru напрямую
WIFI_EXTRA_RULES = [
    {"type": "field", "domain": ["regexp:\\.ru$"], "outboundTag": "direct"},
]

# ===== LTE SNI WHITELIST =====

LTE_SNI_WHITELIST = (
    # Мессенджеры / соцсети / почта
    "vk.com",
    "vk.ru",
    "vk-portal.net",
    "userapi.com",
    "ok.ru",
    "okcdn.ru",
    "mail.ru",
    "rambler.ru",
    "max.ru",
    "oneme.ru",
    "tamtam.ru",
    "mradx.net",
    # Яндекс экосистема
    "yandex.ru",
    "yandex.com",
    "yandex.net",
    "ya.ru",
    "dzen.ru",
    "kinopoisk.ru",
    "rutube.ru",
    "yastatic.net",
    "yandexcloud.net",
    # Маркетплейсы / ритейл
    "ozon.ru",
    "ozone.ru",
    "wildberries.ru",
    "wb.ru",
    "avito.ru",
    "avito.st",
    "x5.ru",
    "ads.x5.ru",
    "lk.x5.ru",
    "lemanapro.ru",
    # Банки / финансы
    "alfabank.ru",
    "sberbank.ru",
    "vtb.ru",
    "tbank.ru",
    "tinkoff.ru",
    "cdn-tinkoff.ru",
    "yoomoney.ru",
    # Госуслуги / госсайты
    "gosuslugi.ru",
    "digital.gov.ru",
    "government.ru",
    "kremlin.ru",
    "duma.gov.ru",
    "cikrf.ru",
    "izbirkom.ru",
    "mos.ru",
    "mosreg.ru",
    "nalog.ru",
    "gu-st.ru",
    "roskachestvo.gov.ru",
    "onf.ru",
    # Транспорт / сервисы
    "rzd.ru",
    "pochta.ru",
    "taximaxim.ru",
    "tutu.ru",
    "2gis.ru",
    "2gis.com",
    "evotor.ru",
    "ofd.ru",
    "lizaalert.org",
    # Медиа
    "t2.ru",
    "gazeta.ru",
    "lenta.ru",
    "kp.ru",
    "rbc.ru",
    # Прочее
    "dobro.ru",
    "hrlink.ru",
    "sochisirius.ru",
    "sirius.online",
    "mediavitrina.ru",
    "trbcdn.net",
    "ngenix.net",
)


# ===== HELPERS =====


def mask_secret(t):
    return _SECRET_PATTERN.sub("<REDACTED>", t)


def log(msg):
    print(mask_secret(msg), flush=True)


def log_err(msg):
    print(mask_secret(msg), file=sys.stderr, flush=True)


def get_omsk_time_str():
    return datetime.now(OMS_TZ).strftime("%d.%m %H:%M")


def clean_fingerprint(fp):
    if not fp:
        return "chrome"
    cleaned = re.sub(r"[#|*].*", "", fp).strip().lower()
    return cleaned if cleaned in VALID_FINGERPRINTS else "chrome"


def is_excluded_region(remarks):
    return bool(remarks and EXCLUDE_PATTERN.search(remarks))


def normalize_address(addr):
    if addr.startswith("[") and addr.endswith("]"):
        return addr[1:-1]
    return addr


def bracket_if_ipv6(addr):
    if ":" in addr and not addr.startswith("["):
        return f"[{addr}]"
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
                "curl",
                "-sL",
                "--max-time",
                str(timeout),
                url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout + 5,
            )

            if proc.returncode == 0:
                return stdout.decode(errors="ignore").strip()

            log_err(f"⚠️ curl error {proc.returncode} for {url} (attempt {attempt+1})")
        except Exception as e:
            log_err(f"⚠️ fetch error for {url}: {e} (attempt {attempt+1})")

        if attempt < RETRY_ATTEMPTS - 1:
            await asyncio.sleep(2 ** attempt)

    return None


# ===== CONFIG TEMPLATE =====


def create_config_template(remarks_text, extra_rules=None):
    rules = [
        {"type": "field", "protocol": ["bittorrent"], "outboundTag": "direct"},
        {"type": "field", "domain": RU_DIRECT_DOMAINS, "outboundTag": "direct"},
        {"type": "field", "domain": RU_DOMAIN_SUFFIXES, "outboundTag": "direct"},
    ]

    if extra_rules:
        rules.extend(extra_rules)

    rules.append(
        {"type": "field", "network": "tcp,udp", "balancerTag": "WL_Balancer"}
    )

    return {
        "log": {"loglevel": "warning"},
        "dns": {
            "servers": ["8.8.8.8", "9.9.9.9"],
            "queryStrategy": "UseIPv4",
        },
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": 10808,
                "protocol": "socks",
                "settings": {
                    "auth": "noauth",
                    "udp": True,
                    "userLevel": 8,
                },
                "sniffing": {
                    "destOverride": ["http", "tls", "quic"],
                    "enabled": True,
                    "routeOnly": False,
                },
                "tag": "socks",
            },
            {
                "listen": "127.0.0.1",
                "port": 10809,
                "protocol": "http",
                "settings": {"userLevel": 8},
                "tag": "http",
            },
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "domainMatcher": "hybrid",
            "rules": rules,
            "balancers": [
                {
                    "tag": "WL_Balancer",
                    "selector": [],
                    "strategy": {
                        "type": "leastLoad",
                        "settings": {
                            "maxRTT": "7s",
                            "expected": 4,
                            "baselines": ["500ms", "1500ms", "3000ms"],
                            "tolerance": 0.1,
                        },
                    },
                    "fallbackTag": "direct",
                }
            ],
        },
        "observatory": {
            "enableConcurrency": True,
            "probeInterval": "2m",
            "probeUrl": "http://www.gstatic.com/generate_204",
            "subjectSelector": [],
        },
        "outbounds": [],
        "remarks": remarks_text,
    }


def create_single_outbound_config(outbound, remarks):
    if not remarks:
        remarks = (
            outbound.get("remarks")
            or outbound.get("serverName")
            or outbound.get("address")
            or outbound.get("server")
            or "Платная подписка"
        )

    config = create_config_template(remarks)

    ob_copy = copy.deepcopy(outbound)
    ob_copy["tag"] = "paid-1"

    config["outbounds"] = [
        ob_copy,
        {
            "protocol": "freedom",
            "settings": {"domainStrategy": "UseIPv4"},
            "tag": "direct",
        },
        {
            "protocol": "blackhole",
            "settings": {"response": {"type": "http"}},
            "tag": "block",
        },
    ]

    config["routing"]["balancers"][0]["selector"] = ["paid-1"]
    config["observatory"]["subjectSelector"] = ["paid-1"]

    return config


# ===== PARSE DATA CLASSES =====


@dataclass
class ParsedProxy:
    outbound: Dict[str, Any]
    remarks: str
    address: str
    port: int


@dataclass
class Candidate:
    outbound: Dict[str, Any]
    remarks: str
    address: str
    port: int
    rtt: float = 0.0
    source: str = ""


# ===== PROTOCOL HANDLERS =====


class ProtocolHandler(ABC):
    scheme: str

    @abstractmethod
    def parse(self, raw_url: str) -> Optional[ParsedProxy]:
        ...

    @staticmethod
    def split_remarks(raw_url):
        url_str = raw_url.strip()
        remarks = ""

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
        if not url_str.startswith(self.scheme):
            return None

        try:
            parsed = urllib.parse.urlparse(url_str)
            user_id, address_raw, port = parsed.username, parsed.hostname, parsed.port or 443

            if not user_id or not address_raw:
                return None

            address = normalize_address(address_raw)
            params = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items() if v}

            network = self.norm_network(params.get("type"))
            if network is None:
                return None

            fingerprint = clean_fingerprint(params.get("fp") or params.get("fingerprint"))
            is_reality = (
                ("pbk" in params)
                or ("publicKey" in params)
                or (params.get("security") == "reality")
            )

            if is_reality and not (params.get("pbk") or params.get("publicKey")):
                return None

            if is_reality and network not in ("tcp", "grpc"):
                return None

            stream: Dict[str, Any] = {
                "network": network,
                "security": "reality" if is_reality else "tls",
            }

            if network == "tcp":
                stream["tcpSettings"] = {"header": {"type": params.get("headerType", "none")}}
            elif network == "ws":
                ws = {"path": params.get("path", "/")}
                if params.get("host"):
                    ws["headers"] = {"Host": params["host"]}
                stream["wsSettings"] = ws
            elif network == "grpc":
                stream["grpcSettings"] = {"serviceName": params.get("serviceName", "")}
            elif network == "httpupgrade":
                stream["httpUpgradeSettings"] = {
                    "path": params.get("path", "/"),
                    "host": params.get("host", ""),
                }

            outbound = {
                "tag": None,
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": address,
                            "port": port,
                            "users": [
                                {
                                    "id": user_id,
                                    "encryption": "none",
                                    "flow": params.get("flow", ""),
                                    "level": 8,
                                }
                            ],
                        }
                    ]
                },
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

                if params.get("spx"):
                    reality["spiderX"] = params["spx"]

                stream["realitySettings"] = reality
            else:
                stream["tlsSettings"] = {
                    "allowInsecure": False,
                    "serverName": params.get("sni", address),
                    "fingerprint": fingerprint,
                }

            outbound["remarks"] = remarks
            return ParsedProxy(outbound, remarks, address, port)

        except Exception:
            return None


class TrojanHandler(ProtocolHandler):
    scheme = "trojan://"

    def parse(self, raw_url):
        url_str, remarks = self.split_remarks(raw_url)
        if not url_str.startswith(self.scheme):
            return None

        try:
            parsed = urllib.parse.urlparse(url_str)
            password, address_raw, port = parsed.username, parsed.hostname, parsed.port or 443

            if not password or not address_raw:
                return None

            params = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items() if v}

            network = self.norm_network(params.get("type"))
            if network is None:
                return None

            address = normalize_address(address_raw)

            stream: Dict[str, Any] = {
                "network": network,
                "security": "tls",
            }

            if network == "ws":
                ws = {"path": params.get("path", "/")}
                if params.get("host"):
                    ws["headers"] = {"Host": params["host"]}
                stream["wsSettings"] = ws
            elif network == "grpc":
                stream["grpcSettings"] = {"serviceName": params.get("serviceName", "")}

            stream["tlsSettings"] = {
                "allowInsecure": params.get("allowInsecure", "0") == "1",
                "serverName": params.get("sni", address),
                "fingerprint": clean_fingerprint(params.get("fingerprint")),
            }

            outbound = {
                "tag": None,
                "protocol": "trojan",
                "settings": {
                    "servers": [
                        {
                            "address": address,
                            "port": port,
                            "password": password,
                        }
                    ]
                },
                "streamSettings": stream,
            }

            outbound["remarks"] = remarks
            return ParsedProxy(outbound, remarks, address, port)

        except Exception:
            return None


class ShadowsocksHandler(ProtocolHandler):
    scheme = "ss://"

    def parse(self, raw_url):
        url_str, remarks = self.split_remarks(raw_url)
        if not url_str.startswith(self.scheme):
            return None

        try:
            content = url_str[len(self.scheme):]

            if "@" in content:
                userinfo, hostport = content.split("@", 1)
                decoded = base64.urlsafe_b64decode(
                    userinfo + "=" * (-len(userinfo) % 4)
                ).decode()
                method, password = decoded.split(":", 1)
            else:
                decoded = base64.urlsafe_b64decode(
                    content + "=" * (-len(content) % 4)
                ).decode()
                userinfo, hostport = decoded.split("@", 1)
                method, password = userinfo.split(":", 1)

            address_raw, port_str = hostport.rsplit(":", 1)
            address = normalize_address(address_raw)
            port = int(port_str)

            outbound = {
                "tag": None,
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [
                        {
                            "address": address,
                            "port": port,
                            "method": method,
                            "password": password,
                        }
                    ]
                },
            }

            outbound["remarks"] = remarks
            return ParsedProxy(outbound, remarks, address, port)

        except Exception:
            return None


class VmessHandler(ProtocolHandler):
    scheme = "vmess://"

    def parse(self, raw_url):
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

            network = self.norm_network(cfg.get("net"))
            if network is None:
                return None

            tls = cfg.get("tls", "")

            stream: Dict[str, Any] = {
                "network": network,
                "security": "tls" if tls == "tls" else "none",
            }

            host, path = cfg.get("host", ""), cfg.get("path", "")

            if network == "ws":
                ws = {"path": path}
                if host:
                    ws["headers"] = {"Host": host}
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
                "tag": None,
                "protocol": "vmess",
                "settings": {
                    "vnext": [
                        {
                            "address": address,
                            "port": port,
                            "users": [
                                {
                                    "id": uuid,
                                    "alterId": int(cfg.get("aid", 0)),
                                    "security": cfg.get("scy", "auto"),
                                    "level": 8,
                                }
                            ],
                        }
                    ]
                },
                "streamSettings": stream,
            }

            outbound["remarks"] = remarks
            return ParsedProxy(outbound, remarks, address, port)

        except Exception:
            return None


PROTOCOL_REGISTRY = [
    VlessHandler(),
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


# ===== PING =====


async def tcp_ping(host, port, timeout=TCP_TIMEOUT):
    start = time.monotonic()

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )

        writer.close()

        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=1)
        except Exception:
            pass

        return time.monotonic() - start
    except Exception:
        return None


async def tls_ping(host, port, timeout=TCP_TIMEOUT):
    start = time.monotonic()

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        server_hostname = None if _is_ip(host) else host

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host,
                port,
                ssl=ctx,
                server_hostname=server_hostname,
            ),
            timeout=timeout,
        )

        writer.close()

        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=1)
        except Exception:
            pass

        return time.monotonic() - start
    except Exception:
        return None


async def check_server(p: ParsedProxy):
    if p.outbound.get("protocol") in ("vless", "vmess", "trojan"):
        return await tls_ping(p.address, p.port)
    return await tcp_ping(p.address, p.port)


async def ping_candidates(
    parsed_candidates,
    max_to_ping=0,
    allow_retry=False,
):
    """
    Пинг уникальных серверов.

    max_to_ping:
      0 = без лимита
      >0 = взять случайные max_to_ping серверов после уникализации
    """

    uniq: Dict[Tuple[str, int], ParsedProxy] = {}

    for p in parsed_candidates:
        uniq.setdefault((p.address, p.port), p)

    items = list(uniq.values())

    if max_to_ping and len(items) > max_to_ping:
        log(
            f"   ✂️ Слишком много серверов ({len(items)}), "
            f"беру случайные {max_to_ping} для пинга"
        )
        random.shuffle(items)
        items = items[:max_to_ping]

    total = len(items)
    log(f"   🌐 Unique servers to ping: {total}")

    rtt_map: Dict[Tuple[str, int], Optional[float]] = {}

    for i in range(0, total, PING_BATCH):
        batch = items[i:i + PING_BATCH]
        results = await asyncio.gather(*(check_server(p) for p in batch))

        for p, rtt in zip(batch, results):
            rtt_map[(p.address, p.port)] = rtt

        log(f"   ⏳ Progress: {min(i + PING_BATCH, total)}/{total}")

    if allow_retry:
        item_keys = {(p.address, p.port) for p in items}
        dead = [
            uniq[k]
            for k, rtt in rtt_map.items()
            if rtt is None and k in item_keys
        ]

        if dead:
            log(f"   🔄 Retry: {len(dead)} не ответили, даю второй шанс")
            revived = 0

            for i in range(0, len(dead), PING_BATCH):
                batch = dead[i:i + PING_BATCH]
                results = await asyncio.gather(*(check_server(p) for p in batch))

                for p, rtt in zip(batch, results):
                    if rtt is not None:
                        rtt_map[(p.address, p.port)] = rtt
                        revived += 1

                log(
                    f"   🔄 Retry progress: "
                    f"{min(i + PING_BATCH, len(dead))}/{len(dead)}"
                )

            log(f"   ✅ Со второй попытки ожило: {revived}")

    return rtt_map


# ===== CHUNKING =====


def generate_chunked_configs(
    candidates,
    base_name,
    emoji,
    omsk_time,
    extra_rules=None,
):
    """
    Нарезает список серверов на конфиги по CHUNK_SIZE.
    Если серверов нет — не создаёт ничего.
    """

    configs = []

    if not candidates:
        return configs

    chunks = [
        candidates[i:i + CHUNK_SIZE]
        for i in range(0, len(candidates), CHUNK_SIZE)
    ]

    safe_base = re.sub(r"[^a-zA-Z0-9]", "", base_name).lower() or "config"

    for i, chunk in enumerate(chunks, start=1):
        remarks = f"{emoji} {base_name}-{i} ✅ {len(chunk)} | ⏱ {omsk_time}"
        config = create_config_template(remarks, extra_rules)

        outbounds = []
        tags = []

        for idx, cand in enumerate(chunk, start=1):
            tag = f"{safe_base}-{i}-{idx}"

            ob_copy = copy.deepcopy(cand.outbound)
            ob_copy["tag"] = tag

            outbounds.append(ob_copy)
            tags.append(tag)

        config["outbounds"] = outbounds + [
            {
                "protocol": "freedom",
                "settings": {"domainStrategy": "UseIPv4"},
                "tag": "direct",
            },
            {
                "protocol": "blackhole",
                "settings": {"response": {"type": "http"}},
                "tag": "block",
            },
        ]

        config["routing"]["balancers"][0]["selector"] = tags
        config["observatory"]["subjectSelector"] = tags

        configs.append(config)

    return configs


# ===== PAID SUBSCRIPTION =====


def _extract_server_from_dict(item):
    address = item.get("server") or item.get("address") or item.get("host")
    port = item.get("port") or item.get("port_number")

    if address and port:
        return {
            "address": normalize_address(address),
            "port": int(port),
            "protocol": item.get("type") or item.get("protocol") or "unknown",
            "remarks": item.get("remarks") or item.get("name") or "",
        }

    return None


def _filter_paid_configs(configs):
    """
    Выкидываем наши сгенерированные маркеры.
    Порядок платных конфигов не трогаем.
    """

    exclude_markers = ("🏳️", "🏴", "📦", "✅", "⛔")

    filtered = [
        c
        for c in configs
        if not any(m in c.get("remarks", "") for m in exclude_markers)
    ]

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

            # На случай, если старый файл был SIP008-обёрткой
            if isinstance(old, dict) and isinstance(old.get("servers"), list):
                old = old["servers"]

            if isinstance(old, list):
                paid_only = _filter_paid_configs(old)
                log(f"🔄 Восстановлено {len(paid_only)} платных конфигов")
                return paid_only

        except Exception as e:
            log_err(f"⚠️ Ошибка чтения subscription.json: {e}")

        return []

    try:
        data = json.loads(raw)

        # Поддержка SIP008-обёртки: {"servers": [...]}
        if isinstance(data, dict) and isinstance(data.get("servers"), list):
            data = data["servers"]

        if isinstance(data, list):
            ready, obs = [], []

            for item in data:
                if not isinstance(item, dict):
                    continue

                if "outbounds" in item and "routing" in item:
                    ready.append(item)
                elif "protocol" in item or "settings" in item:
                    obs.append((item, item.get("remarks", "")))
                else:
                    srv = _extract_server_from_dict(item)
                    if srv:
                        obs.append(
                            (
                                {
                                    "protocol": srv["protocol"],
                                    "settings": {
                                        "servers": [
                                            {
                                                "address": srv["address"],
                                                "port": srv["port"],
                                            }
                                        ]
                                    },
                                    "remarks": srv["remarks"],
                                },
                                srv["remarks"],
                            )
                        )

            if ready:
                return _filter_paid_configs(ready)

            if obs:
                return _filter_paid_configs(
                    [
                        create_single_outbound_config(ob, rm or ob.get("remarks", ""))
                        for ob, rm in obs
                    ]
                )

            log_err("⚠️ Не удалось распознать элементы списка")

        elif isinstance(data, dict):
            if "outbounds" in data and "routing" in data:
                return _filter_paid_configs([data])

            if "outbounds" in data:
                return _filter_paid_configs(
                    [
                        create_single_outbound_config(
                            ob,
                            ob.get("remarks", "") or data.get("remarks", "Платная подписка"),
                        )
                        for ob in data["outbounds"]
                    ]
                )

            srv = _extract_server_from_dict(data)

            if srv:
                return _filter_paid_configs(
                    [
                        create_single_outbound_config(
                            {
                                "protocol": srv["protocol"],
                                "settings": {
                                    "servers": [
                                        {
                                            "address": srv["address"],
                                            "port": srv["port"],
                                        }
                                    ]
                                },
                                "remarks": srv["remarks"],
                            },
                            srv["remarks"],
                        )
                    ]
                )

            log_err("⚠️ Неизвестный формат JSON")

        else:
            log_err("⚠️ Неожиданный тип JSON")

    except json.JSONDecodeError:
        try:
            decoded = base64.b64decode(raw).decode("utf-8")
        except Exception:
            decoded = raw

        items = [
            (pp.outbound, pp.remarks)
            for line in decoded.splitlines()
            if line.strip() and (pp := parse_proxy_url(line))
        ]

        if items:
            return _filter_paid_configs(
                [
                    create_single_outbound_config(ob, rm or ob.get("remarks", ""))
                    for ob, rm in items
                ]
            )

        log_err("⚠️ Не удалось распарсить ссылки")

    return []


# ===== MAIN =====


async def main_async():
    omsk_time = get_omsk_time_str()

    # ===== ПЛАТНЫЕ =====

    paid_configs = await load_paid_subscription()

    # Добавляем время Омска к платным конфигам,
    # но не плодим старые таймстампы.
    for cfg in paid_configs:
        old_remarks = cfg.get("remarks", "Платная подписка")
        base_remarks = old_remarks.split(" | ⏱")[0].strip()
        cfg["remarks"] = f"{base_remarks} | ⏱ {omsk_time}"

    log(f"Итого платных конфигов: {len(paid_configs)}\n")

    # ===== ССЫЛКИ =====

    white_links, black_links, extra_links = await asyncio.gather(
        get_links_from_urls(WHITE_URLS),
        get_links_from_urls(BLACK_URLS),
        get_links_from_urls(EXTRA_URLS),
    )

    log(
        f"Найдено ссылок: белые={len(white_links)}, "
        f"чёрные={len(black_links)}, extra={len(extra_links)}"
    )

    def parse_all(links):
        return [
            p
            for link in links
            if (p := parse_proxy_url(link)) is not None
        ]

    white_parsed_all = parse_all(white_links)
    black_parsed = parse_all(black_links)
    extra_parsed_all = parse_all(extra_links)

    # Для LTE используем только РУ-SNI
    white_parsed = [p for p in white_parsed_all if is_lte_compatible(p)]
    extra_parsed = [p for p in extra_parsed_all if is_lte_compatible(p)]

    # ===== PING EXTRA =====

    log(f"📱 Pinging extra (LTE reserve): {len(extra_parsed)}")

    rtt_map_extra = await ping_candidates(
        extra_parsed,
        max_to_ping=MAX_PING_EXTRA,
        allow_retry=PING_RETRY,
    )

    alive_extra = [
        Candidate(
            p.outbound,
            p.remarks,
            p.address,
            p.port,
            rtt_map_extra[(p.address, p.port)],
            "LTE-Extra",
        )
        for p in extra_parsed
        if rtt_map_extra.get((p.address, p.port)) is not None
    ]

    alive_extra.sort(key=lambda c: c.rtt)

    # ===== PING BLACK =====

    log(f"📱 Pinging black (Wi-Fi): {len(black_parsed)}")

    rtt_map_black = await ping_candidates(
        black_parsed,
        max_to_ping=MAX_PING_WIFI,
        allow_retry=PING_RETRY,
    )

    alive_black = [
        Candidate(
            p.outbound,
            p.remarks,
            p.address,
            p.port,
            rtt_map_black[(p.address, p.port)],
            "Wi-Fi",
        )
        for p in black_parsed
        if rtt_map_black.get((p.address, p.port)) is not None
    ]

    alive_black.sort(key=lambda c: c.rtt)

    # ===== LTE: ВСЕ РЕГИОНЫ =====

    lte_all_pool = []
    seen_all = set()

    # Сначала белые списки
    for p in white_parsed:
        key = (p.address, p.port)
        if key in seen_all:
            continue

        seen_all.add(key)
        lte_all_pool.append(
            Candidate(
                p.outbound,
                p.remarks,
                p.address,
                p.port,
                0.0,
                "LTE-White",
            )
        )

    # Потом живые пропингованные резервные
    for c in alive_extra:
        key = (c.address, c.port)
        if key in seen_all:
            continue

        seen_all.add(key)
        lte_all_pool.append(c)

    # ===== LTE: БЕЗ РФ/РБ =====

    lte_no_ru_pool = []
    seen_no_ru = set()

    for p in white_parsed:
        if is_excluded_region(p.remarks):
            continue

        key = (p.address, p.port)
        if key in seen_no_ru:
            continue

        seen_no_ru.add(key)
        lte_no_ru_pool.append(
            Candidate(
                p.outbound,
                p.remarks,
                p.address,
                p.port,
                0.0,
                "LTE-White",
            )
        )

    for c in alive_extra:
        if is_excluded_region(c.remarks):
            continue

        key = (c.address, c.port)
        if key in seen_no_ru:
            continue

        seen_no_ru.add(key)
        lte_no_ru_pool.append(c)

    # ===== GENERATE CONFIGS =====

    lte_all_configs = generate_chunked_configs(
        lte_all_pool,
        "LTE",
        "🏳️",
        omsk_time,
    )

    lte_no_ru_configs = generate_chunked_configs(
        lte_no_ru_pool,
        "LTE(no-ru)",
        "🏳️",
        omsk_time,
    )

    wifi_configs = generate_chunked_configs(
        alive_black,
        "Wi-Fi",
        "🏴",
        omsk_time,
        extra_rules=WIFI_EXTRA_RULES,
    )

    final_configs = (
        lte_all_configs
        + lte_no_ru_configs
        + wifi_configs
        + paid_configs
    )

    # Обычный массив конфигов, без SIP008
    with open("subscription.json", "w", encoding="utf-8") as f:
        json.dump(final_configs, f, indent=2, ensure_ascii=False)

    log("\n✅ Успешно обновлено!")
    log(f"   • 🏳️ LTE (все регионы): {len(lte_all_configs)} конфигов, серверов в пуле: {len(lte_all_pool)}")
    log(f"   • 🏳️ LTE (no-ru): {len(lte_no_ru_configs)} конфигов, серверов в пуле: {len(lte_no_ru_pool)}")
    log(f"   • 🏴 Wi-Fi: {len(wifi_configs)} конфигов, живых серверов: {len(alive_black)}")
    log(f"   • Платных конфигов: {len(paid_configs)}")
    log(f"   • Всего записей: {len(final_configs)}")


def main():
    try:
        asyncio.run(asyncio.wait_for(main_async(), timeout=SCRIPT_TIMEOUT))
    except asyncio.TimeoutError:
        log_err(f"❌ Скрипт превысил лимит {SCRIPT_TIMEOUT}s и был остановлен")
        sys.exit(1)
    except Exception as e:
        log_err(f"❌ Критическая ошибка: {mask_secret(str(e))}")

        import traceback

        log_err(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()
