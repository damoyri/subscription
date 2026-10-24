#!/usr/bin/env python3
"""
Сбор VPN-конфигов из нескольких источников + проверка, что конфиг РЕАЛЬНО работает.

Как проверяется (для vless / vmess / trojan / ss):
  каждый конфиг поднимается в настоящем ядре Xray как локальный SOCKS-вход,
  через него идёт HTTP-запрос на generate_204 и скачивается небольшой файл.
  Так проверяются ключ, UUID, flow, SNI, shortId — всё, что рукопожатие не видит.
  Пинг вторичен: это время реального запроса через туннель.

Что не умеет проверить Xray (hysteria2/tuic/wireguard, allowInsecure, плагины ss и т.п.):
  UDP-протоколы остаются как есть, остальное проходит старую проверку TCP + TLS.

Защита от поломок:
  - нет ядра / ядро не стартует / у раннера нет интернета -> подписку НЕ трогаем, выходим с кодом 0;
  - рабочих меньше MIN_WORKING или ядро массово отвергает конфиги -> подписку не трогаем;
  - общий лимит времени TIME_BUDGET_SEC, все процессы ядра гарантированно убиваются.
"""
import atexit
import base64
import ipaddress
import json
import os
import random
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

# ================= НАСТРОЙКИ =================
MAX_CONFIGS = 1000            # сколько конфигов оставить в итоге
OUTPUT_FILE = "subscription.json"
DEAD_FILE = "dead.txt"        # куда сложить отбракованные (для отладки), "" — не писать
CHECK_ENABLED = True          # включить проверку живости
MAX_LATENCY_MS = 6000         # отбрасывать слишком медленные (время реального запроса через туннель)
SORT_BY_LATENCY = True        # быстрые конфиги наверх (внутри страны); время меряется С РАННЕРА GitHub
DEDUP_BY_SERVER = False       # True = не больше одного конфига на host:port
KEEP_UDP_PROTOCOLS = True     # hysteria2/tuic/wireguard: проверить нечем, оставлять как есть
FALLBACK_LEGACY_CHECK = True  # то, что Xray не умеет, проверять по TCP+TLS (иначе — выбрасывать)

# --- реальная проверка через Xray ---
XRAY_PATH = os.environ.get("XRAY_PATH", "")   # путь к бинарнику; пусто = искать в PATH и ./xray/xray
CHUNK_SIZE = 120              # конфигов на один процесс Xray
PARALLEL_CHUNKS = 3           # сколько процессов Xray одновременно
STARTUP_TIMEOUT = 20.0        # сколько ждать старта Xray, сек
TUNNEL_TIMEOUT = 8.0          # таймаут одного запроса через туннель, сек
DOWNLOAD_TIMEOUT = 10.0       # таймаут скачивания тестового файла, сек
REQUIRE_DOWNLOAD = True       # дополнительно скачать файл (ловит «рукопожатие есть, данных нет»)
MIN_DOWNLOAD_BYTES = 40_000   # сколько байт должно прийти через туннель
RETRY_FAILED = True           # второй проход по упавшим (отсекает случайные таймауты)
TIME_BUDGET_SEC = int(os.environ.get("TIME_BUDGET_SEC", 16 * 60))  # лимит времени на проверку
MAX_TO_CHECK = 6000           # защита, если источник внезапно отдал мусорный огромный список
MIN_WORKING = 10              # меньше рабочих — считаем, что что-то сломалось, файл не трогаем
MAX_REJECT_SHARE = 0.5        # если ядро отвергло больше половины конфигов — формат устарел, файл не трогаем
ALLOW_PRIVATE_HOSTS = False   # False = конфиги с адресом 127.x / 10.x / localhost отбрасываются

# --- старая проверка (запасная) ---
CONNECT_TIMEOUT = 4.0
TLS_TIMEOUT = 5.0
MAX_WORKERS = 120

# куда стучимся ЧЕРЕЗ туннель: (url, ожидаемый код)
TUNNEL_URLS = [
    ("http://cp.cloudflare.com/generate_204", 204),
    ("https://www.gstatic.com/generate_204", 204),
]
# что скачиваем через туннель (>16 КБ, чтобы поймать обрыв после первых пакетов)
DOWNLOAD_URLS = [
    "https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js",
    "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js",
]

URLS = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",
    "https://etoneya.su/whitelist"
]
UDP_SCHEMES = {"hysteria", "hysteria2", "hy2", "tuic", "wireguard", "warp"}
SS_METHODS = {
    "aes-128-gcm", "aes-256-gcm", "chacha20-poly1305", "chacha20-ietf-poly1305",
    "xchacha20-poly1305", "xchacha20-ietf-poly1305", "none", "plain",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
}
# =============================================

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_SSL_CTX = ssl.create_default_context()


class Unsupported(Exception):
    """Конфиг валиден, но проверить его через Xray нельзя."""


class Invalid(Exception):
    """Конфиг заведомо негоден (битый uuid, ключ, порт и т.п.)."""


def log(msg=""):
    print(msg, flush=True)


def warn(msg):
    # аннотация в интерфейсе GitHub Actions + обычная строка в логе
    print(f"::warning::{msg}", flush=True)


# ---------- загрузка ----------
def is_valid_config(line: str) -> bool:
    line = line.strip()
    if not line or line.startswith("#") or len(line) > 8000:
        return False
    return "://" in line


def fetch_url(url: str) -> list:
    content = None
    for attempt in range(1, 4):
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"}
            )
            with urllib.request.urlopen(req, timeout=20) as response:
                content = response.read(30_000_000).decode("utf-8", errors="ignore")
            break
        except Exception as e:
            print(f"⚠️ Ошибка при скачивании {url} (попытка {attempt}/3): {e}", file=sys.stderr, flush=True)
            time.sleep(2 * attempt)
    if content is None:
        return []
    # источник может отдавать base64-подписку целиком
    stripped = "".join(content.split())
    if "://" not in content and len(stripped) > 40:
        try:
            content = b64decode(stripped).decode("utf-8", errors="ignore")
        except Exception:
            pass
    return [l.strip() for l in content.splitlines() if is_valid_config(l)]


# ---------- парсинг (старый, для запасной проверки/сортировки) ----------
def b64decode(data: str) -> bytes:
    data = data.strip().replace("-", "+").replace("_", "/")
    data += "=" * (-len(data) % 4)
    return base64.b64decode(data)


def parse_config(line: str):
    """
    Возвращает dict: scheme, host, port, tls(bool), sni(str|None)
    или None, если распарсить не удалось.
    """
    try:
        scheme = line.split("://", 1)[0].lower()
        rest = line.split("://", 1)[1]
        # ---- vmess: base64(json) ----
        if scheme == "vmess":
            raw = rest.split("#", 1)[0]
            cfg = json.loads(b64decode(raw).decode("utf-8", errors="ignore"))
            host = str(cfg.get("add", "")).strip()
            port = int(str(cfg.get("port", "0")).strip() or 0)
            tls = str(cfg.get("tls", "")).lower() in ("tls", "reality", "true", "1")
            sni = cfg.get("sni") or cfg.get("host") or host
            return mk(scheme, host, port, tls, sni)
        # ---- ss: может быть base64 целиком ----
        if scheme in ("ss", "ssr") and "@" not in rest.split("#", 1)[0]:
            raw = rest.split("#", 1)[0]
            decoded = b64decode(raw).decode("utf-8", errors="ignore")
            if "@" in decoded:
                hostport = decoded.rsplit("@", 1)[1]
                host, port = split_hostport(hostport)
                return mk(scheme, host, port, False, None)
            return None
        # ---- остальное: uuid/pass@host:port?params#name ----
        u = urllib.parse.urlsplit(line)
        host = u.hostname
        port = u.port
        q = urllib.parse.parse_qs(u.query)
        security = (q.get("security", [""])[0] or "").lower()
        tls = security in ("tls", "reality", "xtls") or scheme in ("trojan", "hysteria2", "hy2", "tuic")
        sni = (
            q.get("sni", [None])[0]
            or q.get("peer", [None])[0]
            or q.get("host", [None])[0]
            or host
        )
        if not port:
            port = 443
        return mk(scheme, host, port, tls, sni)
    except Exception:
        return None


def split_hostport(s: str):
    if s.startswith("["):  # IPv6
        host, _, port = s[1:].partition("]:")
        return host, int(port)
    host, _, port = s.rpartition(":")
    return host, int(port)


def mk(scheme, host, port, tls, sni):
    if not host or not port or port < 1 or port > 65535:
        return None
    return {"scheme": scheme, "host": host, "port": int(port), "tls": bool(tls), "sni": sni}


def get_name(cfg: str) -> str:
    try:
        if cfg.lower().startswith("vmess://"):
            raw = cfg.split("://", 1)[1].split("#", 1)[0]
            return json.loads(b64decode(raw).decode("utf-8", errors="ignore")).get("ps", "")
        if "#" in cfg:
            return urllib.parse.unquote(cfg.split("#", 1)[1])
    except Exception:
        pass
    return ""


def name_key(cfg: str):
    name = get_name(cfg)
    low = name.lower()
    # Россия — в самый конец
    if "🇷🇺" in name or "russia" in low or "росси" in low:
        return (2, "")
    # остальные страны — по алфавиту кода флага
    flags = re.findall("[\U0001F1E6-\U0001F1FF]{2}", name)
    if flags:
        return (0, flags[0])
    # без флага (Unknown и т.п.) — между странами и Россией
    return (1, low)


# ---------- конвертер ссылка -> outbound Xray ----------
def flat_params(query: str) -> dict:
    return {k.lower(): v[0] for k, v in urllib.parse.parse_qs(query).items() if v and v[0] != ""}


def check_host(host):
    if not host or len(host) > 253 or any(c.isspace() for c in host):
        raise Invalid("плохой адрес сервера")
    low = host.lower()
    if not ALLOW_PRIVATE_HOSTS:
        if low == "localhost" or low.endswith(".localhost") or low.endswith(".local"):
            raise Invalid("локальный адрес")
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None
        if ip is not None and (ip.is_private or ip.is_loopback or ip.is_link_local
                               or ip.is_unspecified or ip.is_reserved or ip.is_multicast):
            raise Invalid("приватный/служебный IP")


def check_port(port):
    if port is None or not (1 <= int(port) <= 65535):
        raise Invalid("порт")
    return int(port)


def build_stream(p: dict, host: str, default_security: str) -> dict:
    """p — параметры ссылки в нижнем регистре. Возвращает streamSettings для Xray."""
    net = (p.get("type") or p.get("net") or "tcp").lower()
    if net == "raw":
        net = "tcp"
    sec = (p.get("security") or default_security or "none").lower()
    if sec == "xtls":
        sec = "tls"
    if sec not in ("none", "tls", "reality"):
        raise Unsupported(f"security={sec}")

    stream = {"security": sec}

    # ---- транспорт ----
    if net == "tcp":
        if (p.get("headertype") or "none").lower() not in ("none", ""):
            raise Unsupported("tcp headerType")
        stream["network"] = "tcp"
    elif net == "ws":
        stream["network"] = "ws"
        ws = {"path": p.get("path") or "/"}
        if p.get("host"):
            ws["host"] = p["host"]
        stream["wsSettings"] = ws
    elif net == "grpc":
        stream["network"] = "grpc"
        g = {"serviceName": p.get("servicename") or p.get("path") or ""}
        if (p.get("mode") or "").lower() == "multi":
            g["multiMode"] = True
        if p.get("authority"):
            g["authority"] = p["authority"]
        stream["grpcSettings"] = g
    elif net == "httpupgrade":
        stream["network"] = "httpupgrade"
        h = {"path": p.get("path") or "/"}
        if p.get("host"):
            h["host"] = p["host"]
        stream["httpupgradeSettings"] = h
    elif net in ("xhttp", "splithttp"):
        stream["network"] = "xhttp"
        x = {"path": p.get("path") or "/"}
        if p.get("host"):
            x["host"] = p["host"]
        if p.get("mode"):
            x["mode"] = p["mode"]
        if p.get("extra"):
            try:
                x["extra"] = json.loads(p["extra"])
            except Exception:
                raise Invalid("xhttp extra не JSON")
        stream["xhttpSettings"] = x
    else:
        raise Unsupported(f"транспорт {net}")

    # ---- защита ----
    def truthy(v):
        return str(v).lower() in ("1", "true", "yes")

    if sec == "tls":
        if truthy(p.get("allowinsecure", "")) or truthy(p.get("insecure", "")):
            raise Unsupported("allowInsecure (Xray его больше не поддерживает)")
        if p.get("pcs") or p.get("ech") or p.get("vcn"):
            raise Unsupported("pcs/ech/vcn")
        tls = {}
        sni = p.get("sni") or p.get("peer") or p.get("host") or ""
        if not sni:
            try:
                ipaddress.ip_address(host)
            except ValueError:
                sni = host
        if sni:
            tls["serverName"] = sni
        fp = (p.get("fp") or "").lower()
        if fp and fp != "none":
            tls["fingerprint"] = fp
        if p.get("alpn"):
            tls["alpn"] = [a for a in p["alpn"].split(",") if a]
        stream["tlsSettings"] = tls
    elif sec == "reality":
        pbk = p.get("pbk") or p.get("publickey") or ""
        try:
            if len(b64decode(pbk)) != 32:
                raise ValueError
        except Exception:
            raise Invalid("reality: публичный ключ (pbk)")
        sid = p.get("sid") or p.get("shortid") or ""
        if len(sid) > 16 or len(sid) % 2 or not re.fullmatch(r"[0-9a-fA-F]*", sid):
            raise Invalid("reality: shortId (sid)")
        sni = p.get("sni") or p.get("peer") or host
        r = {
            "serverName": sni,
            "fingerprint": (p.get("fp") or "chrome").lower(),
            "publicKey": pbk,
            "shortId": sid,
            "spiderX": p.get("spx") or "",
        }
        if p.get("pqv"):
            r["mldsa65Verify"] = p["pqv"]
        stream["realitySettings"] = r
    return stream


def _vless_or_trojan(scheme: str, line: str) -> dict:
    u = urllib.parse.urlsplit(line)
    try:
        port = u.port
    except ValueError:
        raise Invalid("порт")
    host = u.hostname
    check_host(host)
    port = check_port(port if port is not None else 443)
    secret = urllib.parse.unquote(u.username or "")
    p = flat_params(u.query)
    if scheme == "vless":
        if not UUID_RE.match(secret):
            raise Invalid("uuid")
        user = {"id": secret, "encryption": p.get("encryption") or "none"}
        if p.get("flow"):
            user["flow"] = p["flow"]
        return {
            "protocol": "vless",
            "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
            "streamSettings": build_stream(p, host, "none"),
        }
    if not secret:
        raise Invalid("пустой пароль trojan")
    return {
        "protocol": "trojan",
        "settings": {"servers": [{"address": host, "port": port, "password": secret}]},
        "streamSettings": build_stream(p, host, "tls"),
    }


def _vmess(rest: str) -> dict:
    try:
        j = json.loads(b64decode(rest.split("#", 1)[0]).decode("utf-8", errors="ignore"))
    except Exception:
        raise Invalid("vmess: не base64-json")
    host = str(j.get("add", "")).strip()
    check_host(host)
    try:
        port = check_port(int(str(j.get("port", "")).strip()))
    except ValueError:
        raise Invalid("порт")
    uid = str(j.get("id", "")).strip()
    if not UUID_RE.match(uid):
        raise Invalid("uuid")
    net = str(j.get("net") or "tcp").lower()
    p = {
        "type": net,
        "headertype": j.get("type") or "none",
        "host": j.get("host") or "",
        "path": j.get("path") or "",
        "security": "tls" if str(j.get("tls", "")).lower() in ("tls", "true", "1") else "none",
        "sni": j.get("sni") or "",
        "alpn": j.get("alpn") or "",
        "fp": j.get("fp") or "",
        "allowinsecure": j.get("allowInsecure") or j.get("insecure") or "",
    }
    p = {k: str(v) for k, v in p.items() if v not in ("", None)}
    if net == "grpc" and p.get("path"):
        p["servicename"] = p["path"]
    try:
        aid = int(str(j.get("aid") or 0))
    except ValueError:
        aid = 0
    user = {"id": uid, "alterId": aid, "security": str(j.get("scy") or "auto")}
    return {
        "protocol": "vmess",
        "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
        "streamSettings": build_stream(p, host, "none"),
    }


def _ss(line: str) -> dict:
    body = line.split("://", 1)[1]
    main_part = body.split("#", 1)[0]
    main_part, _, query = main_part.partition("?")
    if "plugin" in query.lower():
        raise Unsupported("ss plugin")
    try:
        if "@" in main_part:
            userinfo, _, hostport = main_part.rpartition("@")
            ui = urllib.parse.unquote(userinfo)
            if ":" not in ui:
                ui = b64decode(ui).decode("utf-8", errors="ignore")
        else:
            dec = b64decode(main_part).decode("utf-8", errors="ignore")
            ui, _, hostport = dec.rpartition("@")
        method, _, password = ui.partition(":")
        host, port = split_hostport(hostport.rstrip("/"))
    except Exception:
        raise Invalid("ss: не разобрать ссылку")
    check_host(host)
    port = check_port(port)
    method = method.lower()
    if method not in SS_METHODS:
        raise Unsupported(f"ss метод {method}")
    if not password:
        raise Invalid("пустой пароль ss")
    return {
        "protocol": "shadowsocks",
        "settings": {"servers": [{"address": host, "port": port, "method": method, "password": password}]},
    }


def to_outbound(line: str) -> dict:
    scheme = line.split("://", 1)[0].lower()
    if scheme == "vmess":
        return _vmess(line.split("://", 1)[1])
    if scheme in ("vless", "trojan"):
        return _vless_or_trojan(scheme, line)
    if scheme == "ss":
        return _ss(line)
    raise Unsupported(f"схема {scheme}")


# ---------- запуск ядра ----------
_LIVE = set()
_LIVE_LOCK = threading.Lock()
_PORT_LOCK = threading.Lock()
_PORTS_BUSY = set()


def kill_all_cores(*_):
    with _LIVE_LOCK:
        procs = list(_LIVE)
    for p in procs:
        _kill(p)


def _kill(proc):
    try:
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except Exception:
                proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except Exception:
                    proc.kill()
                try:
                    proc.wait(timeout=3)
                except Exception:
                    pass
    except Exception:
        pass
    with _LIVE_LOCK:
        _LIVE.discard(proc)


def _on_signal(signum, _frame):
    kill_all_cores()
    sys.exit(128 + signum)


def find_core() -> str:
    cands = [XRAY_PATH, shutil.which("xray") or "", "./xray/xray", "./xray"]
    for c in cands:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return os.path.abspath(c)
    return ""


def reserve_ports(n: int) -> list:
    """Свободные порты вне эфемерного диапазона (чтобы не пересекаться с исходящими соединениями)."""
    with _PORT_LOCK:
        ports = []
        tries = 0
        while len(ports) < n and tries < n * 50 + 100:
            tries += 1
            port = random.randint(20000, 32000)
            if port in _PORTS_BUSY or port in ports:
                continue
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.bind(("127.0.0.1", port))
            except OSError:
                continue
            finally:
                s.close()
            ports.append(port)
        if len(ports) < n:
            raise RuntimeError("не нашлось свободных портов")
        _PORTS_BUSY.update(ports)
        return ports


def release_ports(ports):
    with _PORT_LOCK:
        _PORTS_BUSY.difference_update(ports)


def build_core_config(outbounds: list, ports: list) -> dict:
    inbounds, outs, rules = [], [], []
    for i, (ob, port) in enumerate(zip(outbounds, ports)):
        itag, otag = f"i{i}", f"o{i}"
        inbounds.append({
            "tag": itag, "listen": "127.0.0.1", "port": port, "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
        })
        ob = dict(ob)
        ob["tag"] = otag
        outs.append(ob)
        rules.append({"type": "field", "inboundTag": [itag], "outboundTag": otag})
    outs.append({"tag": "block", "protocol": "blackhole"})
    return {
        "log": {"loglevel": "error"},
        "inbounds": inbounds,
        "outbounds": outs,
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }


class CoreInstance:
    """Один процесс Xray: N SOCKS-входов, каждый ведёт в свой outbound."""

    def __init__(self, core: str):
        self.core = core
        self.proc = None
        self.ports = []
        self.dir = None
        self.error = ""

    def start(self, outbounds: list) -> bool:
        self.ports = reserve_ports(len(outbounds))
        self.dir = tempfile.mkdtemp(prefix="xchk_")
        cfg_path = os.path.join(self.dir, "config.json")
        log_path = os.path.join(self.dir, "core.log")
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(build_core_config(outbounds, self.ports), f)
        logf = open(log_path, "wb")
        try:
            self.proc = subprocess.Popen(
                [self.core, "run", "-c", cfg_path],
                stdin=subprocess.DEVNULL, stdout=logf, stderr=subprocess.STDOUT,
                start_new_session=True, cwd=self.dir,
            )
        except Exception as e:
            self.error = f"не запустился: {e}"
            return False
        finally:
            logf.close()
        with _LIVE_LOCK:
            _LIVE.add(self.proc)
        if self._wait_ready():
            return True
        self.error = self._log_tail() or "ядро не поднялось"
        return False

    def _wait_ready(self) -> bool:
        end = time.monotonic() + STARTUP_TIMEOUT
        pending = list(self.ports)
        while pending and time.monotonic() < end:
            if self.proc.poll() is not None:
                return False
            still = []
            for port in pending:
                try:
                    socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
                except OSError:
                    still.append(port)
            pending = still
            if pending:
                time.sleep(0.2)
        return not pending

    def _log_tail(self) -> str:
        try:
            with open(os.path.join(self.dir, "core.log"), "rb") as f:
                data = f.read()[-600:]
            text = re.sub(r"\x1b\[[0-9;]*m", "", data.decode("utf-8", errors="ignore"))
            return " ".join(text.split())[-300:]
        except Exception:
            return ""

    def close(self):
        if self.proc is not None:
            _kill(self.proc)
        release_ports(self.ports)
        if self.dir:
            shutil.rmtree(self.dir, ignore_errors=True)


# ---------- HTTP через SOCKS5 (без сторонних библиотек) ----------
def _recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("соединение закрыто")
        buf += chunk
    return buf


def http_get_via_socks(port: int, url: str, timeout: float, stop_after=None):
    """GET через локальный SOCKS5. Возвращает (код ответа, байт тела).
    stop_after — прекратить чтение, когда набрано столько байт тела."""
    u = urllib.parse.urlsplit(url)
    host = u.hostname
    https = u.scheme == "https"
    dport = u.port or (443 if https else 80)
    path = (u.path or "/") + (("?" + u.query) if u.query else "")
    end = time.monotonic() + timeout

    def left():
        r = end - time.monotonic()
        if r <= 0:
            raise TimeoutError("таймаут")
        return r

    raw = socket.create_connection(("127.0.0.1", port), timeout=left())
    s = raw
    try:
        s.settimeout(left())
        s.sendall(b"\x05\x01\x00")
        if _recv_exact(s, 2) != b"\x05\x00":
            raise ConnectionError("socks: отказ")
        hb = host.encode("idna")
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + dport.to_bytes(2, "big"))
        rep = _recv_exact(s, 4)
        if rep[1] != 0:
            raise ConnectionError(f"socks: код {rep[1]}")
        if rep[3] == 1:
            _recv_exact(s, 4 + 2)
        elif rep[3] == 4:
            _recv_exact(s, 16 + 2)
        else:
            _recv_exact(s, _recv_exact(s, 1)[0] + 2)
        if https:
            s.settimeout(left())
            s = _SSL_CTX.wrap_socket(raw, server_hostname=host)
        req = (f"GET {path} HTTP/1.1\r\nHost: {u.netloc}\r\n"
               "User-Agent: Mozilla/5.0 (X11; Linux x86_64)\r\nAccept: */*\r\n"
               "Accept-Encoding: identity\r\nConnection: close\r\n\r\n")
        s.settimeout(left())
        s.sendall(req.encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            s.settimeout(left())
            chunk = s.recv(65536)
            if not chunk:
                raise ConnectionError("обрыв до заголовков ответа")
            buf += chunk
            if len(buf) > 65536:
                raise ValueError("слишком длинные заголовки")
        head, _, body = buf.partition(b"\r\n\r\n")
        status = int(head.split(b" ", 2)[1])
        total = len(body)
        while stop_after is not None and total < stop_after:
            s.settimeout(left())
            chunk = s.recv(65536)
            if not chunk:
                break
            total += len(chunk)
        return status, total
    finally:
        for sock in (s, raw):
            try:
                sock.close()
            except Exception:
                pass


def short_err(e: Exception) -> str:
    if isinstance(e, (TimeoutError, socket.timeout)):
        return "таймаут"
    if isinstance(e, ssl.SSLError):
        return "TLS-ошибка внутри туннеля"
    if isinstance(e, ConnectionError):
        return str(e) or "обрыв"
    return type(e).__name__


def check_via_port(port: int, deadline: float):
    """Реальная проверка одного конфига. Возвращает (ok, задержка_мс|None, причина)."""
    last = "нет ответа"
    latency = None
    for url, want in TUNNEL_URLS:
        if time.monotonic() > deadline:
            return False, None, "лимит времени"
        t0 = time.perf_counter()
        try:
            status, _ = http_get_via_socks(port, url, TUNNEL_TIMEOUT)
            if status == want:
                latency = (time.perf_counter() - t0) * 1000
                break
            last = f"код ответа {status}"
        except Exception as e:
            last = short_err(e)
    if latency is None:
        return False, None, f"туннель: {last}"
    if latency > MAX_LATENCY_MS:
        return False, latency, f"медленный: {int(latency)} мс"

    if REQUIRE_DOWNLOAD:
        got, last = 0, "нет ответа"
        for url in DOWNLOAD_URLS:
            if time.monotonic() > deadline:
                return False, None, "лимит времени"
            try:
                status, n = http_get_via_socks(port, url, DOWNLOAD_TIMEOUT, stop_after=MIN_DOWNLOAD_BYTES)
                got = max(got, n)
                if status == 200 and n >= MIN_DOWNLOAD_BYTES:
                    return True, latency, "ok"
                last = f"код {status}, получено {n} байт"
            except Exception as e:
                last = short_err(e)
        return False, latency, f"загрузка: {last}"
    return True, latency, "ok"


# ---------- пакетная проверка ----------
def run_chunk(chunk: list, core: str, deadline: float) -> dict:
    """chunk: [(idx, cfg, outbound)] -> {idx: (ok, latency, reason)}.
    Если Xray не стартует из-за одного кривого конфига — делим пополам, пока не найдём виновника."""
    if time.monotonic() > deadline:
        return {i: (False, None, "лимит времени") for i, _, _ in chunk}
    inst = CoreInstance(core)
    try:
        ok = inst.start([ob for _, _, ob in chunk])
        if ok:
            out = {}
            with ThreadPoolExecutor(max_workers=len(chunk)) as pool:
                futs = {pool.submit(check_via_port, port, deadline): idx
                        for (idx, _, _), port in zip(chunk, inst.ports)}
                for fut in as_completed(futs):
                    try:
                        out[futs[fut]] = fut.result()
                    except Exception as e:
                        out[futs[fut]] = (False, None, f"туннель: {short_err(e)}")
            return out
        err = inst.error
    finally:
        inst.close()
    if len(chunk) == 1:
        return {chunk[0][0]: (False, None, f"ядро отвергло конфиг: {err}")}
    mid = len(chunk) // 2
    out = run_chunk(chunk[:mid], core, deadline)
    out.update(run_chunk(chunk[mid:], core, deadline))
    return out


def run_pass(items: list, core: str, deadline: float) -> dict:
    chunks = [items[i:i + CHUNK_SIZE] for i in range(0, len(items), CHUNK_SIZE)]
    results, done = {}, 0
    with ThreadPoolExecutor(max_workers=PARALLEL_CHUNKS) as pool:
        futs = [pool.submit(run_chunk, c, core, deadline) for c in chunks]
        for fut in as_completed(futs):
            try:
                results.update(fut.result())
            except Exception as e:
                warn(f"сбой пакета проверки: {type(e).__name__}: {e}")
            done += 1
            alive = sum(1 for r in results.values() if r[0])
            log(f"   пакетов {done}/{len(chunks)} | проверено {len(results)}/{len(items)} | рабочих {alive}")
    return results


def is_retryable(reason: str) -> bool:
    return reason.startswith("туннель") or reason.startswith("загрузка")


def verify_with_core(items: list, core: str, deadline: float) -> dict:
    results = {}
    pending = items
    passes = 2 if RETRY_FAILED else 1
    for n in range(1, passes + 1):
        if not pending:
            break
        log(f"🔍 Проход {n}/{passes}: проверяем {len(pending)} конфигов через ядро")
        res = run_pass(pending, core, deadline)
        retry = []
        for it in pending:
            r = res.get(it[0], (False, None, "лимит времени"))
            results[it[0]] = r
            if not r[0] and is_retryable(r[2]):
                retry.append(it)
        pending = retry
    return results


def selftest(core: str):
    """Контроль без VPN: ядро стартует, а у раннера есть доступ к тестовым адресам
    (запрос идёт через freedom-outbound). Возвращает (ok, сообщение, скачивание_работает)."""
    inst = CoreInstance(core)
    try:
        if not inst.start([{"protocol": "freedom", "settings": {}}]):
            return False, f"ядро не стартует: {inst.error}", False
        port = inst.ports[0]
        errs, tunnel_ok = [], False
        for url, want in TUNNEL_URLS:
            try:
                status, _ = http_get_via_socks(port, url, TUNNEL_TIMEOUT)
                if status == want:
                    tunnel_ok = True
                    break
                errs.append(f"{url}: код {status}")
            except Exception as e:
                errs.append(f"{url}: {short_err(e)}")
        if not tunnel_ok:
            return False, "у раннера нет доступа к тестовым адресам: " + "; ".join(errs), False
        download_ok = not REQUIRE_DOWNLOAD
        if REQUIRE_DOWNLOAD:
            for url in DOWNLOAD_URLS:
                try:
                    status, n = http_get_via_socks(port, url, DOWNLOAD_TIMEOUT, stop_after=MIN_DOWNLOAD_BYTES)
                    if status == 200 and n >= MIN_DOWNLOAD_BYTES:
                        download_ok = True
                        break
                except Exception:
                    pass
        return True, "ok", download_ok
    finally:
        inst.close()


# ---------- запасная проверка (TCP + TLS) ----------
def check_alive(info: dict):
    """Возвращает задержку в мс или None, если сервер не отвечает."""
    host, port = info["host"], info["port"]
    start = time.perf_counter()
    try:
        sock = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
    except Exception:
        return None
    try:
        if info["tls"]:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE          # у Reality/самоподписанных проверять нечего
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            sock.settimeout(TLS_TIMEOUT)
            with ctx.wrap_socket(sock, server_hostname=info["sni"] or host) as ssock:
                if ssock.version() not in ("TLSv1.2", "TLSv1.3"):
                    return None
        # (раньше для не-TLS конфигов здесь возвращался None — они всегда считались мёртвыми)
        return (time.perf_counter() - start) * 1000
    except Exception:
        return None
    finally:
        try:
            sock.close()
        except Exception:
            pass


def legacy_check_many(items: list) -> dict:
    """items: [(idx, cfg)] -> {idx: latency|None}"""
    out = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futs = {}
        for idx, cfg in items:
            info = parse_config(cfg)
            if not info:
                out[idx] = None
                continue
            futs[pool.submit(check_alive, info)] = idx
        for fut in as_completed(futs):
            try:
                out[futs[fut]] = fut.result()
            except Exception:
                out[futs[fut]] = None
    return out


# ---------- вывод ----------
def write_summary(lines):
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    except Exception:
        pass


def write_atomic(path: str, text: str):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


def link_key(cfg: str) -> str:
    return cfg.split("#", 1)[0]


def main():
    try:
        sys.stdout.reconfigure(line_buffering=True)
        resource_raise = __import__("resource")
        soft, hard = resource_raise.getrlimit(resource_raise.RLIMIT_NOFILE)
        resource_raise.setrlimit(resource_raise.RLIMIT_NOFILE, (min(hard, 65536), hard))
    except Exception:
        pass
    atexit.register(kill_all_cores)
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _on_signal)
        except Exception:
            pass

    t_start = time.monotonic()

    # 1. уже имеющиеся конфиги
    existing = []
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
                existing = [l.strip() for l in f if is_valid_config(l)]
            log(f"📖 Загружено из {OUTPUT_FILE}: {len(existing)}")
        except Exception as e:
            print(f"⚠️ Ошибка чтения {OUTPUT_FILE}: {e}", file=sys.stderr)

    # 2. свежие
    downloaded = []
    for url in URLS:
        log(f"📥 Скачиваем: {url}")
        fetched = fetch_url(url)
        log(f"   Найдено {len(fetched)} конфигов")
        downloaded.extend(fetched)
    if not downloaded:
        warn("Ни один источник не отдал конфиги — проверяем только то, что уже в подписке")

    # 3. новые наверх, старые вниз, дедуп (ссылки, отличающиеся только именем, — один конфиг)
    combined, seen, seen_servers = [], set(), set()
    for cfg in downloaded + existing:
        k = link_key(cfg)
        if k in seen:
            continue
        seen.add(k)
        if DEDUP_BY_SERVER:
            info = parse_config(cfg)
            if info:
                key = (info["host"], info["port"])
                if key in seen_servers:
                    continue
                seen_servers.add(key)
        combined.append(cfg)
    if len(combined) > MAX_TO_CHECK:
        warn(f"Конфигов {len(combined)} — проверяем только первые {MAX_TO_CHECK}")
        combined = combined[:MAX_TO_CHECK]
    log(f"\n📊 Всего уникальных конфигов: {len(combined)}")

    if not combined:
        warn("Конфигов нет — файл не трогаем")
        return 0

    # 4. проверка
    if not CHECK_ENABLED:
        final = combined[:MAX_CONFIGS]
        write_atomic(OUTPUT_FILE, "".join(c + "\n" for c in final))
        log(f"✅ Проверка выключена, сохранено {len(final)} в {OUTPUT_FILE}")
        return 0

    core = find_core()
    if not core:
        warn("Ядро Xray не найдено (XRAY_PATH) — подписку не трогаем")
        return 0
    log(f"🧩 Ядро: {core}")
    ok, msg, download_ok = selftest(core)
    if not ok:
        warn(f"Контрольная проверка не пройдена: {msg} — подписку не трогаем")
        return 0
    log("✅ Контроль: ядро работает, интернет у раннера есть")
    global REQUIRE_DOWNLOAD
    if REQUIRE_DOWNLOAD and not download_ok:
        warn("Тестовый файл не скачивается даже напрямую с раннера — шаг загрузки отключён, "
             "проверяется только ответ через туннель")
        REQUIRE_DOWNLOAD = False

    deadline = t_start + TIME_BUDGET_SEC
    t0 = time.perf_counter()

    xray_items, legacy_items, udp_items, dead = [], [], [], []
    for idx, cfg in enumerate(combined):
        scheme = cfg.split("://", 1)[0].lower()
        if scheme in UDP_SCHEMES:
            if KEEP_UDP_PROTOCOLS:
                udp_items.append((idx, cfg))
            else:
                dead.append((cfg, "udp-протокол, проверка невозможна"))
            continue
        try:
            xray_items.append((idx, cfg, to_outbound(cfg)))
        except Invalid as e:
            dead.append((cfg, f"невалидный: {e}"))
        except Unsupported as e:
            if FALLBACK_LEGACY_CHECK and parse_config(cfg):
                legacy_items.append((idx, cfg))
            else:
                dead.append((cfg, f"не проверить: {e}"))
        except Exception as e:
            dead.append((cfg, f"ошибка разбора: {type(e).__name__}"))
    log(f"🗂 К реальной проверке: {len(xray_items)} | по TCP+TLS: {len(legacy_items)} | "
        f"UDP (без проверки): {len(udp_items)} | сразу отброшено: {len(dead)}")

    alive = []   # (latency, order, cfg)
    rejected = 0
    if xray_items:
        results = verify_with_core(xray_items, core, deadline)
        for idx, cfg, _ in xray_items:
            r = results.get(idx, (False, None, "лимит времени"))
            if r[0]:
                alive.append((r[1], idx, cfg))
            else:
                dead.append((cfg, r[2]))
                if r[2].startswith("ядро отвергло"):
                    rejected += 1
    real_alive = len(alive)

    if legacy_items:
        log(f"🔍 Запасная проверка TCP+TLS: {len(legacy_items)} конфигов")
        lat = legacy_check_many([(i, c) for i, c in legacy_items])
        for idx, cfg in legacy_items:
            if lat.get(idx) is None:
                dead.append((cfg, "нет ответа (TCP/TLS)"))
            else:
                # слабая проверка — ставим после тех, что подтверждены реальным трафиком
                alive.append((float(MAX_LATENCY_MS), idx, cfg))

    elapsed = time.perf_counter() - t0
    reasons = Counter(r.split(":")[0] for _, r in dead)
    log(f"\n✅ Рабочих (реальный трафик): {real_alive} | по TCP+TLS: {len(alive) - real_alive} | "
        f"❌ Отброшено: {len(dead)} | ⏱ {elapsed:.0f} с")
    for reason, n in reasons.most_common():
        log(f"   • {reason}: {n}")
    if alive:
        lats = sorted(a[0] for a in alive)
        log(f"⚡ Лучшее время запроса: {int(lats[0])} мс | медиана: {int(lats[len(lats) // 2])} мс")

    if DEAD_FILE:
        try:
            with open(DEAD_FILE, "w", encoding="utf-8") as f:
                for cfg, reason in dead:
                    f.write(f"# {reason}\n{cfg}\n")
        except Exception as e:
            warn(f"Не удалось записать {DEAD_FILE}: {e}")

    summary = ["### Проверка подписки", "",
               f"- Рабочих (реальный трафик): **{real_alive}**",
               f"- По TCP+TLS: {len(alive) - real_alive}",
               f"- UDP без проверки: {len(udp_items)}",
               f"- Отброшено: {len(dead)}", "", "| Причина | Кол-во |", "|---|---|"]
    summary += [f"| {r} | {n} |" for r, n in reasons.most_common()]
    write_summary(summary)

    # 5. защита от «обнуления» подписки
    if time.monotonic() > deadline:
        warn(f"Лимит времени {TIME_BUDGET_SEC} с исчерпан — часть конфигов не проверена")
    if xray_items and rejected / len(xray_items) > MAX_REJECT_SHARE and len(xray_items) >= 20:
        warn(f"Ядро отвергло {rejected} из {len(xray_items)} конфигов — вероятно, изменился формат "
             "настроек Xray. Подписку не трогаем, см. dead.txt")
        return 0
    if len(alive) < MIN_WORKING:
        warn(f"Рабочих всего {len(alive)} (< {MIN_WORKING}) — похоже на сбой проверки. "
             "Подписку не трогаем")
        return 0

    # 6. обрезка по качеству, затем красивая сортировка
    alive.sort(key=lambda x: x[0])
    udp_entries = [(float("inf"), idx, cfg) for idx, cfg in udp_items]
    chosen = (alive + udp_entries)[:MAX_CONFIGS]
    if SORT_BY_LATENCY:
        chosen.sort(key=lambda x: (name_key(x[2]), x[0], x[1]))
    else:
        chosen.sort(key=lambda x: (name_key(x[2]), x[1]))
    final = [c for _, _, c in chosen]
    log(f"✂️ Оставлено (лимит {MAX_CONFIGS}): {len(final)}")
    write_atomic(OUTPUT_FILE, "".join(c + "\n" for c in final))
    log(f"✅ Сохранено в {OUTPUT_FILE}")
    return 0


if __name__ == "__main__":
    try:
        code = main()
    except SystemExit:
        raise
    except Exception as e:  # любая неожиданная ошибка не должна ронять экшен и портить подписку
        warn(f"Непредвиденная ошибка: {type(e).__name__}: {e} — подписку не трогаем")
        import traceback
        traceback.print_exc()
        code = 0
    kill_all_cores()
    sys.exit(code)
