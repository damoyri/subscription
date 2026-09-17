#!/usr/bin/env python3
"""
Сбор VPN-конфигов из нескольких источников + проверка живости серверов.
Проверка: DNS -> TCP-connect -> (если TLS/Reality) TLS-handshake с нужным SNI.
В subscription.json попадают только рабочие конфиги, отсортированные по задержке.
"""
import base64
import json
import os
import socket
import ssl
import sys
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

# ================= НАСТРОЙКИ =================
MAX_CONFIGS = 1000            # сколько конфигов оставить в итоге
OUTPUT_FILE = "subscription.json"
DEAD_FILE = "dead.txt"        # куда сложить отбракованные (для отладки), "" — не писать

CHECK_ENABLED = True          # включить проверку живости
CONNECT_TIMEOUT = 4.0         # таймаут TCP-коннекта, сек
TLS_TIMEOUT = 5.0             # таймаут TLS-handshake, сек
MAX_WORKERS = 120             # параллельных проверок
MAX_LATENCY_MS = 2500         # отбрасывать слишком медленные
SORT_BY_LATENCY = True        # быстрые конфиги наверх
DEDUP_BY_SERVER = False       # True = не больше одного конфига на host:port
KEEP_UDP_PROTOCOLS = True     # hysteria2/tuic/wireguard: TCP-проверить нельзя, оставлять как есть

URLS = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",
    "https://etoneya.su/whitelist"
]

UDP_SCHEMES = {"hysteria", "hysteria2", "hy2", "tuic", "wireguard", "warp"}
# =============================================


# ---------- загрузка ----------
def is_valid_config(line: str) -> bool:
    line = line.strip()
    if not line or line.startswith("#"):
        return False
    return "://" in line


def fetch_url(url: str) -> list:
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"}
        )
        with urllib.request.urlopen(req, timeout=20) as response:
            content = response.read().decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"⚠️ Ошибка при скачивании {url}: {e}", file=sys.stderr)
        return []

    # источник может отдавать base64-подписку целиком
    stripped = "".join(content.split())
    if "://" not in content and len(stripped) > 40:
        try:
            content = b64decode(stripped).decode("utf-8", errors="ignore")
        except Exception:
            pass

    return [l.strip() for l in content.splitlines() if is_valid_config(l)]


# ---------- парсинг ----------
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


# ---------- проверка живости ----------
def check_alive(info: dict):
    """Возвращает задержку в мс или None, если сервер не отвечает."""
    host, port = info["host"], info["port"]
    start = time.perf_counter()
    try:
        sock = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
    except Exception:
        return None

    latency = (time.perf_counter() - start) * 1000
    try:
        if info["tls"]:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE          # у Reality/самоподписанных проверять нечего
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2  # слабые версии не нужны
            sock.settimeout(TLS_TIMEOUT)
            with ctx.wrap_socket(sock, server_hostname=info["sni"] or host) as ssock:
                if ssock.version() not in ("TLSv1.2", "TLSv1.3"):
                    return None
                latency = (time.perf_counter() - start) * 1000
        return latency
    except Exception:
        return None
    finally:
        try:
            sock.close()
        except Exception:
            pass


def filter_alive(configs: list):
    alive, dead, skipped = [], [], []
    tasks = {}

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        for cfg in configs:
            info = parse_config(cfg)
            if not info:
                dead.append((cfg, "не распарсен"))
                continue
            if info["scheme"] in UDP_SCHEMES:
                if KEEP_UDP_PROTOCOLS:
                    skipped.append(cfg)
                else:
                    dead.append((cfg, "udp-протокол, проверка невозможна"))
                continue
            tasks[pool.submit(check_alive, info)] = cfg

        done = 0
        total = len(tasks)
        for fut in as_completed(tasks):
            cfg = tasks[fut]
            done += 1
            if done % 100 == 0:
                print(f"   проверено {done}/{total}")
            try:
                latency = fut.result()
            except Exception:
                latency = None
            if latency is None:
                dead.append((cfg, "нет ответа"))
            elif latency > MAX_LATENCY_MS:
                dead.append((cfg, f"медленный {int(latency)} мс"))
            else:
                alive.append((latency, cfg))

    if SORT_BY_LATENCY:
        alive.sort(key=lambda x: x[0])

    result = [cfg for _, cfg in alive] + skipped
    return result, dead, alive


def main():
    # 1. уже имеющиеся конфиги
    existing = []
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
                existing = [l.strip() for l in f if is_valid_config(l)]
            print(f"📖 Загружено из {OUTPUT_FILE}: {len(existing)}")
        except Exception as e:
            print(f"⚠️ Ошибка чтения {OUTPUT_FILE}: {e}", file=sys.stderr)

    # 2. свежие
    downloaded = []
    for url in URLS:
        print(f"📥 Скачиваем: {url}")
        fetched = fetch_url(url)
        print(f"   Найдено {len(fetched)} конфигов")
        downloaded.extend(fetched)

    # 3. новые наверх, старые вниз, дедуп
    combined, seen, seen_servers = [], set(), set()
    for cfg in downloaded + existing:
        if cfg in seen:
            continue
        seen.add(cfg)
        if DEDUP_BY_SERVER:
            info = parse_config(cfg)
            if info:
                key = (info["host"], info["port"])
                if key in seen_servers:
                    continue
                seen_servers.add(key)
        combined.append(cfg)

    print(f"\n📊 Всего уникальных конфигов: {len(combined)}")

    # 4. проверка живости
    if CHECK_ENABLED:
        print(f"🔍 Проверяем доступность ({MAX_WORKERS} потоков)...")
        t0 = time.perf_counter()
        working, dead, alive = filter_alive(combined)
        print(f"✅ Рабочих: {len(working)} | ❌ Мёртвых: {len(dead)} | ⏱ {time.perf_counter()-t0:.1f} с")
        if alive:
            print(f"⚡ Лучший пинг: {int(alive[0][0])} мс | медиана: "
                  f"{int(alive[len(alive)//2][0])} мс")
        if DEAD_FILE:
            with open(DEAD_FILE, "w", encoding="utf-8") as f:
                for cfg, reason in dead:
                    f.write(f"# {reason}\n{cfg}\n")
    else:
        working = combined

    if not working:
        print("⛔ Рабочих конфигов нет — файл не трогаем, чтобы не сломать подписку.")
        sys.exit(1)

    # 5. обрезка и запись
    final = working[:MAX_CONFIGS]
    print(f"✂️ Оставлено (лимит {MAX_CONFIGS}): {len(final)}")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for cfg in final:
            f.write(cfg + "\n")
    print(f"✅ Сохранено в {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
