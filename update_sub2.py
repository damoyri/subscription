#!/usr/bin/env python3
"""
Сбор VPN-конфигов + проверка живости.
Порядок в итоговом файле:
  1) приоритетные источники, прошедшие TLS   (быстрые сверху)
  2) остальные источники, прошедшие TLS
  3) TCP отвечает, но TLS не прошёл          (могут работать, вниз)
  4) UDP-протоколы, проверить нельзя         (в самый конец)
Мёртвые (нет TCP / не резолвится) — удаляются.
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
MAX_CONFIGS = 1000
OUTPUT_FILE = "subscription.json"
DEAD_FILE = "dead.txt"

CHECK_ENABLED = True
CONNECT_TIMEOUT = 4.0
TLS_TIMEOUT = 5.0
MAX_WORKERS = 120
MAX_LATENCY_MS = 2500
SOFT_TLS = True          # True: не прошёл TLS -> вниз списка, а не в мусор
KEEP_UDP_PROTOCOLS = True
DEDUP_BY_SERVER = False

# priority: меньше = выше в списке. Старые конфиги из файла получают 50.
URLS = [
    {"url": "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt", "priority": 0},
    {"url": "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",  "priority": 0},
    {"url": "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/26.txt",                "priority": 10},
]
EXISTING_PRIORITY = 50

UDP_SCHEMES = {"hysteria", "hysteria2", "hy2", "tuic", "wireguard", "warp"}
# =============================================


def is_valid_config(line: str) -> bool:
    line = line.strip()
    return bool(line) and not line.startswith("#") and "://" in line


def b64decode(data: str) -> bytes:
    data = data.strip().replace("-", "+").replace("_", "/")
    data += "=" * (-len(data) % 4)
    return base64.b64decode(data)


def fetch_url(url: str) -> list:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"})
        with urllib.request.urlopen(req, timeout=20) as r:
            content = r.read().decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"⚠️ Ошибка при скачивании {url}: {e}", file=sys.stderr)
        return []

    stripped = "".join(content.split())
    if "://" not in content and len(stripped) > 40:
        try:
            content = b64decode(stripped).decode("utf-8", errors="ignore")
        except Exception:
            pass
    return [l.strip() for l in content.splitlines() if is_valid_config(l)]


# ---------- парсинг ----------
def split_hostport(s: str):
    if s.startswith("["):
        host, _, port = s[1:].partition("]:")
        return host, int(port)
    host, _, port = s.rpartition(":")
    return host, int(port)


def mk(scheme, host, port, tls, sni):
    if not host or not port or not (1 <= int(port) <= 65535):
        return None
    return {"scheme": scheme, "host": host, "port": int(port), "tls": bool(tls), "sni": sni}


def parse_config(line: str):
    try:
        scheme, rest = line.split("://", 1)
        scheme = scheme.lower()

        if scheme == "vmess":
            cfg = json.loads(b64decode(rest.split("#", 1)[0]).decode("utf-8", errors="ignore"))
            host = str(cfg.get("add", "")).strip()
            port = int(str(cfg.get("port", "0")).strip() or 0)
            tls = str(cfg.get("tls", "")).lower() in ("tls", "reality", "true", "1")
            sni = cfg.get("sni") or cfg.get("host") or None
            return mk(scheme, host, port, tls, sni)

        if scheme in ("ss", "ssr") and "@" not in rest.split("#", 1)[0]:
            decoded = b64decode(rest.split("#", 1)[0]).decode("utf-8", errors="ignore")
            if "@" in decoded:
                host, port = split_hostport(decoded.rsplit("@", 1)[1])
                return mk(scheme, host, port, False, None)
            return None

        u = urllib.parse.urlsplit(line)
        q = urllib.parse.parse_qs(u.query)
        security = (q.get("security", [""])[0] or "").lower()
        tls = security in ("tls", "reality", "xtls") or scheme in ("trojan", "hysteria2", "hy2", "tuic")
        sni = q.get("sni", [None])[0] or q.get("peer", [None])[0] or q.get("host", [None])[0]
        return mk(scheme, u.hostname, u.port or 443, tls, sni)
    except Exception:
        return None


def is_ip(host: str) -> bool:
    for fam in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(fam, host)
            return True
        except OSError:
            continue
    return False


# ---------- проверка ----------
def check(info: dict):
    """(status, latency_ms). status: 'tls' | 'tcp' | 'dead'."""
    host, port = info["host"], info["port"]
    t0 = time.perf_counter()
    try:
        sock = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
    except Exception:
        return "dead", None
    tcp_latency = (time.perf_counter() - t0) * 1000

    if not info["tls"]:
        sock.close()
        return "tls", tcp_latency  # для не-TLS протоколов TCP-ответа достаточно

    # SNI: явный из ссылки -> домен хоста -> ничего (IP в server_name ломает часть серверов)
    server_name = info["sni"] or (None if is_ip(host) else host)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        sock.settimeout(TLS_TIMEOUT)
        with ctx.wrap_socket(sock, server_hostname=server_name) as s:
            ok = s.version() in ("TLSv1.2", "TLSv1.3")
        return ("tls" if ok else "tcp"), (time.perf_counter() - t0) * 1000
    except Exception:
        return "tcp", tcp_latency
    finally:
        try:
            sock.close()
        except Exception:
            pass


def main():
    # 1. собираем кандидатов: конфиг -> лучший (минимальный) priority
    order, prio = [], {}

    def add(cfg, p):
        if cfg not in prio:
            prio[cfg] = p
            order.append(cfg)
        else:
            prio[cfg] = min(prio[cfg], p)

    for src in URLS:
        print(f"📥 Скачиваем: {src['url']}")
        fetched = fetch_url(src["url"])
        print(f"   Найдено {len(fetched)}, приоритет {src['priority']}")
        for cfg in fetched:
            add(cfg, src["priority"])

    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
                old = [l.strip() for l in f if is_valid_config(l)]
            print(f"📖 Загружено из {OUTPUT_FILE}: {len(old)}")
            for cfg in old:
                add(cfg, EXISTING_PRIORITY)
        except Exception as e:
            print(f"⚠️ Ошибка чтения {OUTPUT_FILE}: {e}", file=sys.stderr)

    # опциональный дедуп по серверу
    if DEDUP_BY_SERVER:
        seen_srv, filtered = set(), []
        for cfg in sorted(order, key=lambda c: prio[c]):
            info = parse_config(cfg)
            key = (info["host"], info["port"]) if info else None
            if key and key in seen_srv:
                continue
            if key:
                seen_srv.add(key)
            filtered.append(cfg)
        order = filtered

    print(f"\n📊 Всего уникальных конфигов: {len(order)}")

    if not CHECK_ENABLED:
        write(order)
        return

    # 2. проверка
    print(f"🔍 Проверяем ({MAX_WORKERS} потоков)...")
    t0 = time.perf_counter()
    tls_ok, tcp_only, udp, dead = [], [], [], []
    tasks = {}

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        for cfg in order:
            info = parse_config(cfg)
            if not info:
                dead.append((cfg, "не распарсен"))
                continue
            if info["scheme"] in UDP_SCHEMES:
                (udp if KEEP_UDP_PROTOCOLS else dead).append(
                    cfg if KEEP_UDP_PROTOCOLS else (cfg, "udp, проверка невозможна"))
                continue
            tasks[pool.submit(check, info)] = cfg

        done, total = 0, len(tasks)
        for fut in as_completed(tasks):
            cfg = tasks[fut]
            done += 1
            if done % 200 == 0:
                print(f"   проверено {done}/{total}")
            try:
                status, latency = fut.result()
            except Exception:
                status, latency = "dead", None

            if status == "dead":
                dead.append((cfg, "нет ответа"))
            elif latency and latency > MAX_LATENCY_MS:
                dead.append((cfg, f"медленный {int(latency)} мс"))
            elif status == "tls":
                tls_ok.append((prio[cfg], latency, cfg))
            else:  # tcp
                if SOFT_TLS:
                    tcp_only.append((prio[cfg], latency, cfg))
                else:
                    dead.append((cfg, "TLS не прошёл"))

    # 3. сортировка: сначала по приоритету источника, внутри — по пингу
    tls_ok.sort(key=lambda x: (x[0], x[1]))
    tcp_only.sort(key=lambda x: (x[0], x[1]))
    result = [c for _, _, c in tls_ok] + [c for _, _, c in tcp_only] + udp

    print(f"✅ TLS ok: {len(tls_ok)} | ⚠️ только TCP: {len(tcp_only)} | "
          f"❔ UDP: {len(udp)} | ❌ мёртвых: {len(dead)} | ⏱ {time.perf_counter()-t0:.1f} с")
    if tls_ok:
        top = [c for p, l, c in tls_ok if p == tls_ok[0][0]]
        print(f"⚡ Из приоритетных источников наверху: {len(top)}, лучший пинг {int(tls_ok[0][1])} мс")

    if DEAD_FILE:
        with open(DEAD_FILE, "w", encoding="utf-8") as f:
            for cfg, reason in dead:
                f.write(f"# {reason}\n{cfg}\n")

    if not result:
        print("⛔ Рабочих конфигов нет — файл не трогаем.")
        sys.exit(1)
    write(result)


def write(configs):
    final = configs[:MAX_CONFIGS]
    print(f"✂️ Оставлено (лимит {MAX_CONFIGS}): {len(final)}")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for cfg in final:
            f.write(cfg + "\n")
    print(f"✅ Сохранено в {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
