#!/usr/bin/env python3
"""
update_subscription.py – скачивает VPN-ссылки, исключает конфиги с пометкой Россия/Беларусь,
проверяет TCP-пинг оставшихся, сохраняет TOP_K с минимальной задержкой.
Выходной файл: best_ping.txt (одна ссылка на строку).
"""

import asyncio
import base64
import json
import sys
import urllib.parse
from typing import Optional, List, Tuple

# ========================== НАСТРОЙКИ ==========================
SOURCES = [
    "https://bitbucket.org/igareck/vpn-configs-for-russia/raw/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://bitbucket.org/igareck/vpn-configs-for-russia/raw/main/WHITE-SNI-RU-all.txt",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/static/sub_en",
    "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/26.txt",
    "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/1.txt",
    "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/6.txt",
    "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/22.txt",
    "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/23.txt",
    "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/24.txt",
    "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/25.txt",
    "https://github.com/nikita29a/FreeProxyList/raw/refs/heads/main/mirror/1.txt",
]

TOP_K = 67                 # сколько лучших конфигов оставить
TCP_TIMEOUT = 1.5          # таймаут TCP-пинга (сек)
MAX_CONCURRENT = 20        # параллельных проверок

# Ключевые слова для исключения (регистронезависимо)
EXCLUDED_KEYWORDS = [
    "россия", "беларусь", "russia", "belarus",
    "🇷🇺", "🇧🇾", "ru"          # anycast убрали – не исключаем
]

# ======================== ПАРСЕРЫ ПРОТОКОЛОВ ========================
def parse_proxy_url(url: str) -> Optional[Tuple[str, int]]:
    url = url.strip()
    if url.startswith("vless://"):
        return _parse_vless(url)
    if url.startswith("trojan://"):
        return _parse_trojan(url)
    if url.startswith("ss://"):
        return _parse_ss(url)
    if url.startswith("vmess://"):
        return _parse_vmess(url)
    if url.startswith("hysteria2://"):
        return _parse_hysteria2(url)
    return None

def _parse_vless(url: str) -> Optional[Tuple[str, int]]:
    try:
        p = urllib.parse.urlparse(url)
        host = p.hostname
        port = p.port or 443
        if host:
            return (host, port)
    except:
        pass
    return None

def _parse_trojan(url: str) -> Optional[Tuple[str, int]]:
    try:
        p = urllib.parse.urlparse(url)
        host = p.hostname
        port = p.port or 443
        if host:
            return (host, port)
    except:
        pass
    return None

def _parse_ss(url: str) -> Optional[Tuple[str, int]]:
    try:
        content = url[5:]  # убираем "ss://"
        if "@" in content:
            userinfo, hostport = content.split("@", 1)
        else:
            decoded = base64.urlsafe_b64decode(content + "=" * (-len(content) % 4)).decode()
            userinfo, hostport = decoded.split("@", 1)
        host_raw, port_str = hostport.rsplit(":", 1)
        host = host_raw.strip("[]")
        return (host, int(port_str))
    except:
        return None

def _parse_vmess(url: str) -> Optional[Tuple[str, int]]:
    try:
        b64 = url[8:]  # убираем "vmess://"
        b64 += "=" * (-len(b64) % 4)
        cfg = json.loads(base64.urlsafe_b64decode(b64).decode())
        host = cfg.get("add")
        port = int(cfg.get("port", 443))
        if host:
            return (host, port)
    except:
        pass
    return None

def _parse_hysteria2(url: str) -> Optional[Tuple[str, int]]:
    try:
        p = urllib.parse.urlparse(url)
        host = p.hostname
        port = p.port or 443
        if host:
            return (host, port)
    except:
        pass
    return None

# ======================== ИСКЛЮЧЕНИЕ РОССИИ/БЕЛАРУСИ ========================
def is_excluded(link: str) -> bool:
    """Возвращает True, если ссылка содержит маркер России или Беларуси."""
    lower = link.lower()
    if "#" in link:
        before, after = link.split("#", 1)
        decoded_comment = urllib.parse.unquote(after).lower()
        full_text = before.lower() + " " + decoded_comment
    else:
        full_text = lower

    for kw in EXCLUDED_KEYWORDS:
        if kw in full_text:
            return True
    return False

# ======================== TCP-ПИНГ ========================
async def tcp_ping(host: str, port: int, timeout: float = TCP_TIMEOUT) -> Optional[float]:
    start = asyncio.get_event_loop().time()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except:
            pass
        return asyncio.get_event_loop().time() - start
    except:
        return None

# ======================== ЗАГРУЗКА СПИСКОВ ========================
async def fetch_url(url: str, timeout: float = 10.0) -> Optional[str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sL", "--max-time", str(int(timeout)), url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 5)
        if proc.returncode != 0:
            return None
        return stdout.decode(errors="ignore").strip()
    except:
        return None

async def load_all_links() -> List[str]:
    links = []
    for src in SOURCES:
        print(f"⬇️ Загрузка {src}")
        content = await fetch_url(src)
        if not content:
            continue
        for line in content.splitlines():
            line = line.strip()
            if line and line.startswith(("vless://", "trojan://", "ss://", "vmess://", "hysteria2://")):
                links.append(line)
    return list(dict.fromkeys(links))

# ======================== ОСНОВНАЯ ЛОГИКА ========================
async def main():
    print("🔍 Загружаем все списки...")
    raw_links = await load_all_links()
    print(f"✅ Найдено ссылок: {len(raw_links)}")

    # Фильтруем: исключаем Россию/Беларусь (anycast оставляем)
    filtered_links = [link for link in raw_links if not is_excluded(link)]
    print(f"🧹 После исключения РФ/РБ осталось: {len(filtered_links)}")

    if not filtered_links:
        print("❌ После фильтрации не осталось ни одной ссылки!")
        sys.exit(1)

    # Распознаём адреса и порты у оставшихся
    candidates = []
    for link in filtered_links:
        parsed = parse_proxy_url(link)
        if parsed:
            addr, port = parsed
            candidates.append({
                "link": link,
                "addr": addr,
                "port": port,
            })
    print(f"🧩 Распознано {len(candidates)} конфигов, проверяем пинг...")

    # Проверяем пинг параллельно
    sem = asyncio.Semaphore(MAX_CONCURRENT)

    async def check_one(cand):
        async with sem:
            rtt = await tcp_ping(cand["addr"], cand["port"])
            cand["rtt"] = rtt
            if rtt is not None:
                print(f"   ✅ {cand['link'][:50]}... {rtt*1000:.1f} мс")
            else:
                print(f"   ❌ {cand['link'][:50]}... таймаут")
        return cand

    tasks = [check_one(c) for c in candidates]
    results = await asyncio.gather(*tasks)

    # Отбираем живые
    alive = [c for c in results if c["rtt"] is not None]
    if not alive:
        print("❌ Нет ни одного рабочего конфига!")
        sys.exit(1)

    # Сортируем по RTT
    alive.sort(key=lambda x: x["rtt"])
    best = alive[:TOP_K]

    print(f"\n🏆 Лучшие {len(best)} конфигов по пингу (без РФ/РБ):")
    for i, c in enumerate(best, 1):
        print(f"  {i}. {c['link'][:60]}...  {c['rtt']*1000:.1f} мс")

    # Записываем только ссылки в best_ping.txt
    with open("best_ping.txt", "w", encoding="utf-8") as f:
        for c in best:
            f.write(c["link"] + "\n")

    print("✅ Готово! Файл best_ping.txt обновлён.")

if __name__ == "__main__":
    asyncio.run(main())
