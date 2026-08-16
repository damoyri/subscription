#!/usr/bin/env python3
"""
update_subscription.py – скачивает VPN-ссылки, исключает конфиги с пометкой Россия/Беларусь,
проверяет реальную работоспособность через sing‑box (HTTP-запрос через прокси),
сохраняет TOP_K с минимальной задержкой.
Выходной файл: best_ping.txt (одна ссылка на строку).
Автоматически коммитит и пушит изменения в репозиторий.
"""

import asyncio
import base64
import json
import sys
import urllib.parse
from typing import Optional, List, Tuple
import subprocess
import datetime
import tempfile
import os
import time

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

TOP_K = 42                 # сколько лучших конфигов оставить
TCP_TIMEOUT = 7.0          # таймаут для реальной проверки (сек)
MAX_CONCURRENT = 50        # параллельных проверок

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
        content = url[5:]
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
        b64 = url[8:]
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

# ======================== ГЕНЕРАТОР КОНФИГА SING-BOX ========================
def generate_singbox_config(link: str) -> Optional[str]:
    """Создаёт временный конфиг sing-box для прокси-ссылки, возвращает путь к файлу"""
    parsed = parse_proxy_url(link)
    if not parsed:
        return None
    host, port = parsed

    # Базовая структура конфига
    config = {
        "log": {"level": "error"},
        "inbounds": [
            {
                "type": "socks",
                "listen": "127.0.0.1",
                "listen_port": 1080,
                "tag": "socks-in"
            }
        ],
        "outbounds": [
            {
                "type": "direct",
                "tag": "direct"
            }
        ]
    }

    # Парсим параметры в зависимости от протокола
    if link.startswith("vless://"):
        p = urllib.parse.urlparse(link)
        uuid = p.username or ""
        server = p.hostname
        server_port = p.port or 443
        params = dict(urllib.parse.parse_qsl(p.query))
        outbound = {
            "type": "vless",
            "server": server,
            "server_port": server_port,
            "uuid": uuid,
            "flow": params.get("flow", ""),
            "tls": {
                "enabled": params.get("security", "") == "tls" or params.get("tls", "") == "tls",
                "server_name": params.get("sni", server),
                "utls": {"enabled": True, "fingerprint": "chrome"}
            },
            "transport": {
                "type": params.get("type", "tcp"),
                "path": params.get("path", ""),
                "host": params.get("host", "")
            }
        }
        config["outbounds"].append(outbound)

    elif link.startswith("trojan://"):
        p = urllib.parse.urlparse(link)
        password = p.username or ""
        server = p.hostname
        server_port = p.port or 443
        params = dict(urllib.parse.parse_qsl(p.query))
        outbound = {
            "type": "trojan",
            "server": server,
            "server_port": server_port,
            "password": password,
            "tls": {
                "enabled": True,
                "server_name": params.get("sni", server),
                "utls": {"enabled": True, "fingerprint": "chrome"}
            },
            "transport": {
                "type": params.get("type", "tcp"),
                "path": params.get("path", ""),
                "host": params.get("host", "")
            }
        }
        config["outbounds"].append(outbound)

    else:
        # Для vmess, ss, hysteria2 — не реализовано, пропускаем
        return None

    # Сохраняем во временный файл
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config, f)
            return f.name
    except Exception:
        return None

# ======================== РЕАЛЬНАЯ ПРОВЕРКА ЧЕРЕЗ SING-BOX ========================
async def real_check(link: str, timeout: float = TCP_TIMEOUT) -> Optional[float]:
    """Проверяет конфиг через sing-box и реальный HTTP-запрос к google.com"""
    config_path = generate_singbox_config(link)
    if not config_path:
        return None

    # Запускаем sing-box
    proc = await asyncio.create_subprocess_exec(
        "sing-box", "run", "-c", config_path,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL
    )
    # Даём время подняться (0.5 сек достаточно)
    await asyncio.sleep(0.5)

    # Пытаемся сделать curl через прокси
    start = asyncio.get_event_loop().time()
    success = False
    try:
        curl_proc = await asyncio.create_subprocess_exec(
            "curl", "-x", "socks5://127.0.0.1:1080",
            "https://google.com", "-m", str(int(timeout)),
            "--connect-timeout", str(int(timeout)),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL
        )
        await asyncio.wait_for(curl_proc.wait(), timeout=timeout)
        if curl_proc.returncode == 0:
            success = True
    except asyncio.TimeoutError:
        pass
    finally:
        # Завершаем sing-box
        proc.terminate()
        await proc.wait()
        # Удаляем временный файл
        try:
            os.unlink(config_path)
        except:
            pass

    if success:
        return asyncio.get_event_loop().time() - start
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

    filtered_links = [link for link in raw_links if not is_excluded(link)]
    print(f"🧹 После исключения РФ/РБ осталось: {len(filtered_links)}")

    if not filtered_links:
        print("❌ После фильтрации не осталось ни одной ссылки!")
        sys.exit(1)

    # Собираем кандидатов (только те, что поддерживаются sing-box: vless, trojan)
    candidates = []
    for link in filtered_links:
        if link.startswith(("vless://", "trojan://")):
            candidates.append({"link": link})
    print(f"🧩 Распознано {len(candidates)} конфигов (vless/trojan), проверяем через sing-box...")

    if not candidates:
        print("❌ Нет конфигов для проверки!")
        sys.exit(1)

    sem = asyncio.Semaphore(MAX_CONCURRENT)

    async def check_one(cand):
        async with sem:
            rtt = await real_check(cand["link"])
            cand["rtt"] = rtt
            if rtt is not None:
                print(f"   ✅ {cand['link'][:50]}... {rtt*1000:.1f} мс")
            else:
                print(f"   ❌ {cand['link'][:50]}... не работает")
        return cand

    tasks = [check_one(c) for c in candidates]
    results = await asyncio.gather(*tasks)

    alive = [c for c in results if c["rtt"] is not None]
    if not alive:
        print("❌ Нет ни одного рабочего конфига!")
        sys.exit(1)

    alive.sort(key=lambda x: x["rtt"])
    best = alive[:TOP_K]

    print(f"\n🏆 Лучшие {len(best)} конфигов по реальной задержке (без РФ/РБ):")
    for i, c in enumerate(best, 1):
        print(f"  {i}. {c['link'][:60]}...  {c['rtt']*1000:.1f} мс")

    with open("best_ping.txt", "w", encoding="utf-8") as f:
        for c in best:
            f.write(c["link"] + "\n")

    print("✅ Готово! Файл best_ping.txt обновлён.")

    # ==================== АВТОМАТИЧЕСКИЙ PUSH НА GITHUB ====================
    try:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        # Сначала подтягиваем удалённые изменения (чтобы избежать конфликтов)
        subprocess.run(["git", "pull", "origin", "main", "--no-rebase"], check=True, cwd=".")
        subprocess.run(["git", "add", "best_ping.txt"], check=True, cwd=".")
        subprocess.run(["git", "commit", "-m", f"Auto-update {timestamp}"], check=True, cwd=".")
        subprocess.run(["git", "push"], check=True, cwd=".")
        print("✅ Изменения отправлены на GitHub")
    except subprocess.CalledProcessError as e:
        print(f"⚠️ Ошибка git: {e}")

if __name__ == "__main__":
    asyncio.run(main())
