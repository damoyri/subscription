#!/usr/bin/env python3
import json
import os
import re
import sys
import shutil
import tarfile
import subprocess
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import parse_qs, urlparse, unquote
import base64

# ================= НАСТРОЙКИ =================
MAX_CONFIGS = 1000          # Лимит сохраненных конфигов
OUTPUT_FILE = "subscription.json"  # Итоговый файл (содержит vless:// строки)
NUM_THREADS = 15            # Количество параллельных потоков проверки
TIMEOUT_PER_TEST = 3.5      # Таймаут рукопожатия/теста соединения (сек)

# Источники подписок
URLS = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
    "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/26.txt",
]

# Дополнительные разрешенные SNI (если не оканчиваются на .ru)
ALLOWED_EXACT_SNI = {"vk.com", "www.vk.com", "ok.ru", "www.ok.ru"}
ALLOWED_SNI_SUFFIXES = (".vk.com", ".ok.ru", ".yandex.ru", ".ya.ru", ".sberbank.ru", ".tbank.ru")

SINGBOX_BINARY = "./sing-box"
SINGBOX_URL = "https://github.com/SagerNet/sing-box/releases/download/v1.10.7/sing-box-1.10.7-linux-amd64.tar.gz"
# =============================================


def download_singbox() -> bool:
    """Скачивает бинарник sing-box для Linux AMD64 в ранере GitHub Actions."""
    if os.path.exists(SINGBOX_BINARY):
        return True
    
    print("📥 Скачивание ядра sing-box для валидации...")
    archive_path = "sing-box.tar.gz"
    try:
        req = urllib.request.Request(
            SINGBOX_URL, headers={"User-Agent": "Mozilla/5.0"}
        )
        with urllib.request.urlopen(req, timeout=30) as resp, open(archive_path, "wb") as f:
            shutil.copyfileobj(resp, f)

        with tarfile.open(archive_path, "r:gz") as tar:
            for member in tar.getmembers():
                if member.name.endswith("sing-box"):
                    member.name = os.path.basename(member.name)
                    tar.extract(member, path=".")
                    break

        os.chmod(SINGBOX_BINARY, 0o755)
        if os.path.exists(archive_path):
            os.remove(archive_path)
        print("✅ sing-box успешно подготовлен.")
        return True
    except Exception as e:
        print(f"❌ Ошибка скачивания sing-box: {e}", file=sys.stderr)
        return False


def is_allowed_sni(sni: str) -> bool:
    """
    Проверяет, подходит ли SNI под белый список:
    - Все домены с окончанием .ru (.ru, .com.ru и т.д.)
    - Домены из явно заданного списка (vk.com и др.)
    """
    if not sni:
        return False
    sni = sni.lower().strip()
    
    # Разрешаем любые домены на .ru
    if sni.endswith(".ru") or ".ru:" in sni:
        return True
        
    if sni in ALLOWED_EXACT_SNI:
        return True

    return any(sni.endswith(sfx) for sfx in ALLOWED_SNI_SUFFIXES)


def parse_vless(vless_url: str) -> dict | None:
    """Парсит vless:// ссылку в структуру параметров."""
    try:
        vless_url = vless_url.strip()
        if not vless_url.startswith("vless://"):
            return None

        parsed = urlparse(vless_url)
        query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        
        uuid = parsed.username
        host = parsed.hostname
        port = int(parsed.port or 443)
        sni = query.get("sni") or query.get("host") or host
        security = query.get("security", "")

        if not uuid or not host:
            return None

        return {
            "uuid": uuid,
            "host": host,
            "port": port,
            "sni": sni,
            "pbk": query.get("pbk", ""),
            "sid": query.get("sid", ""),
            "fp": query.get("fp", "chrome"),
            "flow": query.get("flow", ""),
            "security": security,
            "raw_url": vless_url
        }
    except Exception:
        return None


def test_reality_handshake(config_data: dict, thread_id: int) -> bool:
    """
    Поднимает временный локальный HTTP-инбоунд в sing-box и совершает
    реальный запрос через VLESS Reality outbound для проверки TLS-хендшейка.
    """
    sni = config_data["sni"]
    if not is_allowed_sni(sni):
        return False

    local_port = 20000 + thread_id
    config_file = f"temp_cfg_{thread_id}.json"

    # Формируем outbound под Reality или стандартный TLS
    outbound = {
        "type": "vless",
        "tag": "proxy",
        "server": config_data["host"],
        "server_port": config_data["port"],
        "uuid": config_data["uuid"],
        "tls": {
            "enabled": True,
            "server_name": config_data["sni"],
            "utls": {
                "enabled": True,
                "fingerprint": config_data["fp"] or "chrome"
            }
        }
    }

    if config_data["flow"]:
        outbound["flow"] = config_data["flow"]

    if config_data["security"] == "reality" or config_data["pbk"]:
        outbound["tls"]["reality"] = {
            "enabled": True,
            "public_key": config_data["pbk"],
            "short_id": config_data["sid"]
        }

    singbox_config = {
        "log": {"level": "panic"},
        "inbounds": [{
            "type": "http",
            "tag": "http-in",
            "listen": "127.0.0.1",
            "listen_port": local_port
        }],
        "outbounds": [outbound]
    }

    with open(config_file, "w", encoding="utf-8") as f:
        json.dump(singbox_config, f)

    proc = None
    try:
        # Запускаем фоновый процесс sing-box
        proc = subprocess.Popen(
            [SINGBOX_BINARY, "run", "-c", config_file],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        # Прокси-настройка для проверки через HTTP-инбоунд
        proxy_handler = urllib.request.ProxyHandler({
            "http": f"http://127.0.0.1:{local_port}",
            "https": f"http://127.0.0.1:{local_port}"
        })
        opener = urllib.request.build_opener(proxy_handler)

        # Выполняем контрольный запрос (204 No Content от Cloudflare)
        req = urllib.request.Request(
            "http://cp.cloudflare.com/generate_204",
            headers={"User-Agent": "Mozilla/5.0"}
        )
        
        with opener.open(req, timeout=TIMEOUT_PER_TEST) as resp:
            if resp.status in (200, 204):
                return True
    except Exception:
        return False
    finally:
        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=0.5)
            except Exception:
                proc.kill()
        if os.path.exists(config_file):
            try:
                os.remove(config_file)
            except Exception:
                pass

    return False


def fetch_url(url: str) -> list[str]:
    """Скачивает подписки (поддерживает обычный текст и Base64)."""
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"}
        )
        with urllib.request.urlopen(req, timeout=15) as response:
            raw_content = response.read().decode("utf-8", errors="ignore").strip()
            
            # Если содержимое в формате Base64
            if not raw_content.startswith("vless://") and len(raw_content) > 50:
                try:
                    decoded = base64.b64decode(raw_content).decode("utf-8", errors="ignore")
                    lines = decoded.splitlines()
                except Exception:
                    lines = raw_content.splitlines()
            else:
                lines = raw_content.splitlines()

            return [line.strip() for line in lines if "vless://" in line]
    except Exception as e:
        print(f"⚠️ Ошибка при скачивании {url}: {e}", file=sys.stderr)
        return []


def main():
    if not download_singbox():
        print("❌ Не удалось запустить скрипт без ядра sing-box.", file=sys.stderr)
        sys.exit(1)

    # 1. Загрузка старых конфигураций
    existing_configs = []
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
                existing_configs = [line.strip() for line in f if "vless://" in line]
            print(f"📖 Загружено имеющихся конфигов: {len(existing_configs)}")
        except Exception as e:
            print(f"⚠️ Ошибка чтения {OUTPUT_FILE}: {e}", file=sys.stderr)

    # 2. Загрузка новых конфигураций
    new_downloaded = []
    for url in URLS:
        print(f"📥 Скачиваем: {url}")
        fetched = fetch_url(url)
        print(f"   Найдено {len(fetched)} VLESS-конфигов")
        new_downloaded.extend(fetched)

    # 3. Объединение и дедупликация (новые конфиги в начале списка)
    combined = []
    seen = set()

    for cfg in new_downloaded + existing_configs:
        if cfg not in seen:
            seen.add(cfg)
            combined.append(cfg)

    print(f"\n🔍 Подготовка к проверке {len(combined)} уникальных конфигураций...")

    # 4. Фильтрация и многопоточная проверка рукопожатий
    valid_configs = []
    parsed_items = []

    for cfg in combined:
        parsed = parse_vless(cfg)
        if parsed and is_allowed_sni(parsed["sni"]):
            parsed_items.append(parsed)

    print(f"🎯 Прошли первичное отсечение по SNI (.ru / whitelist): {len(parsed_items)} шт.")
    print(f"⚡ Запуск проверки TLS-рукопожатий в {NUM_THREADS} потоков...")

    tested_count = 0
    with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
        futures = {
            executor.submit(test_reality_handshake, item, idx % NUM_THREADS): item
            for idx, item in enumerate(parsed_items)
        }

        for future in as_completed(futures):
            item = futures[future]
            tested_count += 1
            is_working = future.result()
            
            if is_working:
                valid_configs.append(item["raw_url"])
                print(f"[{tested_count}/{len(parsed_items)}] ✅ {item['host']} (SNI: {item['sni']})")
            else:
                print(f"[{tested_count}/{len(parsed_items)}] ❌ {item['host']} (SNI: {item['sni']})")

            # Ограничиваем количество валидных рабочих конфигов
            if len(valid_configs) >= MAX_CONFIGS:
                print(f"\n🎉 Достигнут лимит в {MAX_CONFIGS} рабочих конфигураций.")
                break

    # 5. Сохранение результата
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for cfg in valid_configs:
            f.write(cfg + "\n")

    print(f"\n📊 Итоги:")
    print(f" • Всего проверено по SNI: {len(parsed_items)}")
    print(f" • Прошли тест рукопожатия и пинга: {len(valid_configs)}")
    print(f" • Сохранено в файл: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
