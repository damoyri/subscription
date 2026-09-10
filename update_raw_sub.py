#!/usr/bin/env python3
import os
import sys
import urllib.request

# ================= НАСТРОЙКИ =================
MAX_CONFIGS = 200  # Максимальное количество конфигов
OUTPUT_FILE = "subscription.json"  # Итоговый файл со ссылками

URLS = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
]
# =============================================


def is_valid_config(line: str) -> bool:
    """Забираем любые строки, содержащие ссылку на протокол (любой ://)."""
    line = line.strip()
    if not line or line.startswith("#"):
        return False
    return "://" in line


def fetch_url(url: str) -> list[str]:
    """Скачивает конфиги по ссылке и возвращает список строк."""
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"}
        )
        with urllib.request.urlopen(req, timeout=15) as response:
            content = response.read().decode("utf-8", errors="ignore")
            lines = []
            for line in content.splitlines():
                line = line.strip()
                if is_valid_config(line):
                    lines.append(line)
            return lines
    except Exception as e:
        print(f"⚠️ Ошибка при скачивании {url}: {e}", file=sys.stderr)
        return []


def main():
    # 1. Читаем уже имеющиеся конфиги из файла
    existing_configs = []
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if is_valid_config(line):
                        existing_configs.append(line)
            print(
                f"📖 Загружено имеющихся конфигов из {OUTPUT_FILE}: {len(existing_configs)}"
            )
        except Exception as e:
            print(
                f"⚠️ Ошибка чтения файла {OUTPUT_FILE}: {e}", file=sys.stderr
            )

    # 2. Скачиваем свежие ссылки
    new_downloaded = []
    for url in URLS:
        print(f"📥 Скачиваем: {url}")
        fetched = fetch_url(url)
        print(f"   Найдено {len(fetched)} конфигов")
        new_downloaded.extend(fetched)

    # 3. Новые ссылки ставим НАВЕРХ, старые смещаем ВНИЗ
    combined = []
    seen = set()

    for cfg in new_downloaded:
        if cfg not in seen:
            seen.add(cfg)
            combined.append(cfg)

    for cfg in existing_configs:
        if cfg not in seen:
            seen.add(cfg)
            combined.append(cfg)

    # 4. Обрезаем ровно до MAX_CONFIGS
    final_configs = combined[:MAX_CONFIGS]

    print(f"\n📊 Всего уникальных конфигов: {len(combined)}")
    print(f"✂️ Оставлено после обрезки (лимит {MAX_CONFIGS}): {len(final_configs)}")

    # 5. Перезаписываем файл
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for cfg in final_configs:
            f.write(cfg + "\n")

    print(f"✅ Успешно сохранено в {OUTPUT_FILE}!")


if __name__ == "__main__":
    main()
