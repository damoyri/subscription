#!/usr/bin/env python3
import os
import sys
import urllib.request

# ================= НАСТРОЙКИ =================
MAX_CONFIGS = 200  # Максимальное количество конфигов (регулируй здесь)
OUTPUT_FILE = "subscription.json"  # Итоговый файл со ссылками

URLS = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
]

VALID_SCHEMES = ("vless://", "vmess://", "trojan://", "ss://")
# =============================================


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
                if line and any(line.startswith(s) for s in VALID_SCHEMES):
                    lines.append(line)
            return lines
    except Exception as e:
        print(f"⚠️ Ошибка при скачивании {url}: {e}", file=sys.stderr)
        return []


def main():
    # 1. Читаем уже существующие конфиги из файла (если файл есть)
    existing_configs = []
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and any(line.startswith(s) for s in VALID_SCHEMES):
                        existing_configs.append(line)
            print(
                f"📖 Загружено имеющихся конфигов из {OUTPUT_FILE}: {len(existing_configs)}"
            )
        except Exception as e:
            print(
                f"⚠️ Ошибка чтения файла {OUTPUT_FILE}: {e}", file=sys.stderr
            )

    # 2. Загружаем свежие конфиги из внешних источников
    new_downloaded = []
    for url in URLS:
        print(f"📥 Скачиваем: {url}")
        fetched = fetch_url(url)
        print(f"   Найдено {len(fetched)} конфигов")
        new_downloaded.extend(fetched)

    # 3. Объединяем: Новые скачанные ставим НАВЕРХ, старые смещаем ВНИЗ
    combined = []
    seen = set()

    # Сначала добавляем свежие
    for cfg in new_downloaded:
        if cfg not in seen:
            seen.add(cfg)
            combined.append(cfg)

        # Затем добавляем старые
    for cfg in existing_configs:
        if cfg not in seen:
            seen.add(cfg)
            combined.append(cfg)

    # 4. Обрезаем список до лимита MAX_CONFIGS (все что дальше 200 — удаляется)
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
