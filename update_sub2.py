#!/usr/bin/env python3
"""
Обновление списка ссылок из подписки.
- Загружает текст по URL
- Декодирует Base64, если нужно
- Извлекает все строки-ссылки
- Удаляет дубликаты
- Сохраняет в sub2.json (каждая ссылка с новой строки)
"""

import os
import requests
import base64
import sys

SUB_FILE = "sub2.json"

def load_existing_links() -> set:
    """Загружает существующие ссылки из файла (если есть)."""
    if not os.path.exists(SUB_FILE):
        return set()
    try:
        with open(SUB_FILE, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f if line.strip()]
            return set(lines)
    except Exception:
        return set()

def save_links(links: set) -> None:
    """Сохраняет ссылки в файл, каждая на новой строке."""
    with open(SUB_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted(links)))

def fetch_subscription(url: str) -> set:
    """
    Загружает подписку.
    Возвращает множество уникальных ссылок.
    """
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        content = resp.text.strip()

        # Если ответ выглядит как Base64 (только символы A-Za-z0-9+/=)
        # пробуем декодировать
        if all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in content):
            try:
                decoded = base64.b64decode(content).decode('utf-8')
                content = decoded
            except Exception:
                pass  # оставляем как есть

        # Разбиваем на строки
        lines = [line.strip() for line in content.splitlines() if line.strip()]
        # Фильтруем: оставляем только то, что похоже на ссылку (начинается с протокола)
        # Можно расширить список протоколов
        protocols = ('http://', 'https://', 'ss://', 'vmess://', 'vless://', 'trojan://', 'ssr://', 'hy2://')
        links = set()
        for line in lines:
            # Если строка начинается с одного из протоколов – добавляем
            if any(line.startswith(p) for p in protocols):
                links.add(line)
            # Если строка содержит пробелы – возможно, это список через пробел?
            # Но обычно каждая ссылка на отдельной строке.
        return links
    except requests.RequestException as e:
        print(f"❌ Ошибка загрузки подписки: {e}")
        return set()

def main():
    sub_url = os.getenv("PAID_SUB_URL")
    if not sub_url:
        print("❌ PAID_SUB_URL не задан")
        sys.exit(1)

    print("📥 Загрузка подписки...")
    new_links = fetch_subscription(sub_url)
    if not new_links:
        print("⚠️  Не удалось получить ссылки. Сохраняем существующие.")
        sys.exit(0)

    print(f"📌 Получено уникальных ссылок: {len(new_links)}")

    # Загружаем старые ссылки и объединяем (без удаления нерабочих, т.к. пинг убран)
    existing = load_existing_links()
    combined = existing | new_links
    added = len(combined) - len(existing)
    print(f"➕ Добавлено новых: {added}")

    print(f"💾 Сохранение в {SUB_FILE}...")
    save_links(combined)
    print("✅ Готово!")

if __name__ == "__main__":
    main()
