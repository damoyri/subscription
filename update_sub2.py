#!/usr/bin/env python3
"""
Обновление списка прокси из платной подписки:
- Проверяет старые серверы по TCP-пингу (доступность порта)
- Удаляет неработающие
- Загружает новые из подписки (поддерживает JSON и Base64)
- Исключает дубликаты (по server:port:type)
- Сохраняет результат в sub2.json
"""

import os
import json
import socket
import requests
import base64
import sys
from typing import List, Dict, Any, Optional

# Конфигурация
TIMEOUT = 3  # таймаут TCP-проверки (секунды)
SUB_FILE = "sub2.json"


def load_existing_servers() -> List[Dict[str, Any]]:
    """Загружает список серверов из файла sub2.json."""
    if not os.path.exists(SUB_FILE):
        return []
    try:
        with open(SUB_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
            else:
                print("⚠️  sub2.json содержит не список, используем пустой.")
                return []
    except json.JSONDecodeError:
        print("⚠️  Ошибка парсинга sub2.json, используем пустой список.")
        return []


def save_servers(servers: List[Dict[str, Any]]) -> None:
    """Сохраняет список серверов в файл sub2.json."""
    with open(SUB_FILE, 'w', encoding='utf-8') as f:
        json.dump(servers, f, indent=2, ensure_ascii=False)


def get_server_key(server: Dict[str, Any]) -> str:
    """
    Генерирует уникальный ключ для сервера на основе его основных параметров.
    Пытается найти поля: server/host/address и port.
    Если порт не указан, использует 0.
    """
    # Ищем поле с адресом
    address = (
        server.get("server") or
        server.get("host") or
        server.get("address") or
        server.get("hostname") or
        ""
    )
    # Ищем порт
    port = (
        server.get("port") or
        server.get("port_number") or
        0
    )
    # Тип (если есть)
    proxy_type = server.get("type") or server.get("protocol") or "unknown"
    return f"{address}:{port}:{proxy_type}".lower()


def is_server_reachable(server: Dict[str, Any]) -> bool:
    """
    Проверяет доступность сервера по TCP-соединению к указанному порту.
    Возвращает True, если соединение установлено в течение TIMEOUT.
    """
    # Ищем адрес и порт
    host = (
        server.get("server") or
        server.get("host") or
        server.get("address") or
        server.get("hostname")
    )
    port = (
        server.get("port") or
        server.get("port_number")
    )

    if not host or not port:
        # Если нет адреса или порта, считаем недоступным
        return False

    try:
        with socket.create_connection((host, int(port)), timeout=TIMEOUT):
            return True
    except Exception:
        return False


def fetch_subscription(url: str) -> Optional[List[Dict[str, Any]]]:
    """
    Загружает подписку по URL.
    Поддерживает JSON и Base64-закодированный JSON.
    Возвращает список серверов или None при ошибке.
    """
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        content = resp.text.strip()

        # Попытка парсинга как JSON
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            # Если не JSON, пробуем декодировать Base64
            try:
                decoded = base64.b64decode(content).decode('utf-8')
                data = json.loads(decoded)
            except Exception:
                print("❌ Не удалось распарсить ответ подписки (ни JSON, ни Base64).")
                return None

        # Ожидаем список серверов
        if isinstance(data, list):
            return data
        elif isinstance(data, dict):
            # Возможно, серверы находятся под ключом "servers" или "proxies"
            for key in ("servers", "proxies", "data"):
                if key in data and isinstance(data[key], list):
                    return data[key]
            # Или одиночный объект – помещаем в список
            return [data]
        else:
            print("❌ Неизвестный формат подписки (не список и не объект).")
            return None

    except requests.RequestException as e:
        print(f"❌ Ошибка загрузки подписки: {e}")
        return None


def main():
    # Получаем URL подписки из переменной окружения
    sub_url = os.getenv("PAID_SUB_URL")
    if not sub_url:
        print("❌ Переменная PAID_SUB_URL не установлена.")
        sys.exit(1)

    print("🔍 Загрузка существующих серверов...")
    existing = load_existing_servers()
    print(f"📌 Найдено серверов: {len(existing)}")

    # Проверка доступности старых
    print("🏓 Проверка доступности старых серверов...")
    alive = []
    removed = 0
    for server in existing:
        if is_server_reachable(server):
            alive.append(server)
        else:
            removed += 1
    print(f"✅ Рабочих: {len(alive)}, удалено: {removed}")

    # Загрузка новых серверов из подписки
    print("📡 Загрузка подписки...")
    new_servers = fetch_subscription(sub_url)
    if new_servers is None:
        print("⚠️  Подписка не загружена, сохраняем только проверенные старые.")
        save_servers(alive)
        sys.exit(0)

    print(f"📥 Получено серверов из подписки: {len(new_servers)}")

    # Собираем ключи существующих рабочих серверов
    existing_keys = {get_server_key(s) for s in alive}
    added = 0
    for server in new_servers:
        key = get_server_key(server)
        if key not in existing_keys:
            # Добавляем новый сервер (с небольшим приоритетом – можно добавить поле)
            alive.append(server)
            existing_keys.add(key)
            added += 1

    print(f"➕ Добавлено новых серверов: {added}")
    print(f"💾 Сохранение в {SUB_FILE}...")
    save_servers(alive)
    print("✅ Готово!")


if __name__ == "__main__":
    main()
