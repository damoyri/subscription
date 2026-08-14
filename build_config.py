import asyncio
import json
import time
from typing import Dict, Any, List, Optional

# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ЛОГИРОВАНИЯ ---
def log_info(msg: str):
    print(f"[INFO] {msg}")

def log_err(msg: str):
    print(f"[ERROR] {msg}")

def log_ok(msg: str):
    print(f"[OK] {msg}")


# --- ОСНОВНАЯ ФУНКЦИЯ TCP-ПИНГА ---
async def check_via_tcp_ping(outbound: Dict[str, Any], timeout: float = 3.0) -> Optional[float]:
    """Выполняет TCP-пинг непосредственно до сервера outbound'а (server:port).
    
    Возвращает время отклика (RTT) в секундах или None, если узел недоступен.
    """
    # Достаём адрес сервера и порт из структуры outbound
    server = outbound.get("server")
    port = outbound.get("server_port") or outbound.get("port")

    # Если у outbound'а нет сервера/порта (например, direct, block и т.д.)
    if not server or not port:
        return None

    try:
        port = int(port)
        start_time = time.perf_counter()

        # Попытка установить TCP-соединение с узлом
        connector = asyncio.open_connection(server, port)
        reader, writer = await asyncio.wait_for(connector, timeout=timeout)

        # Вычисляем задержку в секундах
        rtt = time.perf_counter() - start_time

        # Аккуратно закрываем созданное соединение
        writer.close()
        await writer.wait_closed()

        return rtt

    except (asyncio.TimeoutError, OSError, ValueError):
        # Если сервер не ответил, сбросил соединение или вышло время таймаута
        return None


# --- ПРОВЕРКА СПИСКА OUTBOUND'ОВ ---
async def check_outbounds(outbounds: List[Dict[str, Any]], timeout: float = 3.0) -> List[Dict[str, Any]]:
    """Проверяет массив outbound'ов через TCP-пинг и выводит результаты."""
    results = []

    log_info(f"Начинаем TCP-проверку {len(outbounds)} узлов...")

    for index, outbound in enumerate(outbounds, 1):
        tag = outbound.get("tag", f"outbound-{index}")
        server = outbound.get("server", "N/A")
        port = outbound.get("server_port") or outbound.get("port", "N/A")

        # Если это служебный outbound без сервера
        if server == "N/A":
            continue

        rtt = await check_via_tcp_ping(outbound, timeout=timeout)

        if rtt is not None:
            rtt_ms = rtt * 1000
            log_ok(f"[{tag}] {server}:{port} — Живой! Пинг: {rtt_ms:.1f} ms")
            outbound["rtt_ms"] = round(rtt_ms, 1)
            results.append(outbound)
        else:
            log_err(f"[{tag}] {server}:{port} — Не отвечает (Timeout/Offline)")

    return results


# --- ТОЧКА ВХОДА И ТЕСТОВЫЙ ПРИМЕР ---
async def main():
    # Пример структуры outbounds (замени на свою загрузку JSON или списка)
    sample_outbounds = [
        {
            "tag": "US-Server",
            "type": "vless",
            "server": "1.1.1.1",
            "server_port": 443
        },
        {
            "tag": "Google-DNS",
            "type": "shadowsocks",
            "server": "8.8.8.8",
            "server_port": 53
        },
        {
            "tag": "Bad-Server",
            "type": "trojan",
            "server": "192.0.2.1",
            "server_port": 8443
        }
    ]

    # Запускаем проверку
    working_outbounds = await check_outbounds(sample_outbounds, timeout=2.5)

    print("\n--- Результат ---")
    log_info(f"Успешно проверено и доступно узлов: {len(working_outbounds)}")


if __name__ == "__main__":
    asyncio.run(main())
