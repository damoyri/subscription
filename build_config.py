import asyncio
import json
import time
from typing import Dict, Any, List, Optional

# --- TCP-ПИНГ ОДНОГО СЕРВЕРА ---
async def check_via_tcp_ping(outbound: Dict[str, Any], timeout: float = 3.0) -> Optional[Dict[str, Any]]:
    server = outbound.get("server")
    port = outbound.get("server_port") or outbound.get("port")
    tag = outbound.get("tag", "no-tag")

    # Пропускаем локальные/специальные теги без реального IP/порта
    if not server or not port:
        return None

    try:
        port = int(port)
        start_time = time.perf_counter()

        # Создаем TCP-подключение (Handshake)
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server, port), 
            timeout=timeout
        )

        # Вычисляем время отклика в миллисекундах
        rtt_ms = (time.perf_counter() - start_time) * 1000

        # Закрываем сокет
        writer.close()
        await writer.wait_closed()

        # Возвращаем копию аутбаунда с замеренным пингом
        result_outbound = outbound.copy()
        result_outbound["ping_ms"] = round(rtt_ms, 1)
        
        print(f"✅ [{tag}] {server}:{port} -> {rtt_ms:.1f} ms")
        return result_outbound

    except (asyncio.TimeoutError, OSError, ValueError):
        print(f"❌ [{tag}] {server}:{port} -> Offline / Timeout")
        return None


# --- ПАРАЛЛЕЛЬНАЯ ПРОВЕРКА ВСЕХ СЕРВЕРОВ ---
async def check_all_outbounds(outbounds: List[Dict[str, Any]], timeout: float = 3.0) -> List[Dict[str, Any]]:
    print(f"🚀 Запуск параллельного TCP-пинга для {len(outbounds)} узлов...\n")
    
    # Запускаем задачи для всех серверов одновременно
    tasks = [check_via_tcp_ping(outbound, timeout) for outbound in outbounds]
    results = await asyncio.gather(*tasks)

    # Отфильтровываем отвалившиеся (None)
    working_outbounds = [res for res in results if res is not None]
    
    # Сортируем рабочие узлы по возрастанию пинга (самые быстрые сверху)
    working_outbounds.sort(key=lambda x: x["ping_ms"])
    
    return working_outbounds


# --- ПРИМЕР ЗАПУСКА ---
async def main():
    # Твой массив outbounds (например, распарсенный из config.json)
    outbounds_list = [
        {"tag": "Cloudflare-DNS", "server": "1.1.1.1", "server_port": 443},
        {"tag": "Google-DNS", "server": "8.8.8.8", "server_port": 53},
        {"tag": "Dead-Server", "server": "192.0.2.1", "server_port": 8443},
        {"tag": "Yandex-DNS", "server": "77.88.8.8", "server_port": 53},
    ]

    start = time.perf_counter()
    valid_nodes = await check_all_outbounds(outbounds_list, timeout=2.5)
    total_time = time.perf_counter() - start

    print(f"\n📊 Итог: Найдено {len(valid_nodes)} рабочих из {len(outbounds_list)} за {total_time:.2f} сек.")


if __name__ == "__main__":
    asyncio.run(main())
