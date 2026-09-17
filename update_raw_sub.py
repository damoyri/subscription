# -*- coding: utf-8 -*-
import requests
import urllib.parse
import json
import subprocess
import os
import time
import base64
import zipfile
import io
from concurrent.futures import ThreadPoolExecutor, as_completed

XRAY_PATH = "xray.exe"
XRAY_ZIP_URL = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-windows-64.zip"
TEST_URL = "https://cp.cloudflare.com/generate_204"  # Быстрый эталонный ресурс
TIMEOUT = 5.0
THREADS = 100  # Количество одновременных проверок Xray

# ВСЕ ТВОИ ИСТОЧНИКИ КОНФИГОВ
CONFIGS_URLS = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
    "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/26.txt"
]

def ensure_xray_installed():
    """Скачивает и распаковывает xray.exe, если его нет в папке."""
    if os.path.exists(XRAY_PATH):
        print("✅ Исполняемый файл xray.exe найден в папке.")
        return True

    print("⏬ xray.exe не найден. Автоматическая загрузка Xray-core с GitHub...")
    try:
        resp = requests.get(XRAY_ZIP_URL, timeout=30)
        if resp.status_code == 200:
            with zipfile.ZipFile(io.BytesIO(resp.content)) as z:
                # Извлекаем только xray.exe
                for file_info in z.infolist():
                    if file_info.filename.lower() == "xray.exe":
                        file_info.filename = "xray.exe"
                        z.extract(file_info, path=".")
                        print("✅ xray.exe успешно скачан и сохранен!")
                        return True
        print("❌ Ошибка при скачивании Xray-core.")
        return False
    except Exception as e:
        print(f"❌ Не удалось загрузить Xray-core: {e}")
        return False

def vless_to_xray_json(vless_url, http_port):
    """Преобразует vless:// ссылку в JSON-конфиг для Xray."""
    try:
        parsed = urllib.parse.urlparse(vless_url)
        if parsed.scheme != "vless":
            return None

        uuid = parsed.username
        host = parsed.hostname
        port = parsed.port
        params = dict(urllib.parse.parse_qsl(parsed.query))

        security = params.get("security", "none")
        net = params.get("type", "tcp")
        sni = params.get("sni") or params.get("serverName", "")
        flow = params.get("flow", "")
        fp = params.get("fp", "chrome")
        pbk = params.get("pbk", "")
        sid = params.get("sid", "")
        path = params.get("path", "")
        service_name = params.get("serviceName", "")

        stream_settings = {"network": net, "security": security}

        if security == "tls":
            stream_settings["tlsSettings"] = {"serverName": sni, "fingerprint": fp}
        elif security == "reality":
            stream_settings["realitySettings"] = {
                "serverName": sni,
                "fingerprint": fp,
                "publicKey": pbk,
                "shortId": sid
            }

        if net == "ws":
            stream_settings["wsSettings"] = {"path": path}
        elif net == "grpc":
            stream_settings["grpcSettings"] = {"serviceName": service_name}

        user_entry = {"id": uuid, "encryption": "none"}
        if flow:
            user_entry["flow"] = flow

        return {
            "log": {"loglevel": "none"},
            "inbounds": [{
                "port": http_port,
                "listen": "127.0.0.1",
                "protocol": "http"
            }],
            "outbounds": [{
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": host,
                        "port": port,
                        "users": [user_entry]
                    }]
                },
                "streamSettings": stream_settings
            }]
        }
    except Exception:
        return None

def test_via_xray(vless_link, worker_id):
    """Поднимает изолированный процесс Xray и проверяет реальный трафик."""
    http_port = 10800 + worker_id
    config_file = f"temp_config_{worker_id}.json"
    
    config_data = vless_to_xray_json(vless_link, http_port)
    if not config_data:
        return None

    with open(config_file, "w", encoding="utf-8") as f:
        json.dump(config_data, f)

    proc = None
    try:
        proc = subprocess.Popen(
            [XRAY_PATH, "run", "-c", config_file],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(0.5)

        proxies = {
            "http": f"http://127.0.0.1:{http_port}",
            "https": f"http://127.0.0.1:{http_port}"
        }
        
        start_time = time.time()
        resp = requests.get(TEST_URL, proxies=proxies, timeout=TIMEOUT)
        latency = int((time.time() - start_time) * 1000)

        if resp.status_code in [200, 204]:
            return vless_link, latency
    except Exception:
        pass
    finally:
        if proc:
            proc.kill()
            proc.wait()
        if os.path.exists(config_file):
            os.remove(config_file)
            
    return None

def main():
    if not ensure_xray_installed():
        return

    print("\n1. Скачивание баз конфигураций из всех источников...")
    all_vless = set()

    for url in CONFIGS_URLS:
        try:
            print(f"Загрузка: {url}")
            resp = requests.get(url, timeout=10)
            try:
                content = base64.b64decode(resp.text).decode('utf-8')
            except Exception:
                content = resp.text
            
            found = [line.strip() for line in content.split('\n') if line.strip().startswith('vless://')]
            all_vless.update(found)
        except Exception as e:
            print(f"Ошибка загрузки {url}: {e}")

    lines = list(all_vless)
    total = len(lines)
    print(f"\n2. Найдено уникальных VLESS конфигов: {total}")
    print(f"Запуск реальной проверки через Xray-core ({THREADS} потоков)...\n")

    working = []
    checked = 0

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {executor.submit(test_via_xray, link, i % THREADS): link for i, link in enumerate(lines)}
        
        for future in as_completed(futures):
            checked += 1
            result = future.result()
            if result:
                link, ping = result
                working.append(link)
                print(f"[{checked}/{total}] ✅ РАБОЧИЙ VLESS! Задержка: {ping}ms")
            else:
                if checked % 20 == 0:
                    print(f"[{checked}/{total}] Проверено... Рабочих: {len(working)}")

    print(f"\n--- Итог ---")
    print(f"Всего проверено: {total}")
    print(f"Работающих через Xray: {len(working)}")

    if working:
        with open("subscription.json", "w", encoding="utf-8") as f:
            f.write("\n".join(working))
        print("Сохранено в файл: subscription.json")

if __name__ == "__main__":
    main()
