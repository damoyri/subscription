#!/usr/bin/env python3
import re
import json
import urllib.parse
import subprocess
import sys

# ---------- ДОПУСТИМЫЕ ЗНАЧЕНИЯ FINGERPRINT ----------
VALID_FINGERPRINTS = ['chrome', 'firefox', 'edge', 'safari', 'ios', 'android', 'qq', 'random']

def clean_fingerprint(fp):
    """Очищает fingerprint: если невалидный, возвращает 'chrome'"""
    if not fp:
        return 'chrome'
    # Приводим к нижнему регистру и убираем всё после '#', ' ', '|' и т.п.
    cleaned = re.sub(r'[#|*].*', '', fp).strip().lower()
    # Если очищенное значение есть в списке допустимых, возвращаем его, иначе 'chrome'
    if cleaned in VALID_FINGERPRINTS:
        return cleaned
    return 'chrome'

# ---------- ШАБЛОН КОНФИГА С БАЛАНСИРОВЩИКОМ ----------
CONFIG_TEMPLATE = {
    "dns": {
        "servers": [
            "https://8.8.8.8/dns-query",
            "https://8.8.4.4/dns-query"
        ],
        "queryStrategy": "UseIP"
    },
    "log": {"loglevel": "warning"},
    "inbounds": [
        {
            "listen": "127.0.0.1",
            "port": 10808,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True, "userLevel": 8},
            "sniffing": {"destOverride": ["http", "tls"], "enabled": True, "routeOnly": False},
            "tag": "socks"
        },
        {
            "listen": "127.0.0.1",
            "port": 10809,
            "protocol": "http",
            "settings": {"userLevel": 8},
            "tag": "http"
        }
    ],
    "routing": {
        "domainStrategy": "IPIfNonMatch",
        "domainMatcher": "hybrid",
        "rules": [
            {"type": "field", "protocol": ["bittorrent"], "outboundTag": "direct"},
            {"type": "field", "network": "tcp,udp", "balancerTag": "WL_Balancer"}
        ],
        "balancers": [
            {
                "tag": "WL_Balancer",
                "selector": [],  # заполнится тегами Игарька
                "strategy": {
                    "type": "leastLoad",
                    "settings": {
                        "maxRTT": "5s",
                        "expected": 1,
                        "baselines": ["500ms", "1000ms"],
                        "tolerance": 0
                    }
                },
                "fallbackTag": "direct"
            }
        ]
    },
    "burstObservatory": {
        "pingConfig": {
            "timeout": "7s",
            "interval": "5m",
            "sampling": 1,
            "destination": "http://www.gstatic.com/generate_204"
        },
        "subjectSelector": []  # тоже заполнится
    },
    "outbounds": [],  # сюда добавятся прокси, потом direct и block
    "remarks": "🇫🇲 АВТООБХОД Igareck"
}

# ---------- ПАРСЕР VLESS-ССЫЛКИ ----------
def parse_vless_url(url):
    if not url.startswith('vless://'):
        return None
    parts = url[8:].split('@')
    if len(parts) != 2:
        return None
    userinfo = parts[0]
    hostport = parts[1].split('?')[0]
    query = parts[1].split('?')[1] if '?' in parts[1] else ''

    user_parts = userinfo.split(':')
    user_id = user_parts[0]

    if ':' in hostport:
        address, port = hostport.split(':')
    else:
        address = hostport
        port = '443'

    params = urllib.parse.parse_qs(query)
    for k, v in params.items():
        params[k] = v[0] if v else ''

    # Обработка fingerprint
    fp_raw = params.get('fp') or params.get('fingerprint', 'firefox')
    fingerprint = clean_fingerprint(fp_raw)

    outbound = {
        "tag": None,
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": address,
                "port": int(port),
                "users": [{
                    "id": user_id,
                    "encryption": "none",
                    "flow": params.get('flow', ''),
                    "level": 8
                }]
            }]
        },
        "streamSettings": {
            "network": "tcp",
            "security": "reality" if ('pbk' in params or 'publicKey' in params) else "tls",
            "tcpSettings": {"header": {"type": "none"}}
        }
    }
    if outbound["streamSettings"]["security"] == "reality":
        outbound["streamSettings"]["realitySettings"] = {
            "allowInsecure": False,
            "fingerprint": fingerprint,
            "publicKey": params.get('pbk', '') or params.get('publicKey', ''),
            "serverName": params.get('sni', address),
            "shortId": params.get('sid', ''),
            "show": False
        }
    else:
        outbound["streamSettings"]["tlsSettings"] = {
            "allowInsecure": False,
            "serverName": params.get('sni', address),
            "fingerprint": fingerprint
        }
    return outbound

# ---------- ОСНОВНАЯ ФУНКЦИЯ ----------
def main():
    # 1. Скачиваем платную подписку connliberty
    print("Скачиваем платную подписку...")
    try:
        result = subprocess.run(
            ['curl', '-sL', 'https://connliberty.com/connection/subs/22a12228-aa7d-4f34-a7cd-b617a8f61c20'],
            capture_output=True, text=True, check=True
        )
        connliberty_data = result.stdout.strip()
        try:
            existing_configs = json.loads(connliberty_data)
            if not isinstance(existing_configs, list):
                print("Ошибка: платная подписка не является массивом, создаём пустой массив", file=sys.stderr)
                existing_configs = []
        except json.JSONDecodeError:
            print("Ошибка: платная подписка не является валидным JSON, создаём пустой массив", file=sys.stderr)
            existing_configs = []
    except Exception as e:
        print(f"Ошибка загрузки платной подписки: {e}", file=sys.stderr)
        existing_configs = []

    print(f"Загружено {len(existing_configs)} конфигов из платной подписки")

    # 2. Скачиваем подписки Игарька и собираем VLESS-ссылки
    igareck_urls = [
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt"
    ]

    igareck_links = []
    for url in igareck_urls:
        try:
            result = subprocess.run(['curl', '-sL', url], capture_output=True, text=True, check=True)
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith('vless://'):
                    igareck_links.append(line)
        except Exception as e:
            print(f"Ошибка загрузки {url}: {e}", file=sys.stderr)

    if not igareck_links:
        print("Нет ссылок Игарька, выходим", file=sys.stderr)
        sys.exit(1)

    print(f"Найдено {len(igareck_links)} ссылок Игарька")

    # 3. Создаём outbounds из ссылок Игарька
    outbounds = []
    igareck_tags = []
    for idx, link in enumerate(igareck_links):
        ob = parse_vless_url(link)
        if ob is None:
            continue
        tag = f"proxy-ig-{idx+1}"
        ob['tag'] = tag
        outbounds.append(ob)
        igareck_tags.append(tag)

    # Добавляем direct и block
    outbounds.append({
        "protocol": "freedom",
        "settings": {"domainStrategy": "UseIP"},
        "tag": "direct"
    })
    outbounds.append({
        "protocol": "blackhole",
        "settings": {"response": {"type": "http"}},
        "tag": "block"
    })

    # 4. Формируем новый конфиг с балансировщиком
    new_config = CONFIG_TEMPLATE.copy()
    new_config['outbounds'] = outbounds
    new_config['routing']['balancers'][0]['selector'] = igareck_tags
    new_config['burstObservatory']['subjectSelector'] = igareck_tags

    # 5. Вставляем новый конфиг в начало массива
    final_configs = [new_config] + existing_configs

    # 6. Сохраняем в subscription.json
    with open('subscription.json', 'w', encoding='utf-8') as f:
        json.dump(final_configs, f, indent=2, ensure_ascii=False)

    print(f"✅ Добавлен конфиг с балансировщиком (первый в списке) из {len(igareck_tags)} серверов Игарька")
    print(f"Всего конфигов в файле: {len(final_configs)}")

if __name__ == '__main__':
    main()
