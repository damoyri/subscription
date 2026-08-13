#!/usr/bin/env python3
import re
import json
import urllib.parse
import subprocess
import sys

# ---------- ДОПУСТИМЫЕ FINGERPRINT ----------
VALID_FINGERPRINTS = ['chrome', 'firefox', 'edge', 'safari', 'ios', 'android', 'qq', 'random']

def clean_fingerprint(fp):
    if not fp:
        return 'chrome'
    cleaned = re.sub(r'[#|*].*', '', fp).strip().lower()
    if cleaned in VALID_FINGERPRINTS:
        return cleaned
    return 'chrome'

# ---------- СТОП-СЛОВА ДЛЯ ИСКЛЮЧЕНИЯ РОССИИ/БЕЛАРУСИ ----------
EXCLUDE_PATTERN = re.compile(r'(Россия|anycast|Беларусь|🇷🇺|🇧🇾|Russia|Belarus)', re.IGNORECASE)

def is_russia_or_belarus(remarks):
    """Проверяет, содержит ли remarks признаки России или Беларуси"""
    if not remarks:
        return False
    return bool(EXCLUDE_PATTERN.search(remarks))

# ---------- ШАБЛОН КОНФИГА ----------
def create_config_template(remarks_text):
    return {
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
                    "selector": [],
                    "strategy": {
                        "type": "leastLoad",
                        "settings": {
                            "maxRTT": "3s",
                            "expected": 1,
                            "baselines": ["300ms", "600ms"],
                            "tolerance": 0
                        }
                    },
                    "fallbackTag": "direct"
                }
            ]
        },
        "burstObservatory": {
            "pingConfig": {
                "timeout": "3s",
                "interval": "2m",
                "sampling": 1,
                "destination": "http://www.gstatic.com/generate_204"
            },
            "subjectSelector": []
        },
        "outbounds": [],
        "remarks": remarks_text
    }

# ---------- ПАРСЕР VLESS-ССЫЛКИ (возвращает outbound и remarks) ----------
def parse_vless_url(url):
    # Извлекаем remarks (часть после #)
    remarks = ''
    if '#' in url:
        url, remarks = url.split('#', 1)
        remarks = remarks.strip()

    if not url.startswith('vless://'):
        return None, remarks

    parts = url[8:].split('@')
    if len(parts) != 2:
        return None, remarks
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
    return outbound, remarks

# ---------- ОСНОВНАЯ ФУНКЦИЯ ----------
def main():
    # 1. Скачиваем платную подписку
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
                existing_configs = []
        except:
            existing_configs = []
    except:
        existing_configs = []

    print(f"Загружено {len(existing_configs)} конфигов из платной подписки")

    # 2. Скачиваем подписки Игарька
    igareck_urls = [
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt"
    ]

    all_links = []
    for url in igareck_urls:
        try:
            result = subprocess.run(['curl', '-sL', url], capture_output=True, text=True, check=True)
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith('vless://'):
                    all_links.append(line)
        except:
            pass

    if not all_links:
        print("Нет ссылок Игарька, выходим", file=sys.stderr)
        sys.exit(1)

    print(f"Найдено {len(all_links)} ссылок Игарька")

    # 3. Парсим все ссылки, сохраняем outbound и remarks
    parsed = []
    for link in all_links:
        ob, rem = parse_vless_url(link)
        if ob is not None:
            parsed.append((ob, rem))

    # 4. Формируем outbounds и теги для первого конфига (все)
    all_outbounds = []
    all_tags = []
    filtered_outbounds = []   # для второго конфига (без RU/BY)
    filtered_tags = []

    for idx, (ob, rem) in enumerate(parsed):
        tag = f"proxy-ig-{idx+1}"
        ob['tag'] = tag
        all_outbounds.append(ob)
        all_tags.append(tag)

        # Проверяем, нужно ли исключить
        if not is_russia_or_belarus(rem):
            filtered_outbounds.append(ob.copy())  # копируем, чтобы не изменять
            filtered_tags.append(tag)

    # Добавляем direct и block в оба конфига
    direct_block = [
        {"protocol": "freedom", "settings": {"domainStrategy": "UseIP"}, "tag": "direct"},
        {"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"}
    ]

    # 5. Создаём два конфига
    config_all = create_config_template("🇫🇲 АБС Igareck [LTE]")
    config_all['outbounds'] = all_outbounds + direct_block
    config_all['routing']['balancers'][0]['selector'] = all_tags
    config_all['burstObservatory']['subjectSelector'] = all_tags

    config_filtered = create_config_template("🇫🇲 АБС Igareck [LTE] NoRU/BY")
    config_filtered['outbounds'] = filtered_outbounds + direct_block
    config_filtered['routing']['balancers'][0]['selector'] = filtered_tags
    config_filtered['burstObservatory']['subjectSelector'] = filtered_tags

    # 6. Собираем финальный массив: сначала оба новых, потом старые
    final_configs = [config_all, config_filtered] + existing_configs

    # 7. Сохраняем
    with open('subscription.json', 'w', encoding='utf-8') as f:
        json.dump(final_configs, f, indent=2, ensure_ascii=False)

    print(f"✅ Добавлено 2 конфига: {len(all_tags)} и {len(filtered_tags)} серверов")
    print(f"Всего конфигов в файле: {len(final_configs)}")

if __name__ == '__main__':
    main()
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
