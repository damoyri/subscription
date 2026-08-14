#!/usr/bin/env python3
import re
import json
import urllib.parse
import subprocess
import sys

VALID_FINGERPRINTS = ['chrome', 'firefox', 'edge', 'safari', 'ios', 'android', 'qq', 'random']

def clean_fingerprint(fp):
    if not fp:
        return 'chrome'
    cleaned = re.sub(r'[#|*].*', '', fp).strip().lower()
    return cleaned if cleaned in VALID_FINGERPRINTS else 'chrome'

EXCLUDE_PATTERN = re.compile(r'(Россия|anycast|Беларусь|🇷🇺|🇧🇾|Russia|Belarus)', re.IGNORECASE)

def is_russia_or_belarus(remarks):
    if not remarks:
        return False
    return bool(EXCLUDE_PATTERN.search(remarks))

def create_config_template(remarks_text):
    return {
        "dns": {
            "servers": ["https://8.8.8.8/dns-query", "https://8.8.4.4/dns-query"],
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
                            "maxRTT": "5s",          # вернул 5s
                            "expected": 1,
                            "baselines": ["500ms", "1000ms"],  # вернул как в примере
                            "tolerance": 0
                        }
                    },
                    "fallbackTag": "direct"
                }
            ]
        },
        "burstObservatory": {
            "pingConfig": {
                "timeout": "5s",          # 5 секунд на проверку (не 3, не 25)
                "interval": "5m",         # каждые 5 минут (как в примере)
                "sampling": 1,
                "destination": "http://www.gstatic.com/generate_204"
            },
            "subjectSelector": []
        },
        "outbounds": [],
        "remarks": remarks_text
    }

def parse_vless_url(url):
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
        address, port_str = hostport.split(':', 1)
    else:
        address = hostport
        port_str = '443'

    # Очищаем порт от всего, кроме цифр
    port_clean = re.sub(r'\D', '', port_str)
    if port_clean == '':
        port = 443
    else:
        port = int(port_clean)

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
                "port": port,
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

def main():
    print("Скачиваем платную подписку...")
    try:
        result = subprocess.run(
            ['curl', '-sL', 'https://connliberty.com/connection/subs/22a12228-aa7d-4f34-a7cd-b617a8f61c20'],
            capture_output=True, text=True, check=True
        )
        existing_configs = json.loads(result.stdout.strip())
        if not isinstance(existing_configs, list):
            existing_configs = []
    except:
        existing_configs = []

    print(f"Загружено {len(existing_configs)} конфигов из платной подписки")

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
        print("Нет ссылок Игарька", file=sys.stderr)
        sys.exit(1)

    print(f"Найдено {len(all_links)} ссылок Игарька")

    parsed = []
    for link in all_links:
        ob, rem = parse_vless_url(link)
        if ob is not None:
            parsed.append((ob, rem))

    all_outbounds = []
    all_tags = []
    filtered_outbounds = []
    filtered_tags = []

    for idx, (ob, rem) in enumerate(parsed):
        tag = f"proxy-ig-{idx+1}"
        ob['tag'] = tag
        all_outbounds.append(ob)
        all_tags.append(tag)

        if not is_russia_or_belarus(rem):
            filtered_outbounds.append(ob.copy())
            filtered_tags.append(tag)

    direct_block = [
        {"protocol": "freedom", "settings": {"domainStrategy": "UseIP"}, "tag": "direct"},
        {"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"}
    ]

    config_all = create_config_template("🇫🇲 АБС Igareck [LTE]")
    config_all['outbounds'] = all_outbounds + direct_block
    config_all['routing']['balancers'][0]['selector'] = all_tags
    config_all['burstObservatory']['subjectSelector'] = all_tags

    config_filtered = create_config_template("🇫🇲 АБС Igareck [LTE] NoRU/BY")
    config_filtered['outbounds'] = filtered_outbounds + direct_block
    config_filtered['routing']['balancers'][0]['selector'] = filtered_tags
    config_filtered['burstObservatory']['subjectSelector'] = filtered_tags

    final_configs = [config_all, config_filtered] + existing_configs

    with open('subscription.json', 'w', encoding='utf-8') as f:
        json.dump(final_configs, f, indent=2, ensure_ascii=False)

    print(f"✅ Добавлено 2 конфига: {len(all_tags)} и {len(filtered_tags)} серверов")
    print(f"Всего конфигов в файле: {len(final_configs)}")

if __name__ == '__main__':
    main()
