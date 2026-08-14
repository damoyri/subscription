#!/usr/bin/env python3
import json
import re
import subprocess
import sys
import urllib.parse

VALID_FINGERPRINTS = ['chrome', 'firefox', 'edge', 'safari', 'ios', 'android', 'qq', 'random']
EXCLUDE_PATTERN = re.compile(r'(Россия|anycast|Беларусь|🇷🇺|🇧🇾|Russia|Belarus)', re.IGNORECASE)


def fetch_url(url, timeout=15):
    """
    Скачивание через curl — самый надежный способ в GitHub Actions,
    так как он обходит стандартные блокировки Python urllib со стороны Cloudflare/SSL.
    """
    try:
        result = subprocess.run(
            ['curl', '-sL', '--max-time', str(timeout), url],
            capture_output=True, text=True, check=True
        )
        return result.stdout.strip()
    except Exception as e:
        print(f"⚠️ Ошибка загрузки {url} через curl: {e}", file=sys.stderr)
        return None


def clean_fingerprint(fp):
    if not fp:
        return 'chrome'
    cleaned = re.sub(r'[#|*].*', '', fp).strip().lower()
    return cleaned if cleaned in VALID_FINGERPRINTS else 'chrome'


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
                            "maxRTT": "7s",                         # Увеличено под высокий пинг
                            "expected": 1,
                            "baselines": ["500ms", "1500ms", "3000ms"], # Расширен диапазон задержек
                            "tolerance": 0.1                       # Допуск 10% против флиппинга
                        }
                    },
                    "fallbackTag": "direct"
                }
            ]
        },
        "burstObservatory": {
            "pingConfig": {
                "timeout": "7s",                                    # Даем 7 сек на ответ
                "interval": "1m",                                   # Проверка каждую 1 минуту
                "sampling": 2,                                      # 2 запроса для проверки
                "destination": "http://www.gstatic.com/generate_204"
            },
            "subjectSelector": []
        },
        "outbounds": [],
        "remarks": remarks_text
    }


def parse_vless_url(raw_url):
    """Безопасный парсинг VLESS URL."""
    remarks = ''
    url_str = raw_url.strip()

    if '#' in url_str:
        url_str, remarks = url_str.split('#', 1)
        remarks = urllib.parse.unquote(remarks.strip())

    if not url_str.startswith('vless://'):
        return None, remarks

    try:
        parsed = urllib.parse.urlparse(url_str)
        user_id = parsed.username
        address = parsed.hostname
        port = parsed.port or 443

        if not user_id or not address:
            return None, remarks

        query_params = urllib.parse.parse_qs(parsed.query)
        params = {k: v[0] for k, v in query_params.items() if v}

        fp_raw = params.get('fp') or params.get('fingerprint', 'chrome')
        fingerprint = clean_fingerprint(fp_raw)

        is_reality = ('pbk' in params) or ('publicKey' in params) or (params.get('security') == 'reality')

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
                "network": params.get('type', 'tcp'),
                "security": "reality" if is_reality else "tls",
                "tcpSettings": {"header": {"type": "none"}}
            }
        }

        if is_reality:
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

    except Exception:
        return None, remarks


def main():
    print("📥 Скачиваем платную подписку...")
    paid_sub_url = 'https://connliberty.com/connection/subs/22a12228-aa7d-4f34-a7cd-b617a8f61c20'
    paid_sub_raw = fetch_url(paid_sub_url)
    existing_configs = []

    if paid_sub_raw:
        try:
            parsed_json = json.loads(paid_sub_raw)
            if isinstance(parsed_json, list):
                existing_configs = parsed_json
        except json.JSONDecodeError:
            print("⚠️ Ошибка парсинга JSON платной подписки", file=sys.stderr)

    # ЗАЩИТА: Если подписка не скачалась, пытаемся восстановить прошлые платные конфиги из локального subscription.json
    if not existing_configs:
        print("⚠️ Не удалось загрузить платную подписку по сети. Пробуем восстановить из прошлых данных...")
        try:
            with open('subscription.json', 'r', encoding='utf-8') as f:
                old_file_data = json.load(f)
                if isinstance(old_file_data, list):
                    # Отфильтровываем сгенерированные ранее конфиги Игарька
                    existing_configs = [
                        c for c in old_file_data 
                        if isinstance(c, dict) and not c.get('remarks', '').startswith('🇫🇲 АБС Igareck')
                    ]
                    print(f"🔄 Загружено {len(existing_configs)} платных конфигов из сохраненного subscription.json")
        except Exception as e:
            print(f"⚠️ Не удалось прочитать прошлый subscription.json: {e}")

    print(f"Итого платных конфигов для включения в сборку: {len(existing_configs)}")

    icareck_urls = [
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt"
    ]

    all_links = []
    for url in icareck_urls:
        print(f"📥 Скачиваем список: {url}")
        content = fetch_url(url)
        if content:
            for line in content.splitlines():
                line = line.strip()
                if line.startswith('vless://'):
                    all_links.append(line)

    # Удаляем дубликаты ссылок
    all_links = list(dict.fromkeys(all_links))

    if not all_links:
        print("❌ Не найдено ни одной VLESS ссылки Игарька", file=sys.stderr)
        sys.exit(1)

    print(f"Найдено {len(all_links)} уникальных ссылок Игарька")

    parsed = []
    for link in all_links:
        ob, rem = parse_vless_url(link)
        if ob is not None:
            parsed.append((ob, rem))

    all_outbounds = []
    all_tags = []
    filtered_outbounds = []
    filtered_tags = []

    for idx, (ob, rem) in enumerate(parsed, start=1):
        tag = f"proxy-ig-{idx}"
        
        ob_copy = json.loads(json.dumps(ob))
        ob_copy['tag'] = tag
        all_outbounds.append(ob_copy)
        all_tags.append(tag)

        if not is_russia_or_belarus(rem):
            filtered_outbounds.append(ob_copy)
            filtered_tags.append(tag)

    direct_block = [
        {"protocol": "freedom", "settings": {"domainStrategy": "UseIP"}, "tag": "direct"},
        {"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"}
    ]

    # Сборка общего конфига Игарька
    config_all = create_config_template("🇫🇲 АБС Igareck [LTE]")
    config_all['outbounds'] = all_outbounds + direct_block
    config_all['routing']['balancers'][0]['selector'] = all_tags
    config_all['burstObservatory']['subjectSelector'] = all_tags

    # Сборка фильтрованного конфига Игарька (без RU/BY)
    config_filtered = create_config_template("🇫🇲 АБС Igareck [LTE] NoRU/BY")
    config_filtered['outbounds'] = filtered_outbounds + direct_block
    config_filtered['routing']['balancers'][0]['selector'] = filtered_tags
    config_filtered['burstObservatory']['subjectSelector'] = filtered_tags

    # Объединяем 2 новых балансировщика + платные конфиги
    final_configs = [config_all, config_filtered] + existing_configs

    with open('subscription.json', 'w', encoding='utf-8') as f:
        json.dump(final_configs, f, indent=2, ensure_ascii=False)

    print(f"✅ Успешно обновлено!")
    print(f"   • Серверов в балансировщике (Все): {len(all_tags)}")
    print(f"   • Серверов в балансировщике (NoRU/BY): {len(filtered_tags)}")
    print(f"   • Всего записей в файле подписки: {len(final_configs)}")


if __name__ == '__main__':
    main()
