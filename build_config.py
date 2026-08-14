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
    Скачивание через curl — самый надежный способ в GitHub Actions.
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
                            "maxRTT": "7s",
                            "expected": 1,
                            "baselines": ["500ms", "1500ms", "3000ms"],
                            "tolerance": 0.1
                        }
                    },
                    "fallbackTag": "direct"
                }
            ]
        },
        "burstObservatory": {
            "pingConfig": {
                "timeout": "7s",
                "interval": "1m",
                "sampling": 2,
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


def get_vless_links(urls_list):
    """Вспомогательная функция для массового скачивания VLESS ссылок из списка URL"""
    all_links = []
    for url in urls_list:
        print(f"📥 Скачиваем список: {url}")
        content = fetch_url(url)
        if content:
            for line in content.splitlines():
                line = line.strip()
                if line.startswith('vless://'):
                    all_links.append(line)
    
    # Возвращаем очищенный список без дубликатов
    return list(dict.fromkeys(all_links))


def main():
    print("📥 Загрузка платной подписки...")
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

    # ЗАЩИТА: Восстановление старых конфигов
    if not existing_configs:
        print("⚠️ Не удалось загрузить платную подписку по сети. Пробуем восстановить из прошлых данных...")
        try:
            with open('subscription.json', 'r', encoding='utf-8') as f:
                old_file_data = json.load(f)
                if isinstance(old_file_data, list):
                    # Исключаем все ранее сгенерированные балансировщики (по эмодзи и старому названию)
                    exclude_prefixes = ('🏳️list', '🏴list')
                    existing_configs = [
                        c for c in old_file_data 
                        if isinstance(c, dict) and not c.get('remarks', '').startswith(exclude_prefixes)
                    ]
                    print(f"🔄 Загружено {len(existing_configs)} платных конфигов из сохраненного subscription.json")
        except Exception as e:
            print(f"⚠️ Не удалось прочитать прошлый subscription.json: {e}")

    print(f"Итого платных конфигов: {len(existing_configs)}\n")

    # ==========================
    # ОБРАБОТКА БЕЛЫХ СПИСКОВ
    # ==========================
    white_urls = [
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt"
    ]
    
    white_links = get_vless_links(white_urls)
    print(f"Найдено {len(white_links)} уникальных ссылок (Белые списки)")

    white_parsed = []
    for link in white_links:
        ob, rem = parse_vless_url(link)
        if ob is not None:
            white_parsed.append((ob, rem))

    wl_outbounds_all = []
    wl_tags_all = []
    wl_outbounds_noru = []
    wl_tags_noru = []

    for idx, (ob, rem) in enumerate(white_parsed, start=1):
        tag = f"proxy-wl-{idx}"
        
        ob_copy = json.loads(json.dumps(ob))
        ob_copy['tag'] = tag
        wl_outbounds_all.append(ob_copy)
        wl_tags_all.append(tag)

        if not is_russia_or_belarus(rem):
            wl_outbounds_noru.append(ob_copy)
            wl_tags_noru.append(tag)

    # ==========================
    # ОБРАБОТКА ЧЕРНОГО СПИСКА
    # ==========================
    print("\n")
    black_urls = [
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS_mobile.txt"
    ]
    
    black_links = get_vless_links(black_urls)
    print(f"Найдено {len(black_links)} уникальных ссылок (Черные списки)")

    black_parsed = []
    for link in black_links:
        ob, rem = parse_vless_url(link)
        if ob is not None:
            black_parsed.append((ob, rem))

    bl_outbounds = []
    bl_tags = []

    for idx, (ob, rem) in enumerate(black_parsed, start=1):
        tag = f"proxy-bl-{idx}"
        
        ob_copy = json.loads(json.dumps(ob))
        ob_copy['tag'] = tag
        bl_outbounds.append(ob_copy)
        bl_tags.append(tag)

    # ==========================
    # СБОРКА ИТОГОВЫХ КОНФИГОВ
    # ==========================
    direct_block = [
        {"protocol": "freedom", "settings": {"domainStrategy": "UseIP"}, "tag": "direct"},
        {"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"}
    ]

    # 1. Белый список (Все)
    config_wl_all = create_config_template("🏳️list [LTE]")
    config_wl_all['outbounds'] = wl_outbounds_all + direct_block
    config_wl_all['routing']['balancers'][0]['selector'] = wl_tags_all
    config_wl_all['burstObservatory']['subjectSelector'] = wl_tags_all

    # 2. Белый список (Без RU/BY)
    config_wl_noru = create_config_template("🏳️list [LTE] NoRU/BY")
    config_wl_noru['outbounds'] = wl_outbounds_noru + direct_block
    config_wl_noru['routing']['balancers'][0]['selector'] = wl_tags_noru
    config_wl_noru['burstObservatory']['subjectSelector'] = wl_tags_noru

    # 3. Черный список
    config_bl = create_config_template("🏴list [wifi]")
    # Проверка на случай, если черный список пуст
    if bl_outbounds:
        config_bl['outbounds'] = bl_outbounds + direct_block
        config_bl['routing']['balancers'][0]['selector'] = bl_tags
        config_bl['burstObservatory']['subjectSelector'] = bl_tags
    else:
        config_bl['outbounds'] = direct_block

    # Объединяем все сгенерированные балансировщики и платные конфиги
    final_configs = [config_wl_all, config_wl_noru, config_bl] + existing_configs

    with open('subscription.json', 'w', encoding='utf-8') as f:
        json.dump(final_configs, f, indent=2, ensure_ascii=False)

    print("\n✅ Успешно обновлено!")
    print(f"   • Серверов в белом списке (Все): {len(wl_tags_all)}")
    print(f"   • Серверов в белом списке (NoRU/BY): {len(wl_tags_noru)}")
    print(f"   • Серверов в черном списке: {len(bl_tags)}")
    print(f"   • Всего записей в файле подписки: {len(final_configs)}")


if __name__ == '__main__':
    main()
