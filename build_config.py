#!/usr/bin/env python3
import json
import re
import subprocess
import sys
import urllib.parse

VALID_FINGERPRINTS = ['chrome', 'firefox', 'edge', 'safari', 'ios', 'android', 'qq', 'random']
EXCLUDE_PATTERN = re.compile(r'(Р РѕСЃСЃРёСЏ|anycast|Р‘РµР»Р°СЂСѓСЃСЊ|рџ‡·рџ‡є|рџ‡§рџ‡ѕ|Russia|Belarus)', re.IGNORECASE)


def fetch_url(url, timeout=15):
    """
    РЎРєР°С‡РёРІР°РЅРёРµ С‡РµСЂРµР· curl вЂ” СЃР°РјС‹Р№ РЅР°РґРµР¶РЅС‹Р№ СЃРїРѕСЃРѕР± РІ GitHub Actions.
    """
    try:
        result = subprocess.run(
            ['curl', '-sL', '--max-time', str(timeout), url],
            capture_output=True, text=True, check=True
        )
        return result.stdout.strip()
    except Exception as e:
        print(f"вљ пёЏ РћС€РёР±РєР° Р·Р°РіСЂСѓР·РєРё {url} С‡РµСЂРµР· curl: {e}", file=sys.stderr)
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
    """Р‘РµР·РѕРїР°СЃРЅС‹Р№ РїР°СЂСЃРёРЅРі VLESS URL."""
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
    """Р’СЃРїРѕРјРѕРіР°С‚РµР»СЊРЅР°СЏ С„СѓРЅРєС†РёСЏ РґР»СЏ РјР°СЃСЃРѕРІРѕРіРѕ СЃРєР°С‡РёРІР°РЅРёСЏ VLESS СЃСЃС‹Р»РѕРє РёР· СЃРїРёСЃРєР° URL"""
    all_links = []
    for url in urls_list:
        print(f"рџ“Ґ РЎРєР°С‡РёРІР°РµРј СЃРїРёСЃРѕРє: {url}")
        content = fetch_url(url)
        if content:
            for line in content.splitlines():
                line = line.strip()
                if line.startswith('vless://'):
                    all_links.append(line)
    
    # Р’РѕР·РІСЂР°С‰Р°РµРј РѕС‡РёС‰РµРЅРЅС‹Р№ СЃРїРёСЃРѕРє Р±РµР· РґСѓР±Р»РёРєР°С‚РѕРІ
    return list(dict.fromkeys(all_links))


def main():
    print("рџ“Ґ Р—Р°РіСЂСѓР·РєР° РїР»Р°С‚РЅРѕР№ РїРѕРґРїРёСЃРєРё...")
    paid_sub_url = 'https://vlv.one/h7n0gvdjvv'
    paid_sub_raw = fetch_url(paid_sub_url)
    existing_configs = []

    if paid_sub_raw:
        try:
            parsed_json = json.loads(paid_sub_raw)
            if isinstance(parsed_json, list):
                existing_configs = parsed_json
        except json.JSONDecodeError:
            print("вљ пёЏ РћС€РёР±РєР° РїР°СЂСЃРёРЅРіР° JSON РїР»Р°С‚РЅРѕР№ РїРѕРґРїРёСЃРєРё", file=sys.stderr)

    # Р—РђР©РРўРђ: Р’РѕСЃСЃС‚Р°РЅРѕРІР»РµРЅРёРµ СЃС‚Р°СЂС‹С… РєРѕРЅС„РёРіРѕРІ
    if not existing_configs:
        print("вљ пёЏ РќРµ СѓРґР°Р»РѕСЃСЊ Р·Р°РіСЂСѓР·РёС‚СЊ РїР»Р°С‚РЅСѓСЋ РїРѕРґРїРёСЃРєСѓ РїРѕ СЃРµС‚Рё. РџСЂРѕР±СѓРµРј РІРѕСЃСЃС‚Р°РЅРѕРІРёС‚СЊ РёР· РїСЂРѕС€Р»С‹С… РґР°РЅРЅС‹С…...")
        try:
            with open('subscription.json', 'r', encoding='utf-8') as f:
                old_file_data = json.load(f)
                if isinstance(old_file_data, list):
                    # РСЃРєР»СЋС‡Р°РµРј РІСЃРµ СЂР°РЅРµРµ СЃРіРµРЅРµСЂРёСЂРѕРІР°РЅРЅС‹Рµ Р±Р°Р»Р°РЅСЃРёСЂРѕРІС‰РёРєРё (РїРѕ СЌРјРѕРґР·Рё Рё СЃС‚Р°СЂРѕРјСѓ РЅР°Р·РІР°РЅРёСЋ)
                    exclude_prefixes = ('рџЏіпёЏlist', 'рџЏґlist')
                    existing_configs = [
                        c for c in old_file_data 
                        if isinstance(c, dict) and not c.get('remarks', '').startswith(exclude_prefixes)
                    ]
                    print(f"рџ”„ Р—Р°РіСЂСѓР¶РµРЅРѕ {len(existing_configs)} РїР»Р°С‚РЅС‹С… РєРѕРЅС„РёРіРѕРІ РёР· СЃРѕС…СЂР°РЅРµРЅРЅРѕРіРѕ subscription.json")
        except Exception as e:
            print(f"вљ пёЏ РќРµ СѓРґР°Р»РѕСЃСЊ РїСЂРѕС‡РёС‚Р°С‚СЊ РїСЂРѕС€Р»С‹Р№ subscription.json: {e}")

    print(f"РС‚РѕРіРѕ РїР»Р°С‚РЅС‹С… РєРѕРЅС„РёРіРѕРІ: {len(existing_configs)}\n")

    # ==========================
    # РћР‘Р РђР‘РћРўРљРђ Р‘Р•Р›Р«РҐ РЎРџРРЎРљРћР’
    # ==========================
    white_urls = [
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt"
    ]
    
    white_links = get_vless_links(white_urls)
    print(f"РќР°Р№РґРµРЅРѕ {len(white_links)} СѓРЅРёРєР°Р»СЊРЅС‹С… СЃСЃС‹Р»РѕРє (Р‘РµР»С‹Рµ СЃРїРёСЃРєРё)")

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
    # РћР‘Р РђР‘РћРўРљРђ Р§Р•Р РќРћР“Рћ РЎРџРРЎРљРђ
    # ==========================
    print("\n")
    black_urls = [
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS_mobile.txt"
    ]
    
    black_links = get_vless_links(black_urls)
    print(f"РќР°Р№РґРµРЅРѕ {len(black_links)} СѓРЅРёРєР°Р»СЊРЅС‹С… СЃСЃС‹Р»РѕРє (Р§РµСЂРЅС‹Рµ СЃРїРёСЃРєРё)")

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
    # РЎР‘РћР РљРђ РРўРћР“РћР’Р«РҐ РљРћРќР¤РР“РћР’
    # ==========================
    direct_block = [
        {"protocol": "freedom", "settings": {"domainStrategy": "UseIP"}, "tag": "direct"},
        {"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"}
    ]

    # 1. Р‘РµР»С‹Р№ СЃРїРёСЃРѕРє (Р’СЃРµ)
    config_wl_all = create_config_template("рџЏіпёЏlist [LTE]")
    config_wl_all['outbounds'] = wl_outbounds_all + direct_block
    config_wl_all['routing']['balancers'][0]['selector'] = wl_tags_all
    config_wl_all['burstObservatory']['subjectSelector'] = wl_tags_all

    # 2. Р‘РµР»С‹Р№ СЃРїРёСЃРѕРє (Р‘РµР· RU/BY)
    config_wl_noru = create_config_template("рџЏіпёЏlist [LTE] NoRU/BY")
    config_wl_noru['outbounds'] = wl_outbounds_noru + direct_block
    config_wl_noru['routing']['balancers'][0]['selector'] = wl_tags_noru
    config_wl_noru['burstObservatory']['subjectSelector'] = wl_tags_noru

    # 3. Р§РµСЂРЅС‹Р№ СЃРїРёСЃРѕРє
    config_bl = create_config_template("рџЏґlist [wifi]")
    # РџСЂРѕРІРµСЂРєР° РЅР° СЃР»СѓС‡Р°Р№, РµСЃР»Рё С‡РµСЂРЅС‹Р№ СЃРїРёСЃРѕРє РїСѓСЃС‚
    if bl_outbounds:
        config_bl['outbounds'] = bl_outbounds + direct_block
        config_bl['routing']['balancers'][0]['selector'] = bl_tags
        config_bl['burstObservatory']['subjectSelector'] = bl_tags
    else:
        config_bl['outbounds'] = direct_block

    # РћР±СЉРµРґРёРЅСЏРµРј РІСЃРµ СЃРіРµРЅРµСЂРёСЂРѕРІР°РЅРЅС‹Рµ Р±Р°Р»Р°РЅСЃРёСЂРѕРІС‰РёРєРё Рё РїР»Р°С‚РЅС‹Рµ РєРѕРЅС„РёРіРё
    final_configs = [config_wl_all, config_wl_noru, config_bl] + existing_configs

    # РЎРѕС…СЂР°РЅРµРЅРёРµ РІ subscription.json
    with open('subscription.json', 'w', encoding='utf-8') as f:
        json.dump(final_configs, f, indent=2, ensure_ascii=False)

    # Р”РћР‘РђР’Р›Р•РќРћ: РЎРѕС…СЂР°РЅРµРЅРёРµ РІ subscription.txt (С‚Р°РєРѕР№ Р¶Рµ JSON, РЅРѕ РІ С‚РµРєСЃС‚РѕРІРѕРј С„Р°Р№Р»Рµ)
    with open('subscription.txt', 'w', encoding='utf-8') as f:
        json.dump(final_configs, f, indent=2, ensure_ascii=False)

    print("\nвњ… РЈСЃРїРµС€РЅРѕ РѕР±РЅРѕРІР»РµРЅРѕ!")
    print(f"   вЂў РЎРµСЂРІРµСЂРѕРІ РІ Р±РµР»РѕРј СЃРїРёСЃРєРµ (Р’СЃРµ): {len(wl_tags_all)}")
    print(f"   вЂў РЎРµСЂРІРµСЂРѕРІ РІ Р±РµР»РѕРј СЃРїРёСЃРєРµ (NoRU/BY): {len(wl_tags_noru)}")
    print(f"   вЂў РЎРµСЂРІРµСЂРѕРІ РІ С‡РµСЂРЅРѕРј СЃРїРёСЃРєРµ: {len(bl_tags)}")
    print(f"   вЂў Р’СЃРµРіРѕ Р·Р°РїРёСЃРµР№ РІ С„Р°Р№Р»Рµ РїРѕРґРїРёСЃРєРё: {len(final_configs)}")
    print("   вЂў Р РµР·СѓР»СЊС‚Р°С‚ СЃРѕС…СЂР°РЅС‘РЅ РІ subscription.json Рё subscription.txt")


if __name__ == '__main__':
    main()
