#!/usr/bin/env python3
import re
import json
import urllib.parse
import sys
import subprocess

# ---------- ШАБЛОН КОНФИГА ----------
TEMPLATE = {
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
        "selector": [],   # заполним тегами Игарька
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
    "subjectSelector": []   # тоже заполним тегами Игарька
  },
  "outbounds": [
    # сюда будут добавлены прокси, потом direct и block
  ],
  "remarks": "🚀 WL_Balancer (Игарек) + остальные outbound'ы"
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
            "fingerprint": params.get('fp', 'firefox'),
            "publicKey": params.get('pbk', '') or params.get('publicKey', ''),
            "serverName": params.get('sni', address),
            "shortId": params.get('sid', ''),
            "show": False
        }
    else:
        outbound["streamSettings"]["tlsSettings"] = {
            "allowInsecure": False,
            "serverName": params.get('sni', address),
            "fingerprint": params.get('fp', 'firefox')
        }
    return outbound

# ---------- ОСНОВНАЯ ФУНКЦИЯ ----------
def main():
    # Ссылки на подписки
    igareck_urls = [
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt"
    ]
    connliberty_url = "https://connliberty.com/connection/subs/22a12228-aa7d-4f34-a7cd-b617a8f61c20"

    # Сбор ссылок
    def fetch_links(urls):
        links = []
        for url in urls:
            try:
                result = subprocess.run(['curl', '-sL', url], capture_output=True, text=True, check=True)
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line.startswith('vless://'):
                        links.append(line)
            except Exception as e:
                print(f"Ошибка загрузки {url}: {e}", file=sys.stderr)
        return links

    igareck_links = fetch_links(igareck_urls)
    connliberty_links = fetch_links([connliberty_url])

    print(f"Найдено {len(igareck_links)} ссылок Игарька, {len(connliberty_links)} ссылок connliberty")

    # ----- Генерируем outbounds -----
    outbounds = []
    igareck_tags = []

    # 1) Игарек – с тегами proxy-ig-*
    for idx, link in enumerate(igareck_links):
        ob = parse_vless_url(link)
        if ob is None:
            continue
        tag = f"proxy-ig-{idx+1}"
        ob['tag'] = tag
        outbounds.append(ob)
        igareck_tags.append(tag)

    # 2) Connliberty – с тегами proxy-cl-*
    for idx, link in enumerate(connliberty_links):
        ob = parse_vless_url(link)
        if ob is None:
            continue
        tag = f"proxy-cl-{idx+1}"
        ob['tag'] = tag
        outbounds.append(ob)
        # не добавляем в балансировщик

    # 3) Добавляем direct и block (в конце)
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

    # ----- Собираем итоговый конфиг -----
    config = TEMPLATE.copy()
    config['outbounds'] = outbounds

    # Обновляем балансировщик – селектор только из igareck_tags
    if igareck_tags:
        config['routing']['balancers'][0]['selector'] = igareck_tags
        config['burstObservatory']['subjectSelector'] = igareck_tags
    else:
        # Если нет серверов Игарька, балансировщик будет использовать direct
        config['routing']['balancers'][0]['selector'] = ['direct']
        config['routing']['balancers'][0]['fallbackTag'] = 'direct'
        config['burstObservatory']['subjectSelector'] = ['direct']

    # Сохраняем
    with open('subscription.json', 'w') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

    print("Конфиг успешно создан. WL_Balancer содержит только сервера Игарька.")

if __name__ == '__main__':
    main()
