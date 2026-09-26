#!/bin/bash
# Лабораторная проверка №3: Caddy — (а) HTTPS-сайт с завершением TLS на Caddy → бэкенд; (б) TLS passthrough по SNI → внутренний сервер со своим сертификатом.
# v4: layer4 Caddyfile-синтаксис — matcher tls не принимает subdirectives; использовать JSON-конфиг для L4 (надёжный путь), для сайта — Caddyfile-адаптация через JSON merge.
set -e
cd /tmp/caddy-test

echo "=== JSON-конфигурация Caddy (сайт + L4 passthrough) ==="
cat > config.json <<'JS'
{
  "admin": {"listen": "127.0.0.1:2019"},
  "logging": {"logs": {"default": {"level": "INFO"}}},
  "apps": {
    "http": {
      "http_port": 8080,
      "https_port": 8442,
      "servers": {
        "srv0": {
          "listen": [":8442"],
          "routes": [{
            "match": [{"host": ["site.test"]}],
            "handle": [{
              "handler": "subroute",
              "routes": [{
                "handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": "127.0.0.1:8081"}]}]
              }]
            }]
          }],
          "automatic_https": {"disable": false}
        }
      }
    },
    "tls": {
      "certificates": {"automate": ["site.test"]},
      "automation": {"policies": [{"issuers": [{"module": "internal"}]}]}
    },
    "layer4": {
      "servers": {
        "srv_l4": {
          "listen": [":8444"],
          "routes": [
            {
              "match": [{"tls": {"sni": ["site1.example.ru"]}}],
              "handle": [{"handler": "proxy", "upstreams": [{"dial": ["127.0.0.1:8443"]}]}]
            },
            {
              "handle": [{"handler": "proxy", "upstreams": [{"dial": ["127.0.0.1:8443"]}]}]
            }
          ]
        }
      }
    }
  }
}
JS

echo "=== Проверка синтаксиса ==="
/usr/local/bin/caddy-l4 validate --config config.json 2>&1 | grep -aiE "valid|error" | tail -2

echo "=== Старт Caddy ==="
pkill -f "caddy-l4 run" 2>/dev/null || true
nohup /usr/local/bin/caddy-l4 run --config config.json > caddy.log 2>&1 &
sleep 3

echo "=== Тест (а): HTTPS через Caddy (TLS завершается на Caddy) ==="
curl -sk https://127.0.0.1:8442/; echo
echo "--- чей сертификат (должен быть Caddy Local CA) ---"
echo | timeout 8 openssl s_client -connect 127.0.0.1:8442 -servername site.test 2>/dev/null | grep -E "subject=|issuer=" | head -2

echo "=== Тест (б): TLS passthrough по SNI (TLS завершается на backend2) ==="
echo "--- чей сертификат (должен быть internal.example.ru от backend2) ---"
echo | timeout 8 openssl s_client -connect 127.0.0.1:8444 -servername site1.example.ru 2>/dev/null | grep -E "subject=|issuer=" | head -2
echo "--- HTTP поверх passthrough ---"
curl -sk --resolve site1.example.ru:8444:127.0.0.1 https://site1.example.ru:8444/; echo
