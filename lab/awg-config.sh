#!/bin/bash
# Полная настройка awg0 на VM: конфиг без Address (setconf-формат), с обфускацией и клиентом.
# Запускать на VM от root: bash /tmp/awg-config.sh
set -e
/usr/local/bin/awg setconf awg0 /dev/stdin <<CFG
[Interface]
ListenPort = 51820
PrivateKey = $(cat /etc/amnezia/server.priv)
Jc = 4
Jmin = 40
Jmax = 70
S1 = 15
S2 = 95
H1 = 1234567
H2 = 2345678
H3 = 3456789
H4 = 4567890

[Peer]
# клиент-тест
PublicKey = $(cat /etc/amnezia/client.pub)
AllowedIPs = 10.66.66.2/32
CFG
ip addr add 10.66.66.1/24 dev awg0 2>/dev/null || true
ip link set awg0 up
echo "=== awg show ==="
/usr/local/bin/awg show awg0
