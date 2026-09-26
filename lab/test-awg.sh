#!/bin/bash
# Тест AmneziaWG userspace на лабораторной VM: сервер awg0 + клиентский канал с обфускацией.
set -e
VM_IP="192.168.122.198"
VM="lab@${VM_IP}"
SSH="sshpass -p 123qwe123*** ssh -o StrictHostKeyChecking=no ${VM}"

echo "=== 1. Запуск awg-go демона с интерфейсом awg0 (обфускация) ==="
$SSH 'sudo -n bash -s' <<'EOF'
# Генерируем ключи
umask 077
mkdir -p /etc/amnezia
[ -f /etc/amnezia/server.priv ] || /usr/local/bin/awg genkey | tee /etc/amnezia/server.priv > /etc/amnezia/server.pub
[ -f /etc/amnezia/client.priv ] || /usr/local/bin/awg genkey | tee /etc/amnezia/client.priv > /etc/amnezia/client.pub

# Запускаем awg-go (userspace daemon)
ip link del awg0 2>/dev/null || true
nohup /usr/local/bin/awg-go -f /etc/amnezia/awg0.conf > /tmp/awg-go.log 2>&1 &
sleep 2

cat > /etc/amnezia/awg0.conf <<CFG
[Interface]
ListenPort = 51820
PrivateKey = $(cat /etc/amnezia/server.priv)
Address = 10.66.66.1/24
Jc = 4
Jmin = 40
Jmax = 70
S1 = 15
S2 = 95
H1 = 1234567
H2 = 2345678
H3 = 3456789
H4 = 4567890
CFG

# выставляем конфиг в интерфейс через awg setconf
/usr/local/bin/awg setconf awg0 /etc/amnezia/awg0.conf 2>&1 || true
/usr/local/bin/awg show awg0 2>&1 | head -4
EOF
echo
echo "=== 2. Проверка клиента (через veth/netns уже нет — просто show) ==="
