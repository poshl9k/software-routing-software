#!/bin/bash
# Запуск awg-go демона на VM как systemd-юнит (надёжнее nohup).
set -e
sudo -n bash -s <<'UNIT'
umask 077
mkdir -p /etc/amnezia
[ -f /etc/amnezia/server.priv ] || /usr/local/bin/awg genkey | tee /etc/amnezia/server.priv > /etc/amnezia/server.pub
[ -f /etc/amnezia/client.priv ] || /usr/local/bin/awg genkey | tee /etc/amnezia/client.priv > /etc/amnezia/client.pub

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

cat > /etc/systemd/system/awg-go.service <<SVC
[Unit]
Description=AmneziaWG userspace daemon (awg-go)
After=network.target

[Service]
ExecStart=/usr/local/bin/awg-go -f /etc/amnezia/awg0.conf
Restart=on-failure

[Install]
WantedBy=multi-user.target
SVC

systemctl daemon-reload
systemctl enable --now awg-go
sleep 2
systemctl is-active awg-go
UNIT
