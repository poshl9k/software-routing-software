#!/bin/sh
# Install after installing the Python package and its system dependencies.
set -eu
id vs-router-web >/dev/null 2>&1 || useradd --system --home-dir /var/lib/vs-router --shell /usr/sbin/nologin vs-router-web
install -d -m 0700 /etc/vs-router /etc/vs-router/applied /etc/vs-router/confirmed
install -d -m 0755 /run/vs-router
install -d -m 0750 -o vs-router-web -g vs-router-web /run/vs-router/web /var/lib/vs-router
packaging_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
install -m 0644 "$packaging_dir"/*.service "$packaging_dir"/*.timer /etc/systemd/system/
install -m 0644 "$packaging_dir/vs-router.conf" /etc/tmpfiles.d/vs-router.conf
systemctl daemon-reload
