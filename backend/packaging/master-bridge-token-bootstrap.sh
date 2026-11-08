#!/bin/sh
# Restricted SSH forced command: token comes only from stdin, never arguments.
set -eu
umask 077
. /etc/vs-router/secrets.env
: "${VS_ROUTER_SECRET_KEY:?missing host encryption key}"
exec /usr/bin/env -i PATH=/usr/bin:/bin VS_ROUTER_SECRET_KEY="$VS_ROUTER_SECRET_KEY" \
    /usr/bin/python3 -m vs_router.master_bridge_bootstrap
