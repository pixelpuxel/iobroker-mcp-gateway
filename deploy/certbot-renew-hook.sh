#!/bin/sh
set -eu
domain=${DOMAIN:?Set DOMAIN}
target=${PROJECT_ROOT:-/opt/iobroker-mcp}/deploy/secrets/tls
cp -L "/etc/letsencrypt/live/$domain/chain.pem" "$target/chain.pem"
cp -L "/etc/letsencrypt/live/$domain/fullchain.pem" "$target/fullchain.pem"
cp -L "/etc/letsencrypt/live/$domain/privkey.pem" "$target/privkey.pem"
chown 1883:1883 "$target/"*.pem
chmod 644 "$target/"*.pem
docker restart iobroker_gateway_broker >/dev/null
