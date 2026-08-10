#!/bin/sh
set -eu

ROOT=${PROJECT_ROOT:-/opt/iobroker-mcp}
DEPLOY=$ROOT/deploy
SECRETS=$DEPLOY/secrets
DOMAIN=${DOMAIN:?Set DOMAIN, for example mcp.example.com}
ADMIN_EMAIL=${ADMIN_EMAIL:-admin@$DOMAIN}
CERT=/etc/letsencrypt/live/$DOMAIN

test -d "$DEPLOY"
test -s "$CERT/fullchain.pem"
mkdir -p "$SECRETS/tls" "$DEPLOY/runtime-logs"
chmod 755 "$SECRETS" "$SECRETS/tls"

make_secret() {
    test -s "$1" || (umask 077 && openssl rand -base64 "$2" | tr -d '\n' > "$1")
}
make_secret "$SECRETS/bridge_password" 30
make_secret "$SECRETS/app_mqtt_password" 30
make_secret "$SECRETS/admin_password" 24

docker run --rm -v "$SECRETS:/work" eclipse-mosquitto:2.0.22 sh -eu -c '
  : > /work/mosquitto.passwd
  mosquitto_passwd -b /work/mosquitto.passwd iobroker_mcp_bridge "$(cat /work/bridge_password)"
  mosquitto_passwd -b /work/mosquitto.passwd iobroker_mcp_app "$(cat /work/app_mqtt_password)"
'

cp -L "$CERT/chain.pem" "$SECRETS/tls/chain.pem"
cp -L "$CERT/fullchain.pem" "$SECRETS/tls/fullchain.pem"
cp -L "$CERT/privkey.pem" "$SECRETS/tls/privkey.pem"
chown 1883:1883 "$SECRETS/mosquitto.passwd" "$SECRETS/tls/"*.pem
chmod 700 "$SECRETS/mosquitto.passwd"
chmod 644 "$SECRETS/tls/"*.pem
chown 1000:1000 "$SECRETS/admin_password"
chmod 400 "$SECRETS/admin_password"

if [ ! -s "$DEPLOY/.env" ]; then
  db_password=$(openssl rand -hex 24)
  mqtt_password=$(cat "$SECRETS/app_mqtt_password")
  umask 077
  {
    echo "APP_URL=https://$DOMAIN"
    echo 'APP_PORT=8080'
    echo 'POSTGRES_DB=iobroker_gateway'
    echo 'POSTGRES_USER=iobroker_gateway'
    echo "POSTGRES_PASSWORD=$db_password"
    echo "DATABASE_URL=postgresql://iobroker_gateway:$db_password@postgres:5432/iobroker_gateway"
    echo 'ADMIN_USERNAME=admin'
    echo "ADMIN_EMAIL=$ADMIN_EMAIL"
    echo 'REMEMBER_DAYS=30'
    echo 'MQTT_URL=mqtt://broker:1883'
    echo 'MQTT_APP_USERNAME=iobroker_mcp_app'
    echo "MQTT_APP_PASSWORD=$mqtt_password"
    echo 'MQTT_PREFIX=iobroker/mcp/v1'
  } > "$DEPLOY/.env"
fi

test -s "$ROOT/INITIAL_ADMIN_PASSWORD" || install -m 0600 "$SECRETS/admin_password" "$ROOT/INITIAL_ADMIN_PASSWORD"
cd "$DEPLOY"
docker compose up -d --build

sed "s/__DOMAIN__/$DOMAIN/g" "$DEPLOY/nginx-location.conf" > "/etc/nginx/sites-available/$DOMAIN"
chmod 644 "/etc/nginx/sites-available/$DOMAIN"
ln -sfn "/etc/nginx/sites-available/$DOMAIN" "/etc/nginx/sites-enabled/$DOMAIN"
nginx -t
systemctl reload nginx

renew_hook=/etc/letsencrypt/renewal-hooks/deploy/iobroker-mcp-broker.sh
cat > "$renew_hook" <<'HOOK'
#!/bin/sh
set -eu
domain=__DOMAIN__
target=__ROOT__/deploy/secrets/tls
cp -L "/etc/letsencrypt/live/$domain/chain.pem" "$target/chain.pem"
cp -L "/etc/letsencrypt/live/$domain/fullchain.pem" "$target/fullchain.pem"
cp -L "/etc/letsencrypt/live/$domain/privkey.pem" "$target/privkey.pem"
chown 1883:1883 "$target/"*.pem
chmod 644 "$target/"*.pem
docker restart iobroker_gateway_broker >/dev/null
HOOK
chmod 700 "$renew_hook"
sed -i "s/__DOMAIN__/$DOMAIN/g; s#__ROOT__#$ROOT#g" "$renew_hook"

echo "Deployment complete: https://$DOMAIN"
