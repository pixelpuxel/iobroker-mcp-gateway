# AGENTS.md

## Project purpose

This repository provides a self-hosted, production-oriented bridge from an ioBroker installation in a private home network to OAuth-capable MCP clients on the public internet.

## Architecture boundaries

Keep these responsibilities strictly separated:

- `adapter/`: runs inside ioBroker, discovers states and communicates only through MQTT/TLS.
- `app/`: owns users, sessions, API tokens, OAuth, roles, scopes, audit, device context, MQTT and all home-automation business logic.
- `server/`: implements MCP only and calls exclusively `/api/integrations/v1/...` on `app`.
- `deploy/`: isolated Docker Compose stack, Mosquitto ACL, Nginx templates, Certbot hook and acceptance test.

The MCP server must never access PostgreSQL, MQTT, ioBroker, host files or Docker volumes directly. Do not duplicate application authorization or device logic in the MCP layer.

## Deployment rules

- All application dependencies and services run in Docker containers.
- Do not install Node.js packages, PostgreSQL, Mosquitto or project runtimes on the VPS host.
- Host changes are limited to Docker/Compose operation, Nginx, Certbot and the chosen project directory under `/opt`.
- Bind gateway and MCP HTTP ports to loopback only.
- Expose only MQTT over TLS for the outbound ioBroker connection.
- Preserve `.env`, secrets, runtime logs and Docker volumes during updates.
- Never run destructive Docker, volume, Git or filesystem cleanup commands without explicit approval.

## Security rules

- Never commit passwords, API tokens, private keys, certificates containing private material or production `.env` files.
- Application API tokens are created in the web UI, stored only as hashes and never placed in `.env`.
- Passwords use Argon2id.
- Persistent sessions are server-verifiable, revocable and stored as token hashes.
- Cookies remain `HttpOnly`, `Secure` and `SameSite=Lax` or stricter.
- OAuth uses Authorization Code with PKCE S256, short-lived single-use codes and revocable bearer tokens.
- Enforce roles and scopes in the integration API, not in the MCP server or UI alone.
- Audit login, logout, user changes, token changes, context edits and device writes.
- Safety-critical devices require explicit confirmation and are excluded from bulk commands.

## Adapter rules

- Use ioBroker's JSON admin configuration under `adapter/admin/jsonConfig.json`.
- Store a configured MQTT password through `encryptedNative`; alternatively support a protected password file.
- Keep CA file configuration optional so public certificates can use system trust.
- Publish connection state, catalog size and the latest connection error under `info.*`.
- Rebuild the catalog after ioBroker object changes.
- Preserve backwards compatibility for existing array-based include/exclude patterns.

## MCP tools

Every tool must define both a narrow input schema and an explicit output schema. Return matching `structuredContent` and a readable text representation. Prefer dedicated tools over generic request tools.

Current tools:

- `gateway_health`
- `gateway_me`
- `list_devices`
- `get_device_state`
- `set_device_state`
- `execute_home_command`
- `list_audit_logs`

## Required checks

Before publishing or deploying changes:

```sh
node --check adapter/main.js
node --check app/src/index.js
node --check server/server.js
python3 -m py_compile deploy/acceptance-test.py
sh -n deploy/install-vps.sh deploy/certbot-renew-hook.sh
```

Then verify:

```sh
cd deploy
docker compose up -d --build
docker compose ps
curl -s http://127.0.0.1:8139/api/integrations/v1/health
curl -s http://127.0.0.1:8140/health
```

Run `deploy/acceptance-test.py` with credentials supplied only as temporary environment variables. It must validate OAuth PKCE, all MCP output schemas, a real MCP tool call and token revocation.

## Documentation

Update `README.md`, root `PROMPT.md`, this file and `server/MEMORY.md` when architecture, scopes, endpoints, tools, deployment or security behavior changes.
