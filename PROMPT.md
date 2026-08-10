# Rebuild prompt: ioBroker MCP Gateway

Build or extend the ioBroker MCP Gateway in this repository.

The goal is a secure outbound bridge from a private ioBroker installation to an MCP endpoint on a public VPS. The home network must not require an inbound port. The ioBroker adapter connects through MQTT over TLS to an isolated broker on the VPS.

Use four Docker Compose services:

1. `app`: web UI, users, roles, sessions, API tokens, OAuth, audit, device context, MQTT and all domain logic.
2. `mcp`: stateless Streamable HTTP MCP translation service.
3. `postgres`: persistent application data.
4. `broker`: isolated Mosquitto broker with separate bridge and application users plus restrictive ACLs.

The MCP service must call only the versioned application API under `/api/integrations/v1/...`. It must not access MQTT, PostgreSQL, ioBroker, application volumes or host files. Forward the bearer token to the application and let the application enforce user state, roles, scopes and audit.

Provide an ioBroker JSON admin page for MQTT URL, username, encrypted password, optional password file, topic prefix, automatic smart-name discovery, include/exclude patterns, optional CA file and TLS validation. Expose adapter diagnostics under `info.connection`, `info.catalogSize` and `info.lastError`.

Provide a web UI with:

- login by username or email;
- password visibility toggle;
- remember-me sessions;
- admin and user roles;
- user creation, editing and deactivation;
- API token creation and revocation;
- audit log;
- clickable device and active-state lists;
- device detail pages;
- editable room, category, aliases and description;
- controlled writes for writable states.

Use Argon2id, secure cookies, CSRF protection, login rate limiting, token hashing, OAuth Authorization Code with PKCE S256 and HTTPS. Do not impose a formal password length or format policy unless explicitly requested.

Every MCP tool must publish explicit input and output schemas and return matching structured content. Implement dedicated tools for health, current identity, device search, state reading, state writing, German home commands and audit logs.

Keep all application services and dependencies inside Docker. On the host use only Docker/Compose, Nginx, Certbot and files below the project directory. App and MCP ports bind to loopback; PostgreSQL has no host port; only MQTT/TLS is exposed for the outbound home connection.

Never commit production secrets. Use `.env.example`, generate deployment secrets locally on the target, keep API tokens in the application, and preserve environment files, runtime data and volumes during deployment.

After changes, run syntax checks, build the Compose stack, verify both health endpoints, run the OAuth/MCP acceptance test, verify unauthorized and missing-scope failures, and update the documentation.
