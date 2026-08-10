# Technische Notizen

- Öffentlich: `https://mcp.example.com/mcp` (über `APP_URL` konfigurierbar)
- Intern: `http://app:8080/api/integrations/v1/...`
- MCP ist stateless Streamable HTTP und verwendet `@modelcontextprotocol/sdk` 1.17.x.
- Der MCP-Container darf weder PostgreSQL noch MQTT direkt ansprechen.
- Bearer Tokens werden unverändert an die Integrations-API weitergegeben.
- Rollen, Scopes, Geräteauflösung, Sicherheitsregeln und Audit liegen in der Gateway-App.
- Öffentliche URLs dürfen niemals Docker-Hostnamen enthalten.
- Keine Tokens, Passwörter, OAuth-Codes oder privaten Schlüssel in dieser Datei dokumentieren.
