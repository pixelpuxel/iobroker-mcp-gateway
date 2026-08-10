#!/usr/bin/env python3
import base64
import hashlib
import http.cookiejar
import json
import os
import re
import secrets
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ.get("ACCEPTANCE_BASE_URL", "https://mcp.example.com").rstrip("/")

def request(opener, path, data=None, headers=None):
    body = None if data is None else urllib.parse.urlencode(data).encode()
    return opener.open(urllib.request.Request(BASE + path, body, headers or {}), timeout=20)

password = os.environ.get("ACCEPTANCE_PASSWORD")
if not password:
    password = open("/opt/iobroker-mcp/INITIAL_ADMIN_PASSWORD", encoding="utf-8").read().strip()
cookies = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies))
username = os.environ.get("ACCEPTANCE_USERNAME", "admin")
request(opener, "/login", {"identifier": username, "password": password, "remember": "yes", "next": "/"}).read()
assert any(c.name == "iobroker_gateway_session" and c.secure for c in cookies)

registration = json.loads(opener.open(urllib.request.Request(
    BASE + "/oauth/register",
    json.dumps({"client_name": "Acceptance Test", "redirect_uris": ["https://client.invalid/callback"]}).encode(),
    {"Content-Type": "application/json"}), timeout=20).read())
client_id = registration["client_id"]
verifier = secrets.token_urlsafe(48)
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
params = {
    "response_type": "code", "client_id": client_id,
    "redirect_uri": "https://client.invalid/callback", "scope": "read:devices write:devices read:audit",
    "state": "acceptance", "code_challenge": challenge, "code_challenge_method": "S256"
}
page = request(opener, "/oauth/authorize?" + urllib.parse.urlencode(params)).read().decode()
csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl): return None

no_redirect = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies), NoRedirect())
try:
    request(no_redirect, "/oauth/authorize", {**params, "csrf": csrf})
    raise AssertionError("OAuth authorize did not redirect")
except urllib.error.HTTPError as error:
    assert error.code == 302
    location = error.headers["Location"]
code = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)["code"][0]
token_result = json.loads(request(opener, "/oauth/token", {
    "grant_type": "authorization_code", "code": code, "client_id": client_id,
    "redirect_uri": params["redirect_uri"], "code_verifier": verifier
}).read())
token = token_result["access_token"]
auth = {"Authorization": "Bearer " + token}
me = json.loads(opener.open(urllib.request.Request(BASE + "/api/integrations/v1/me", headers=auth), timeout=20).read())
assert me["authenticated"] and "write:devices" in me["scopes"]

rpc = json.dumps({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "list_devices", "arguments": {"limit": 3}}}).encode()
mcp_headers = {**auth, "Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
tool_list_rpc = json.dumps({"jsonrpc": "2.0", "id": 6, "method": "tools/list", "params": {}}).encode()
tool_list_text = opener.open(urllib.request.Request(BASE + "/mcp", tool_list_rpc, mcp_headers), timeout=20).read().decode()
tool_list_data = json.loads(next(line.removeprefix("data: ") for line in tool_list_text.splitlines() if line.startswith("data: ")))
tools = tool_list_data["result"]["tools"]
assert len(tools) == 7 and all(tool.get("outputSchema") for tool in tools)
mcp = opener.open(urllib.request.Request(BASE + "/mcp", rpc, mcp_headers), timeout=20).read().decode()
assert '"items"' in mcp and '"id":7' in mcp

request(opener, "/oauth/revoke", {"token": token}).read()
try:
    opener.open(urllib.request.Request(BASE + "/api/integrations/v1/me", headers=auth), timeout=20)
    raise AssertionError("Revoked token was accepted")
except urllib.error.HTTPError as error:
    assert error.code == 401
print(json.dumps({"ok": True, "oauth_pkce": True, "mcp_tool_call": True, "output_schemas": len(tools), "revocation": True, "sample_limit": 3}))
