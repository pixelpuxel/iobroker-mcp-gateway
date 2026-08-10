import express from 'express';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { z } from 'zod';

const env = process.env;
const appBase = String(env.MCP_APP_BASE_URL || 'http://app:8080').replace(/\/$/, '');
const publicBase = String(env.MCP_PUBLIC_BASE_URL).replace(/\/$/, '');
const jsonObject = z.record(z.unknown());
const healthOutput = z.object({ ok: z.boolean(), mqttConnected: z.boolean(), bridge: jsonObject, devices: z.number(), states: z.number() }).passthrough();
const meOutput = z.object({ authenticated: z.boolean(), user: jsonObject, roles: z.array(z.string()), scopes: z.array(z.string()), instance: jsonObject }).passthrough();
const deviceListOutput = z.object({ items: z.array(jsonObject), total: z.number() }).passthrough();
const deviceOutput = z.object({ device: jsonObject, state: jsonObject.nullable() }).passthrough();
const stateChangeOutput = z.object({ ok: z.boolean(), device: jsonObject, result: jsonObject }).passthrough();
const commandOutput = z.object({ command: z.string(), interpreted: jsonObject, results: z.array(jsonObject) }).passthrough();
const auditOutput = z.object({ items: z.array(jsonObject) }).passthrough();

async function api(path, token, options = {}) {
  if (!/^\/api\/integrations\/v1\/[a-zA-Z0-9/_?=&.%:-]*$/.test(path)) throw new Error('Unzulässiger Integrationspfad.');
  const response = await fetch(`${appBase}${path}`, { method: options.method || 'GET', headers: { Authorization: `Bearer ${token}`, Accept: 'application/json', ...(options.body ? { 'Content-Type': 'application/json' } : {}) }, body: options.body ? JSON.stringify(options.body) : undefined, signal: AbortSignal.timeout(15000), redirect: 'error' });
  const value = await response.json().catch(() => ({ error: { message: `HTTP ${response.status}` } }));
  if (!response.ok) throw Object.assign(new Error(value.error?.message || `HTTP ${response.status}`), { status: response.status, value });
  return value;
}
const output = value => ({ content: [{ type: 'text', text: JSON.stringify(value, null, 2) }], structuredContent: value });
function createServer(token) {
  const server = new McpServer({ name: env.MCP_SERVER_NAME || 'ioBroker MCP', version: env.MCP_SERVER_VERSION || '1.0.0' });
  server.registerTool('gateway_health',{description:'Prüft Gateway, MQTT-Heimnetzbrücke und Zahl erkannter Datenpunkte.',inputSchema:{},outputSchema:healthOutput},async()=>output(await api('/api/integrations/v1/health',token)));
  server.registerTool('gateway_me',{description:'Zeigt angemeldeten Benutzer, Rollen, Scopes und Instanz.',inputSchema:{},outputSchema:meOutput},async()=>output(await api('/api/integrations/v1/me',token)));
  server.registerTool('list_devices',{description:'Sucht automatisch erkannte ioBroker-Geräte und Datenpunkte.',inputSchema:{query:z.string().optional(),kind:z.string().optional(),limit:z.number().int().min(1).max(200).optional()},outputSchema:deviceListOutput},async({query='',kind,limit=50})=>{const q=new URLSearchParams({q:query,limit:String(limit)});if(kind)q.set('kind',kind);return output(await api(`/api/integrations/v1/devices?${q}`,token));});
  server.registerTool('get_device_state',{description:'Liest Metadaten, Kontext und aktuellen Zustand eines eindeutig identifizierten Datenpunkts.',inputSchema:{endpoint_id:z.string().min(1)},outputSchema:deviceOutput},async({endpoint_id})=>output(await api(`/api/integrations/v1/devices/${encodeURIComponent(endpoint_id)}`,token)));
  server.registerTool('set_device_state',{description:'Setzt einen Datenpunkt. Sicherheitskritische Geräte erfordern eine ausdrückliche Bestätigung.',inputSchema:{endpoint_id:z.string().min(1),value:z.union([z.boolean(),z.number(),z.string()]),confirm_sensitive:z.boolean().optional()},outputSchema:stateChangeOutput},async({endpoint_id,value,confirm_sensitive=false})=>output(await api(`/api/integrations/v1/devices/${encodeURIComponent(endpoint_id)}/state`,token,{method:'POST',body:{value,confirmSensitive:confirm_sensitive}})));
  server.registerTool('execute_home_command',{description:'Interpretiert einen deutschen Hausautomationsbefehl wie „alle Lichter aus“. Mehrdeutige oder gefährliche Aktionen werden abgewiesen.',inputSchema:{command:z.string().min(1),confirm_sensitive:z.boolean().optional()},outputSchema:commandOutput},async({command,confirm_sensitive=false})=>output(await api('/api/integrations/v1/commands',token,{method:'POST',body:{command,confirmSensitive:confirm_sensitive}})));
  server.registerTool('list_audit_logs',{description:'Liest die letzten protokollierten Anmelde-, Verwaltungs- und Geräteaktionen.',inputSchema:{limit:z.number().int().min(1).max(200).optional()},outputSchema:auditOutput},async({limit=50})=>output(await api(`/api/integrations/v1/audit-logs?limit=${limit}`,token)));
  return server;
}

const web = express(); web.disable('x-powered-by'); web.use(express.json({limit:'256kb'}));
web.get('/health',async(_req,res)=>{try{const response=await fetch(`${appBase}/api/integrations/v1/health`,{signal:AbortSignal.timeout(5000)});res.status(response.ok?200:503).json({ok:response.ok,application:await response.json()});}catch(error){res.status(503).json({ok:false,error:error.message});}});
web.get('/.well-known/oauth-protected-resource',(_req,res)=>res.json({resource:`${publicBase}/mcp`,authorization_servers:[publicBase],bearer_methods_supported:['header']}));
async function authorize(req,res,next){const token=String(req.headers.authorization||'').replace(/^Bearer\s+/i,'');if(!token){res.set('WWW-Authenticate',`Bearer resource_metadata="${publicBase}/.well-known/oauth-protected-resource"`);return res.status(401).json({error:'unauthorized'});}try{await api('/api/integrations/v1/me',token);req.token=token;next();}catch(error){res.set('WWW-Authenticate',`Bearer resource_metadata="${publicBase}/.well-known/oauth-protected-resource"`);res.status(error.status===403?403:401).json(error.value||{error:'invalid_token'});}}
web.post('/mcp',authorize,async(req,res)=>{const server=createServer(req.token);const transport=new StreamableHTTPServerTransport({sessionIdGenerator:undefined});res.on('close',()=>{transport.close().catch(()=>{});server.close().catch(()=>{});});await server.connect(transport);await transport.handleRequest(req,res,req.body);});
web.get('/mcp',authorize,(_req,res)=>res.status(405).json({error:'method_not_allowed'}));
web.delete('/mcp',authorize,(_req,res)=>res.sendStatus(204));
web.listen(Number(env.MCP_PORT||8090),'0.0.0.0',()=>console.log('ioBroker MCP translation service listening'));
