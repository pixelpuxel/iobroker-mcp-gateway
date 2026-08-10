import crypto from 'node:crypto';
import fs from 'node:fs';
import argon2 from 'argon2';
import cookieParser from 'cookie-parser';
import express from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import mqtt from 'mqtt';
import pg from 'pg';
import { z } from 'zod';

const env = process.env;
const db = new pg.Pool({ connectionString: env.DATABASE_URL });
const publicUrl = env.APP_URL;
const prefix = env.MQTT_PREFIX || 'iobroker/mcp/v1';
const cookieName = 'iobroker_gateway_session';
const catalog = new Map();
const states = new Map();
const pending = new Map();
let presence = { online: false };

const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');
const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url');
const htmlEscape = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

async function schema() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      id uuid PRIMARY KEY, username text NOT NULL UNIQUE, email text NOT NULL UNIQUE,
      display_name text NOT NULL, password_hash text NOT NULL, role text NOT NULL CHECK(role IN ('admin','user')),
      active boolean NOT NULL DEFAULT true, email_verified boolean NOT NULL DEFAULT false,
      created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(), last_login_at timestamptz
    );
    CREATE TABLE IF NOT EXISTS sessions (
      id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash text NOT NULL UNIQUE, csrf_token text NOT NULL, persistent boolean NOT NULL,
      expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), last_seen_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS api_tokens (
      id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name text NOT NULL, token_prefix text NOT NULL, token_hash text NOT NULL UNIQUE,
      scopes text[] NOT NULL, expires_at timestamptz, revoked_at timestamptz,
      created_at timestamptz NOT NULL DEFAULT now(), last_used_at timestamptz
    );
    CREATE TABLE IF NOT EXISTS oauth_clients (
      client_id text PRIMARY KEY, client_name text NOT NULL, redirect_uris text[] NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS oauth_codes (
      code_hash text PRIMARY KEY, client_id text NOT NULL REFERENCES oauth_clients(client_id),
      user_id uuid NOT NULL REFERENCES users(id), redirect_uri text NOT NULL, scopes text[] NOT NULL,
      code_challenge text NOT NULL, expires_at timestamptz NOT NULL, used_at timestamptz
    );
    CREATE TABLE IF NOT EXISTS audit_logs (
      id bigserial PRIMARY KEY, actor_user_id uuid REFERENCES users(id), event text NOT NULL,
      target text, details jsonb NOT NULL DEFAULT '{}', ip text, created_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS device_contexts (
      endpoint_id text PRIMARY KEY, display_name text, room text, category text, description text,
      aliases text[] NOT NULL DEFAULT '{}', updated_by uuid REFERENCES users(id),
      created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
    );
  `);
  const existing = await db.query('SELECT id FROM users LIMIT 1');
  if (!existing.rowCount) {
    const password = fs.readFileSync('/run/secrets/admin_password', 'utf8').trim();
    await db.query('INSERT INTO users(id,username,email,display_name,password_hash,role,active,email_verified) VALUES($1,$2,$3,$4,$5,$6,true,true)',
      [crypto.randomUUID(), env.ADMIN_USERNAME || 'admin', env.ADMIN_EMAIL, 'Administrator', await argon2.hash(password, { type: argon2.argon2id }), 'admin']);
  }
}

async function audit(event, actor, target, details, ip) {
  await db.query('INSERT INTO audit_logs(actor_user_id,event,target,details,ip) VALUES($1,$2,$3,$4,$5)', [actor || null, event, target || null, details || {}, ip || null]);
}

const mq = mqtt.connect(env.MQTT_URL || 'mqtt://broker:1883', {
  username: env.MQTT_APP_USERNAME, password: env.MQTT_APP_PASSWORD,
  clientId: `gateway-${crypto.randomUUID()}`, reconnectPeriod: 3000
});
mq.on('connect', () => mq.subscribe([`${prefix}/catalog/+`, `${prefix}/state/+`, `${prefix}/result/+`, `${prefix}/presence/+`], { qos: 1 }));
mq.on('message', (topic, payload) => {
  const parts = topic.slice(prefix.length + 1).split('/');
  if (!payload.length) { (parts[0] === 'catalog' ? catalog : states).delete(parts[1]); return; }
  let value; try { value = JSON.parse(payload.toString('utf8')); } catch { return; }
  if (parts[0] === 'catalog') catalog.set(parts[1], value);
  else if (parts[0] === 'state') states.set(parts[1], value);
  else if (parts[0] === 'presence') presence = value;
  else if (parts[0] === 'result') { const waiter = pending.get(parts[1]); if (waiter) { pending.delete(parts[1]); waiter(value); } }
});

function normalize(text) { return String(text || '').toLocaleLowerCase('de-DE').normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/ß/g, 'ss').trim(); }
function matchScore(query, d) {
  const q = normalize(query); if (!q) return 1;
  const names = [d.name, ...(d.aliases || []), d.objectId].map(normalize);
  if (names.includes(q)) return 100;
  if (names.some(n => n.includes(q) || q.includes(n))) return 80;
  return Math.max(...names.map(n => n.split(/\s+/).filter(w => q.split(/\s+/).includes(w)).length * 15), 0);
}
function findDevice(query, writable = false, source = [...catalog.values()]) {
  const ranked = source.filter(d => !writable || d.writable).map(d => ({ d, score: matchScore(query, d) })).sort((a,b) => b.score-a.score);
  if (!ranked[0] || ranked[0].score < 15) throw Object.assign(new Error(`Kein Datenpunkt für „${query}“ gefunden.`), { status: 404 });
  const ties = ranked.filter(x => x.score === ranked[0].score);
  if (ties.length > 1 && ranked[0].score < 100) throw Object.assign(new Error(`Mehrdeutig: ${ties.slice(0,6).map(x => x.d.name).join(', ')}`), { status: 409 });
  return ranked[0].d;
}
function send(device, value, confirmSensitive) {
  const requestId = crypto.randomUUID();
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { pending.delete(requestId); reject(Object.assign(new Error('Keine Bestätigung der Heimnetz-Bridge.'), { status: 503 })); }, 12000);
    pending.set(requestId, result => { clearTimeout(timer); result.ok ? resolve(result) : reject(Object.assign(new Error(result.error || 'Befehl fehlgeschlagen'), { status: 422 })); });
    mq.publish(`${prefix}/command/${device.endpointId}`, JSON.stringify({ requestId, value, confirmSensitive }), { qos: 1 });
  });
}
function parseCommand(command) {
  const text = normalize(command), off = /\b(aus|ausschalten|abschalten|stoppen)\b/.test(text), on = /\b(an|ein|einschalten|anschalten|starten)\b/.test(text);
  const number = text.match(/(-?\d+(?:[.,]\d+)?)/);
  return { all: /\b(alle|alles|samtl)/.test(text), group: /licht/.test(text) ? 'light' : /rollo|rollladen|jalousie/.test(text) ? 'blind' : null,
    value: number ? Number(number[1].replace(',','.')) : off ? false : on ? true : undefined,
    target: text.replace(/\b(mach|schalte|stelle|setze|bitte|alle|alles|an|ein|aus|auf|zu|einschalten|ausschalten|prozent|grad)\b/g,' ').replace(/\s+/g,' ').trim() };
}

async function deviceContexts(endpointIds) {
  if (!endpointIds.length) return new Map();
  const rows = (await db.query('SELECT * FROM device_contexts WHERE endpoint_id=ANY($1)', [endpointIds])).rows;
  return new Map(rows.map(row => [row.endpoint_id, row]));
}
function contextualDevice(device, context) {
  if (!context) return { ...device, context: { displayName: '', room: '', category: '', description: '', aliases: [] } };
  return { ...device, name: context.display_name || device.name, aliases: [...new Set([...(device.aliases || []), ...(context.aliases || [])])], context: {
    displayName: context.display_name || '', room: context.room || '', category: context.category || '',
    description: context.description || '', aliases: context.aliases || [], updatedAt: context.updated_at
  } };
}

const app = express();
app.set('trust proxy', 1); app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false })); app.use(express.urlencoded({ extended: false, limit: '64kb' })); app.use(express.json({ limit: '256kb' })); app.use(cookieParser());

async function sessionAuth(req, _res, next) {
  const raw = req.cookies[cookieName]; if (!raw) return next();
  const q = await db.query(`SELECT s.*,u.username,u.email,u.display_name,u.role,u.active FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now()`, [sha256(raw)]);
  if (q.rowCount && q.rows[0].active) { req.session = q.rows[0]; req.user = q.rows[0]; await db.query('UPDATE sessions SET last_seen_at=now() WHERE id=$1', [q.rows[0].id]); }
  next();
}
app.use(sessionAuth);
const needLogin = (req,res,next) => req.user ? next() : res.redirect(`/login?next=${encodeURIComponent(req.originalUrl)}`);
const needAdmin = (req,res,next) => req.user?.role === 'admin' ? next() : res.status(403).send('Nicht berechtigt');
const csrf = (req,res,next) => req.session && req.body.csrf === req.session.csrf_token ? next() : res.status(403).send('Ungültiger CSRF-Schutz');

function layout(title, body, user) { return `<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${htmlEscape(title)}</title><style>
:root{color-scheme:dark;--bg:#101419;--card:#1b222a;--line:#34404c;--accent:#55c7a5;--text:#eef4f7;--muted:#a9b5bf;--danger:#ff7d7d}*{box-sizing:border-box}body{margin:0;background:linear-gradient(135deg,#0d1116,#18232a);font:16px system-ui;color:var(--text)}main{max-width:1050px;margin:40px auto;padding:20px}.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:24px;margin:16px 0;box-shadow:0 18px 60px #0005}input,select,button{font:inherit;border-radius:9px;border:1px solid var(--line);padding:11px;background:#11171d;color:var(--text)}button,.button{background:var(--accent);color:#082018;font-weight:700;cursor:pointer;text-decoration:none;display:inline-block}label{display:block;margin:14px 0 6px;color:var(--muted)}.row{display:flex;gap:12px;flex-wrap:wrap;align-items:center}.grow{flex:1;min-width:210px}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:10px;border-bottom:1px solid var(--line)}a{color:#79ddbf}.muted{color:var(--muted)}.danger{color:var(--danger)}nav{display:flex;gap:15px;align-items:center;margin-bottom:25px}nav form{margin-left:auto}.password{position:relative}.password input{width:100%;padding-right:48px}.eye{position:absolute;right:4px;top:4px;background:transparent;color:var(--muted);border:0;padding:7px}</style></head><body><main>${user ? `<nav><b>ioBroker MCP</b><a href="/">Übersicht</a>${user.role==='admin'?'<a href="/admin/users">Benutzer</a><a href="/admin/tokens">API-Tokens</a><a href="/admin/audit">Audit</a>':''}<form method="post" action="/logout"><input type="hidden" name="csrf" value="${user.csrf_token}"><button>Abmelden</button></form></nav>`:''}${body}</main></body></html>`; }

app.get('/login', (req,res) => res.send(layout('Anmelden', `<div class="card" style="max-width:480px;margin:8vh auto"><h1>Anmelden</h1><p class="muted">ioBroker MCP Gateway</p>${req.query.error?'<p class="danger">Anmeldung fehlgeschlagen.</p>':''}<form method="post" action="/login"><input type="hidden" name="next" value="${htmlEscape(req.query.next||'/')}"><label>E-Mail oder Benutzername</label><input class="grow" style="width:100%" name="identifier" required autocomplete="username"><label>Passwort</label><div class="password"><input id="pw" name="password" type="password" required autocomplete="current-password"><button class="eye" type="button" aria-label="Passwort anzeigen" onclick="pw.type=pw.type==='password'?'text':'password';this.textContent=pw.type==='password'?'◉':'⊘'">◉</button></div><label><input type="checkbox" name="remember" value="yes"> Angemeldet bleiben</label><button style="width:100%;margin-top:18px">Anmelden</button></form></div>`)));
const loginLimiter = rateLimit({ windowMs: 15*60*1000, limit: 10, standardHeaders: true, legacyHeaders: false });
app.post('/login', loginLimiter, async (req,res) => {
  const identifier = String(req.body.identifier||'').trim().toLowerCase();
  const q = await db.query('SELECT * FROM users WHERE active=true AND (lower(email)=$1 OR lower(username)=$1)', [identifier]);
  const user = q.rows[0];
  if (!user || !await argon2.verify(user.password_hash, String(req.body.password||''))) { await audit('login_failed', user?.id, null, {}, req.ip); return res.redirect('/login?error=1'); }
  const raw = randomToken(), persistent = req.body.remember === 'yes', hours = persistent ? Number(env.REMEMBER_DAYS||30)*24 : 12;
  await db.query('INSERT INTO sessions(id,user_id,token_hash,csrf_token,persistent,expires_at) VALUES($1,$2,$3,$4,$5,now()+($6||\' hours\')::interval)', [crypto.randomUUID(),user.id,sha256(raw),randomToken(),persistent,String(hours)]);
  await db.query('UPDATE users SET last_login_at=now() WHERE id=$1',[user.id]); await audit('login',user.id,null,{persistent},req.ip);
  res.cookie(cookieName,raw,{httpOnly:true,secure:true,sameSite:'lax',path:'/',maxAge:persistent?hours*3600000:undefined}); res.redirect(String(req.body.next||'/').startsWith('/')?req.body.next:'/');
});
app.post('/logout', needLogin, csrf, async (req,res) => { await db.query('DELETE FROM sessions WHERE id=$1',[req.session.id]); await audit('logout',req.user.user_id,null,{},req.ip); res.clearCookie(cookieName,{path:'/'}); res.redirect('/login'); });
app.get('/', needLogin, (req,res) => res.send(layout('Übersicht', `<h1>ioBroker MCP Gateway</h1><div class="row"><a class="card grow" href="/devices" style="color:inherit;text-decoration:none"><h2>${catalog.size}</h2><span class="muted">erkannte Datenpunkte · öffnen</span></a><a class="card grow" href="/devices?active=1" style="color:inherit;text-decoration:none"><h2>${states.size}</h2><span class="muted">aktuelle Zustände · öffnen</span></a><div class="card grow"><h2>${presence.online?'Verbunden':'Offline'}</h2><span class="muted">Heimnetz-Bridge</span></div></div><div class="card"><h2>MCP-Verbindung</h2><code>${publicUrl}/mcp</code><p class="muted">API-Tokens und OAuth-Zugriffe werden serverseitig verwaltet.</p></div>`,req.user)));

app.get('/devices',needLogin,async(req,res)=>{const query=String(req.query.q||'').trim(),onlyActive=req.query.active==='1';let devices=[...catalog.values()].filter(d=>!onlyActive||states.has(d.endpointId));const contexts=await deviceContexts(devices.map(d=>d.endpointId));devices=devices.map(d=>contextualDevice(d,contexts.get(d.endpointId))).filter(d=>!query||matchScore(query,d)>0||normalize(d.context.room).includes(normalize(query))||normalize(d.context.description).includes(normalize(query))).sort((a,b)=>a.name.localeCompare(b.name,'de'));const rows=devices.map(d=>{const s=states.get(d.endpointId);return `<tr><td><a href="/devices/${encodeURIComponent(d.endpointId)}"><b>${htmlEscape(d.name)}</b></a><br><span class="muted">${htmlEscape(d.context.room||d.context.category||d.kind)}</span></td><td>${s?`<b>${htmlEscape(s.value)}</b>${d.unit?` ${htmlEscape(d.unit)}`:''}`:'<span class="muted">kein Zustand</span>'}</td><td>${htmlEscape(d.type)}</td><td>${d.writable?'änderbar':'nur lesbar'}</td><td>${d.sensitive?'⚠ sicherheitskritisch':''}</td></tr>`;}).join('');res.send(layout(onlyActive?'Aktive Zustände':'Datenpunkte',`<h1>${onlyActive?'Aktive Zustände':'Erkannte Datenpunkte'}</h1><div class="card"><form method="get" class="row"><input class="grow" name="q" value="${htmlEscape(query)}" placeholder="Name, Raum, Beschreibung oder Objekt-ID">${onlyActive?'<input type="hidden" name="active" value="1">':''}<button>Suchen</button><a href="/devices${onlyActive?'?active=1':''}">Zurücksetzen</a></form><p class="muted">${devices.length} Einträge. Ein Datenpunkt öffnet Metadaten, Kontext und Bearbeitung.</p><div style="overflow:auto"><table><tr><th>Datenpunkt</th><th>Wert</th><th>Typ</th><th>Zugriff</th><th></th></tr>${rows}</table></div></div>`,req.user));});

app.get('/devices/:id',needLogin,async(req,res)=>{const raw=catalog.get(req.params.id);if(!raw)return res.status(404).send(layout('Nicht gefunden','<div class="card"><h1>Datenpunkt nicht gefunden</h1></div>',req.user));const context=(await deviceContexts([raw.endpointId])).get(raw.endpointId);const d=contextualDevice(raw,context),s=states.get(d.endpointId);const stateControl=d.writable&&req.user.role==='admin'?`<div class="card"><h2>Zustand ändern</h2><form method="post" action="/devices/${encodeURIComponent(d.endpointId)}/state"><input type="hidden" name="csrf" value="${req.session.csrf_token}"><label>Neuer Wert</label>${d.type==='boolean'?`<select name="value"><option value="true">an / wahr</option><option value="false">aus / falsch</option></select>`:`<input name="value" value="${htmlEscape(s?.value??'')}" ${d.type==='number'?'type="number" step="any"':''}>`}${d.sensitive?'<label><input type="checkbox" name="confirmSensitive" value="yes"> Sicherheitskritische Änderung ausdrücklich bestätigen</label>':''}<p><button>Wert an ioBroker senden</button></p></form></div>`:'';const contextControl=req.user.role==='admin'?`<div class="card"><h2>Kontext bearbeiten</h2><p class="muted">Diese Angaben ergänzen die ioBroker-Metadaten und helfen MCP bei der eindeutigen Interpretation.</p><form method="post" action="/devices/${encodeURIComponent(d.endpointId)}/context"><input type="hidden" name="csrf" value="${req.session.csrf_token}"><label>Anzeigename</label><input class="grow" name="displayName" value="${htmlEscape(d.context.displayName)}" placeholder="Optionaler verständlicher Name"><label>Raum / Bereich</label><input class="grow" name="room" value="${htmlEscape(d.context.room)}" placeholder="z. B. Wohnzimmer"><label>Kategorie</label><input class="grow" name="category" value="${htmlEscape(d.context.category)}" placeholder="z. B. Beleuchtung"><label>Weitere Namen, kommagetrennt</label><input class="grow" name="aliases" value="${htmlEscape(d.context.aliases.join(', '))}"><label>Beschreibung und Verwendung</label><textarea name="description" rows="4" style="width:100%;background:#11171d;color:var(--text);border:1px solid var(--line);border-radius:9px;padding:11px">${htmlEscape(d.context.description)}</textarea><p><button>Kontext speichern</button></p></form></div>`:'';res.send(layout(d.name,`<p><a href="/devices">← Alle Datenpunkte</a></p><h1>${htmlEscape(d.name)}</h1><div class="row"><div class="card grow"><h2>${s?`${htmlEscape(s.value)}${d.unit?` ${htmlEscape(d.unit)}`:''}`:'–'}</h2><span class="muted">Aktueller Zustand</span></div><div class="card grow"><h2>${htmlEscape(d.kind)}</h2><span class="muted">Erkannter Gerätetyp</span></div><div class="card grow"><h2>${d.writable?'änderbar':'nur lesbar'}</h2><span class="muted">ioBroker-Zugriff</span></div></div><div class="card"><h2>Technischer Kontext</h2><table><tr><th>ioBroker-Objekt</th><td><code>${htmlEscape(d.objectId)}</code></td></tr><tr><th>Endpoint-ID</th><td><code>${htmlEscape(d.endpointId)}</code></td></tr><tr><th>Datentyp</th><td>${htmlEscape(d.type)}</td></tr><tr><th>Rolle</th><td>${htmlEscape(d.role||'–')}</td></tr><tr><th>Einheit / Bereich</th><td>${htmlEscape(d.unit||'–')} ${d.min!==undefined?`· min ${d.min}`:''} ${d.max!==undefined?`· max ${d.max}`:''}</td></tr><tr><th>Aliase</th><td>${htmlEscape((d.aliases||[]).join(', '))}</td></tr><tr><th>Raum / Kategorie</th><td>${htmlEscape([d.context.room,d.context.category].filter(Boolean).join(' · ')||'–')}</td></tr><tr><th>Beschreibung</th><td>${htmlEscape(d.context.description||'–')}</td></tr><tr><th>Statuszeit</th><td>${s?.ts?new Date(s.ts).toLocaleString('de-DE'):'–'}</td></tr><tr><th>Letzte Wertänderung</th><td>${s?.lc?new Date(s.lc).toLocaleString('de-DE'):'–'}</td></tr><tr><th>Bestätigt</th><td>${s?s.ack?'ja':'nein':'–'}</td></tr><tr><th>Sicherheitskritisch</th><td>${d.sensitive?'ja':'nein'}</td></tr></table></div>${stateControl}${contextControl}`,req.user));});

app.post('/devices/:id/context',needLogin,needAdmin,csrf,async(req,res)=>{const d=catalog.get(req.params.id);if(!d)return res.sendStatus(404);const aliases=String(req.body.aliases||'').split(',').map(x=>x.trim()).filter(Boolean).slice(0,30);await db.query(`INSERT INTO device_contexts(endpoint_id,display_name,room,category,description,aliases,updated_by) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(endpoint_id) DO UPDATE SET display_name=excluded.display_name,room=excluded.room,category=excluded.category,description=excluded.description,aliases=excluded.aliases,updated_by=excluded.updated_by,updated_at=now()`,[d.endpointId,String(req.body.displayName||'').trim()||null,String(req.body.room||'').trim()||null,String(req.body.category||'').trim()||null,String(req.body.description||'').trim()||null,aliases,req.user.user_id]);await audit('device_context_updated',req.user.user_id,d.objectId,{room:req.body.room,category:req.body.category},req.ip);res.redirect(`/devices/${encodeURIComponent(d.endpointId)}`);});
app.post('/devices/:id/state',needLogin,needAdmin,csrf,async(req,res,next)=>{try{const d=catalog.get(req.params.id);if(!d)return res.sendStatus(404);let value=req.body.value;if(d.type==='boolean')value=value==='true';else if(d.type==='number')value=Number(value);const result=await send(d,value,req.body.confirmSensitive==='yes');await audit('device_state_set_ui',req.user.user_id,d.objectId,{value,result},req.ip);res.redirect(`/devices/${encodeURIComponent(d.endpointId)}`);}catch(error){next(error);}});

app.get('/admin/users',needLogin,needAdmin,async(req,res)=>{const users=(await db.query('SELECT id,username,email,display_name,role,active,last_login_at FROM users ORDER BY username')).rows;res.send(layout('Benutzer',`<h1>Benutzer</h1><div class="card"><table><tr><th>Name</th><th>Login</th><th>Rolle</th><th>Status</th><th>Letzte Anmeldung</th><th></th></tr>${users.map(u=>`<tr><td>${htmlEscape(u.display_name)}</td><td>${htmlEscape(u.username)}<br><span class="muted">${htmlEscape(u.email)}</span></td><td>${u.role}</td><td>${u.active?'aktiv':'deaktiviert'}</td><td>${u.last_login_at?new Date(u.last_login_at).toLocaleString('de-DE'):'–'}</td><td><a href="/admin/users/${u.id}">Bearbeiten</a></td></tr>`).join('')}</table></div><div class="card"><h2>Benutzer erstellen</h2><form method="post"><input type="hidden" name="csrf" value="${req.session.csrf_token}"><div class="row"><input name="username" placeholder="Benutzername" required><input name="email" type="email" placeholder="E-Mail" required><input name="displayName" placeholder="Anzeigename" required><input name="password" type="password" placeholder="Passwort" required><select name="role"><option>user</option><option>admin</option></select><button>Erstellen</button></div></form></div>`,req.user));});
app.post('/admin/users',needLogin,needAdmin,csrf,async(req,res)=>{const v=z.object({username:z.string().min(1),email:z.email(),displayName:z.string().min(1),password:z.string(),role:z.enum(['admin','user']),csrf:z.string()}).parse(req.body);const id=crypto.randomUUID();await db.query('INSERT INTO users(id,username,email,display_name,password_hash,role) VALUES($1,$2,$3,$4,$5,$6)',[id,v.username,v.email.toLowerCase(),v.displayName,await argon2.hash(v.password,{type:argon2.argon2id}),v.role]);await audit('user_created',req.user.user_id,id,{role:v.role},req.ip);res.redirect('/admin/users');});
app.get('/admin/users/:id',needLogin,needAdmin,async(req,res)=>{const u=(await db.query('SELECT * FROM users WHERE id=$1',[req.params.id])).rows[0];if(!u)return res.sendStatus(404);res.send(layout('Benutzer bearbeiten',`<h1>Benutzer bearbeiten</h1><div class="card"><form method="post" action="/admin/users/${u.id}"><input type="hidden" name="csrf" value="${req.session.csrf_token}"><label>Benutzername</label><input name="username" value="${htmlEscape(u.username)}"><label>E-Mail</label><input name="email" type="email" value="${htmlEscape(u.email)}"><label>Anzeigename</label><input name="displayName" value="${htmlEscape(u.display_name)}"><label>Rolle</label><select name="role"><option ${u.role==='user'?'selected':''}>user</option><option ${u.role==='admin'?'selected':''}>admin</option></select><label><input type="checkbox" name="active" ${u.active?'checked':''}> Aktiv</label><label>Neues Passwort (leer lassen = unverändert)</label><input name="password" type="password"><p><button>Speichern</button></p></form></div>`,req.user));});
app.post('/admin/users/:id',needLogin,needAdmin,csrf,async(req,res)=>{const active=req.body.active==='on';await db.query('UPDATE users SET username=$1,email=$2,display_name=$3,role=$4,active=$5,updated_at=now() WHERE id=$6',[req.body.username,String(req.body.email).toLowerCase(),req.body.displayName,req.body.role,active,req.params.id]);if(req.body.password){await db.query('UPDATE users SET password_hash=$1 WHERE id=$2',[await argon2.hash(req.body.password,{type:argon2.argon2id}),req.params.id]);await db.query('DELETE FROM sessions WHERE user_id=$1',[req.params.id]);}if(!active)await db.query('DELETE FROM sessions WHERE user_id=$1',[req.params.id]);await audit('user_updated',req.user.user_id,req.params.id,{role:req.body.role,active,passwordChanged:Boolean(req.body.password)},req.ip);res.redirect('/admin/users');});

app.get('/admin/tokens',needLogin,needAdmin,async(req,res)=>{const rows=(await db.query('SELECT t.id,t.name,t.token_prefix,t.scopes,t.created_at,t.last_used_at,t.revoked_at,u.username FROM api_tokens t JOIN users u ON u.id=t.user_id ORDER BY t.created_at DESC')).rows;res.send(layout('API-Tokens',`<h1>API-Tokens</h1>${req.query.token?`<div class="card"><b>Dieses Token wird nur einmal angezeigt:</b><p><code>${htmlEscape(req.query.token)}</code></p></div>`:''}<div class="card"><table><tr><th>Name</th><th>Benutzer</th><th>Scopes</th><th>Status</th><th></th></tr>${rows.map(t=>`<tr><td>${htmlEscape(t.name)}<br><span class="muted">${t.token_prefix}…</span></td><td>${htmlEscape(t.username)}</td><td>${t.scopes.join(', ')}</td><td>${t.revoked_at?'widerrufen':'aktiv'}</td><td>${t.revoked_at?'':`<form method="post" action="/admin/tokens/${t.id}/revoke"><input type="hidden" name="csrf" value="${req.session.csrf_token}"><button>Widerrufen</button></form>`}</td></tr>`).join('')}</table></div><div class="card"><h2>Token erstellen</h2><form method="post"><input type="hidden" name="csrf" value="${req.session.csrf_token}"><input name="name" placeholder="Name" required><label><input type="checkbox" name="read" checked> read:devices</label><label><input type="checkbox" name="write"> write:devices</label><label><input type="checkbox" name="audit"> read:audit</label><button>Einmaliges Token erzeugen</button></form></div>`,req.user));});
app.post('/admin/tokens',needLogin,needAdmin,csrf,async(req,res)=>{const raw=`ibmcp_${randomToken(36)}`;const scopes=[req.body.read&&'read:devices',req.body.write&&'write:devices',req.body.audit&&'read:audit'].filter(Boolean);await db.query('INSERT INTO api_tokens(id,user_id,name,token_prefix,token_hash,scopes) VALUES($1,$2,$3,$4,$5,$6)',[crypto.randomUUID(),req.user.user_id,req.body.name,raw.slice(0,12),sha256(raw),scopes]);await audit('api_token_created',req.user.user_id,null,{name:req.body.name,scopes},req.ip);res.redirect(`/admin/tokens?token=${encodeURIComponent(raw)}`);});
app.post('/admin/tokens/:id/revoke',needLogin,needAdmin,csrf,async(req,res)=>{await db.query('UPDATE api_tokens SET revoked_at=now() WHERE id=$1',[req.params.id]);await audit('api_token_revoked',req.user.user_id,req.params.id,{},req.ip);res.redirect('/admin/tokens');});
app.get('/admin/audit',needLogin,needAdmin,async(req,res)=>{const rows=(await db.query('SELECT a.*,u.username FROM audit_logs a LEFT JOIN users u ON u.id=a.actor_user_id ORDER BY created_at DESC LIMIT 200')).rows;res.send(layout('Audit',`<h1>Audit-Protokoll</h1><div class="card"><table><tr><th>Zeit</th><th>Ereignis</th><th>Akteur</th><th>Ziel</th></tr>${rows.map(a=>`<tr><td>${new Date(a.created_at).toLocaleString('de-DE')}</td><td>${htmlEscape(a.event)}</td><td>${htmlEscape(a.username||'System')}</td><td>${htmlEscape(a.target||'')}</td></tr>`).join('')}</table></div>`,req.user));});

async function bearer(req,res,next){const raw=String(req.headers.authorization||'').replace(/^Bearer\s+/i,'');if(!raw)return res.status(401).json({error:{code:'unauthorized',message:'Bearer Token fehlt.'}});const q=await db.query(`SELECT t.*,u.username,u.display_name,u.role,u.active FROM api_tokens t JOIN users u ON u.id=t.user_id WHERE t.token_hash=$1 AND t.revoked_at IS NULL AND (t.expires_at IS NULL OR t.expires_at>now())`,[sha256(raw)]);if(!q.rowCount||!q.rows[0].active)return res.status(401).json({error:{code:'invalid_token',message:'Token ist ungültig oder abgelaufen.'}});req.apiToken=q.rows[0];await db.query('UPDATE api_tokens SET last_used_at=now() WHERE id=$1',[q.rows[0].id]);next();}
const scope = wanted => (req,res,next) => req.apiToken.scopes.includes(wanted) ? next() : res.status(403).json({error:{code:'missing_scope',message:`Scope ${wanted} wird benötigt.`}});
app.get('/api/integrations/v1/health',(_req,res)=>res.json({ok:true,mqttConnected:mq.connected,bridge:presence,devices:catalog.size,states:states.size}));
app.get('/api/integrations/v1/me',bearer,(req,res)=>res.json({authenticated:true,user:{id:req.apiToken.user_id,username:req.apiToken.username,displayName:req.apiToken.display_name},roles:[req.apiToken.role],scopes:req.apiToken.scopes,instance:{id:'home',name:'Zuhause'}}));
app.get('/api/integrations/v1/devices',bearer,scope('read:devices'),async(req,res)=>{let source=[...catalog.values()].filter(d=>!req.query.kind||d.kind===req.query.kind);const contexts=await deviceContexts(source.map(d=>d.endpointId));source=source.map(d=>contextualDevice(d,contexts.get(d.endpointId)));const matched=source.map(d=>({...d,state:states.get(d.endpointId)||null,match:matchScore(req.query.q,d)})).filter(d=>!req.query.q||d.match>0).sort((a,b)=>b.match-a.match);const limit=Math.min(Number(req.query.limit)||50,200);res.json({items:matched.slice(0,limit),total:matched.length});});
app.get('/api/integrations/v1/devices/:id',bearer,scope('read:devices'),async(req,res)=>{const raw=catalog.get(req.params.id);if(!raw)return res.status(404).json({error:{code:'not_found',message:'Datenpunkt nicht gefunden.'}});const contexts=await deviceContexts([raw.endpointId]);const d=contextualDevice(raw,contexts.get(raw.endpointId));res.json({device:d,state:states.get(d.endpointId)||null});});
app.post('/api/integrations/v1/devices/:id/state',bearer,scope('write:devices'),async(req,res,next)=>{try{const d=catalog.get(req.params.id);if(!d)return res.sendStatus(404);const result=await send(d,req.body.value,req.body.confirmSensitive===true);await audit('device_state_set',req.apiToken.user_id,d.objectId,{value:req.body.value},req.ip);res.json({ok:true,device:d,result});}catch(e){next(e);}});
app.post('/api/integrations/v1/commands',bearer,scope('write:devices'),async(req,res,next)=>{try{const p=parseCommand(String(req.body.command||''));if(p.value===undefined)throw Object.assign(new Error('Keinen Zielwert erkannt.'),{status:422});const raw=[...catalog.values()],contexts=await deviceContexts(raw.map(d=>d.endpointId)),source=raw.map(d=>contextualDevice(d,contexts.get(d.endpointId)));const targets=p.all?source.filter(d=>d.writable&&!d.sensitive&&(!p.group||d.kind===p.group||(p.group==='light'&&d.kind==='dimmer'))):[findDevice(p.target||req.body.command,true,source)];const results=[];for(const d of targets){try{results.push({device:d.name,ok:true,result:await send(d,p.value,req.body.confirmSensitive===true)});}catch(e){results.push({device:d.name,ok:false,error:e.message});}}await audit('home_command',req.apiToken.user_id,null,{command:req.body.command,targets:targets.map(d=>d.objectId)},req.ip);res.json({command:req.body.command,interpreted:p,results});}catch(e){next(e);}});
app.get('/api/integrations/v1/audit-logs',bearer,scope('read:audit'),(req,res,next)=>req.apiToken.role==='admin'?next():res.status(403).json({error:{code:'missing_role',message:'Administratorrolle wird benötigt.'}}),async(req,res)=>res.json({items:(await db.query('SELECT id,event,target,details,created_at FROM audit_logs ORDER BY created_at DESC LIMIT $1',[Math.min(Number(req.query.limit)||50,200)])).rows}));

app.get('/.well-known/oauth-authorization-server',(_req,res)=>res.json({issuer:publicUrl,authorization_endpoint:`${publicUrl}/oauth/authorize`,token_endpoint:`${publicUrl}/oauth/token`,registration_endpoint:`${publicUrl}/oauth/register`,revocation_endpoint:`${publicUrl}/oauth/revoke`,response_types_supported:['code'],grant_types_supported:['authorization_code'],code_challenge_methods_supported:['S256'],token_endpoint_auth_methods_supported:['none'],scopes_supported:['read:devices','write:devices','read:audit']}));
app.post('/oauth/register',(req,res)=>{const uris=z.array(z.url()).min(1).parse(req.body.redirect_uris);const id=`client_${randomToken(18)}`;db.query('INSERT INTO oauth_clients(client_id,client_name,redirect_uris) VALUES($1,$2,$3)',[id,req.body.client_name||'MCP Client',uris]).then(()=>res.status(201).json({client_id:id,client_name:req.body.client_name||'MCP Client',redirect_uris:uris,token_endpoint_auth_method:'none'}));});
app.get('/oauth/authorize',needLogin,async(req,res)=>{const client=(await db.query('SELECT * FROM oauth_clients WHERE client_id=$1',[req.query.client_id])).rows[0];if(req.query.response_type!=='code'||!client||!client.redirect_uris.includes(req.query.redirect_uri)||req.query.code_challenge_method!=='S256'||!req.query.code_challenge)return res.status(400).send('Ungültige OAuth-Anfrage');const allowed=req.user.role==='admin'?['read:devices','write:devices','read:audit']:['read:devices'];const scopes=String(req.query.scope||'read:devices').split(' ').filter(s=>allowed.includes(s));res.send(layout('Zugriff erlauben',`<div class="card"><h1>Zugriff erlauben?</h1><p><b>${htmlEscape(client.client_name)}</b> fordert diese Rechte an:</p><ul>${scopes.map(s=>`<li>${htmlEscape(s)}</li>`).join('')}</ul><form method="post" action="/oauth/authorize"><input type="hidden" name="csrf" value="${req.session.csrf_token}">${['client_id','redirect_uri','state','code_challenge'].map(k=>`<input type="hidden" name="${k}" value="${htmlEscape(req.query[k])}">`).join('')}<input type="hidden" name="scope" value="${htmlEscape(scopes.join(' '))}"><button>Zugriff erlauben</button></form></div>`,req.user));});
app.post('/oauth/authorize',needLogin,csrf,async(req,res)=>{const code=randomToken(32),scopes=String(req.body.scope||'').split(' ').filter(Boolean);await db.query('INSERT INTO oauth_codes(code_hash,client_id,user_id,redirect_uri,scopes,code_challenge,expires_at) VALUES($1,$2,$3,$4,$5,$6,now()+interval \'5 minutes\')',[sha256(code),req.body.client_id,req.user.user_id,req.body.redirect_uri,scopes,req.body.code_challenge]);const url=new URL(req.body.redirect_uri);url.searchParams.set('code',code);if(req.body.state)url.searchParams.set('state',req.body.state);res.redirect(url.toString());});
app.post('/oauth/token',async(req,res)=>{if(req.body.grant_type!=='authorization_code')return res.status(400).json({error:'unsupported_grant_type'});const q=await db.query('SELECT * FROM oauth_codes WHERE code_hash=$1 AND client_id=$2 AND redirect_uri=$3 AND used_at IS NULL AND expires_at>now()',[sha256(req.body.code||''),req.body.client_id,req.body.redirect_uri]);const row=q.rows[0];const challenge=crypto.createHash('sha256').update(req.body.code_verifier||'').digest('base64url');if(!row||challenge!==row.code_challenge)return res.status(400).json({error:'invalid_grant'});await db.query('UPDATE oauth_codes SET used_at=now() WHERE code_hash=$1',[row.code_hash]);const raw=`ibmcp_${randomToken(36)}`;await db.query('INSERT INTO api_tokens(id,user_id,name,token_prefix,token_hash,scopes,expires_at) VALUES($1,$2,$3,$4,$5,$6,now()+interval \'30 days\')',[crypto.randomUUID(),row.user_id,'OAuth MCP',raw.slice(0,12),sha256(raw),row.scopes]);res.json({access_token:raw,token_type:'Bearer',expires_in:2592000,scope:row.scopes.join(' ')});});
app.post('/oauth/revoke',async(req,res)=>{if(req.body.token)await db.query('UPDATE api_tokens SET revoked_at=now() WHERE token_hash=$1',[sha256(req.body.token)]);res.sendStatus(200);});

app.use((err,req,res,_next)=>{console.error(JSON.stringify({level:'error',path:req.path,error:err.message}));res.status(err.status||500).json({error:{code:err.status===409?'conflict':'request_failed',message:err.status?err.message:'Interner Fehler'}});});
await schema();
app.listen(Number(env.APP_PORT||8080),'0.0.0.0',()=>console.log('ioBroker gateway app listening'));
