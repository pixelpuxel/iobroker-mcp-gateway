'use strict';

const utils = require('@iobroker/adapter-core');
const crypto = require('crypto');
const fs = require('fs');
const mqtt = require('mqtt');

class McpBridge extends utils.Adapter {
  constructor(options = {}) {
    super({ ...options, name: 'mcp-bridge' });
    this.client = null;
    this.catalog = new Map();
    this.byObjectId = new Map();
    this.rebuildTimer = null;
    this.prefix = 'iobroker/mcp/v1';
    this.on('ready', this.onReady.bind(this));
    this.on('stateChange', this.onStateChange.bind(this));
    this.on('objectChange', this.onObjectChange.bind(this));
    this.on('unload', this.onUnload.bind(this));
  }

  endpointId(id) {
    return `io-${crypto.createHash('sha256').update(id).digest('hex').slice(0, 24)}`;
  }

  match(pattern, id) {
    const escaped = String(pattern).replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
    return new RegExp(`^${escaped}$`).test(id);
  }

  included(id, obj) {
    const native = this.config;
    const excluded = (native.excludePatterns || []).some(p => this.match(p, id));
    if (excluded) return false;
    const explicit = (native.includePatterns || []).some(p => this.match(p, id));
    const smart = native.includeAllSmartNames !== false && obj?.common?.smartName;
    return Boolean(explicit || smart);
  }

  localized(value, fallback) {
    if (typeof value === 'string') return value;
    return value?.de || value?.en || fallback;
  }

  classify(common) {
    const smart = typeof common.smartName === 'object' ? common.smartName.smartType : '';
    const hint = `${smart || ''} ${common.role || ''}`.toLowerCase();
    if (/lock|door|garage|gate|alarm/.test(hint)) return 'security';
    if (/thermostat/.test(hint)) return 'thermostat';
    if (/temperature/.test(hint) && common.type === 'number') return 'temperature';
    if (/blind|shutter|level\.blind|button\.(open|close)\.blind/.test(hint)) return 'blind';
    if (/light/.test(hint)) return common.type === 'number' ? 'dimmer' : 'light';
    if (/dimmer|level\.dimmer/.test(hint)) return 'dimmer';
    if (/scene|activity|button/.test(hint)) return 'scene';
    if (common.type === 'boolean') return 'switch';
    if (common.type === 'number') return 'number';
    return 'value';
  }

  sensitive(id, name, kind) {
    return kind === 'security' || /tür|tuer|schloss|garage|tor|alarm|wasser|verschluss/i.test(`${id} ${name}`);
  }

  device(id, obj) {
    const common = obj.common || {};
    const rawSmart = this.localized(common.smartName, this.localized(common.name, id));
    const names = String(rawSmart).split(',').map(x => x.trim()).filter(Boolean);
    const name = names[0] || id.split('.').pop();
    const kind = this.classify(common);
    return {
      endpointId: this.endpointId(id),
      objectId: id,
      name,
      aliases: [...new Set([name, ...names])],
      kind,
      role: common.role || '',
      type: common.type || 'mixed',
      unit: common.unit || '',
      min: common.min,
      max: common.max,
      readable: common.read !== false,
      writable: common.write !== false,
      sensitive: this.sensitive(id, name, kind),
      updatedAt: new Date().toISOString()
    };
  }

  async rebuildCatalog() {
    const objects = await this.getForeignObjectsAsync('*', 'state');
    const next = new Map();
    const reverse = new Map();
    for (const [id, obj] of Object.entries(objects || {})) {
      if (!this.included(id, obj) || obj.common?.read === false) continue;
      const device = this.device(id, obj);
      next.set(device.endpointId, device);
      reverse.set(id, device);
    }
    const removed = [...this.catalog.keys()].filter(id => !next.has(id));
    this.catalog = next;
    this.byObjectId = reverse;
    for (const id of this.byObjectId.keys()) {
      try { await this.subscribeForeignStatesAsync(id); }
      catch (error) { this.log.warn(`Cannot subscribe ${id}: ${error.message}`); }
    }
    if (!this.client?.connected) return;
    for (const endpointId of removed) {
      this.client.publish(`${this.prefix}/catalog/${endpointId}`, '', { qos: 1, retain: true });
      this.client.publish(`${this.prefix}/state/${endpointId}`, '', { qos: 1, retain: true });
    }
    for (const device of this.catalog.values()) {
      this.publishJson(`catalog/${device.endpointId}`, device, true);
    }
    await this.publishAllStates();
    this.publishPresence(true);
    this.log.info(`MCP catalog published: ${this.catalog.size} states`);
  }

  publishJson(suffix, value, retain = false) {
    if (!this.client?.connected) return;
    this.client.publish(`${this.prefix}/${suffix}`, JSON.stringify(value), { qos: 1, retain });
  }

  publishPresence(online) {
    this.publishJson('presence/bridge', {
      online, catalogSize: this.catalog.size, instance: this.namespace, updatedAt: new Date().toISOString()
    }, true);
  }

  normalize(value, type) {
    if (type === 'boolean') return Boolean(value);
    if (type === 'number') return Number(value);
    return value;
  }

  async publishState(device, state) {
    if (!state) return;
    this.publishJson(`state/${device.endpointId}`, {
      endpointId: device.endpointId,
      objectId: device.objectId,
      value: this.normalize(state.val, device.type),
      ack: Boolean(state.ack),
      ts: state.ts,
      lc: state.lc,
      from: state.from,
      updatedAt: new Date().toISOString()
    }, true);
  }

  async publishAllStates() {
    for (const device of this.catalog.values()) {
      const state = await this.getForeignStateAsync(device.objectId);
      await this.publishState(device, state);
    }
  }

  convert(value, device) {
    if (device.type === 'boolean') {
      if (typeof value === 'boolean') return value;
      const text = String(value).toLowerCase();
      if (['1', 'true', 'on', 'an', 'ein', 'open', 'auf'].includes(text)) return true;
      if (['0', 'false', 'off', 'aus', 'close', 'zu'].includes(text)) return false;
      throw new Error('Ungültiger Boolescher Wert');
    }
    if (device.type === 'number') {
      const number = Number(value);
      if (!Number.isFinite(number)) throw new Error('Ungültiger Zahlenwert');
      if (device.min !== undefined && number < device.min) throw new Error(`Wert kleiner als ${device.min}`);
      if (device.max !== undefined && number > device.max) throw new Error(`Wert größer als ${device.max}`);
      return number;
    }
    return value;
  }

  async command(topic, payload) {
    const endpointId = topic.slice(`${this.prefix}/command/`.length);
    const device = this.catalog.get(endpointId);
    let request = {};
    try { request = JSON.parse(payload.toString('utf8')); } catch { request = {}; }
    const requestId = request.requestId || crypto.randomUUID();
    const result = { requestId, endpointId, objectId: device?.objectId, ok: false, updatedAt: new Date().toISOString() };
    try {
      if (!device) throw new Error('Unbekannter Datenpunkt');
      if (!device.writable) throw new Error('Datenpunkt ist schreibgeschützt');
      if (device.sensitive && request.confirmSensitive !== true) throw new Error('Sicherheitskritischer Datenpunkt erfordert Bestätigung');
      const value = device.kind === 'scene' && request.value === undefined ? true : this.convert(request.value, device);
      await this.setForeignStateAsync(device.objectId, value, false);
      result.ok = true;
      result.value = value;
    } catch (error) {
      result.error = error.message;
    }
    this.publishJson(`result/${requestId}`, result, false);
  }

  async onReady() {
    this.prefix = String(this.config.topicPrefix || 'iobroker/mcp/v1').replace(/\/$/, '');
    const password = fs.readFileSync(this.config.secretFile, 'utf8').trim();
    this.client = mqtt.connect(this.config.mqttUrl, {
      username: this.config.mqttUsername,
      password,
      ca: fs.readFileSync(this.config.caFile),
      clientId: `iobroker-mcp-${this.host}-${this.instance}`.replace(/[^a-zA-Z0-9_-]/g, '-'),
      rejectUnauthorized: this.config.allowInvalidCertificate !== true,
      clean: true,
      reconnectPeriod: 5000,
      will: { topic: `${this.prefix}/presence/bridge`, payload: JSON.stringify({ online: false }), qos: 1, retain: true }
    });
    this.client.on('connect', async () => {
      this.log.info('Connected to MCP MQTT broker');
      this.client.subscribe(`${this.prefix}/command/+`, { qos: 1 });
      await this.rebuildCatalog();
    });
    this.client.on('message', (topic, payload) => this.command(topic, payload));
    this.client.on('error', error => this.log.warn(`MQTT: ${error.message}`));
    await this.subscribeForeignObjectsAsync('*');
  }

  onStateChange(id, state) {
    const device = this.byObjectId.get(id);
    if (device && state) this.publishState(device, state);
  }

  onObjectChange() {
    clearTimeout(this.rebuildTimer);
    this.rebuildTimer = setTimeout(() => this.rebuildCatalog().catch(error => this.log.error(error.message)), 1500);
  }

  onUnload(callback) {
    try {
      clearTimeout(this.rebuildTimer);
      if (this.client) {
        this.publishPresence(false);
        this.client.end(true, {}, callback);
      } else callback();
    } catch { callback(); }
  }
}

if (module.parent) module.exports = options => new McpBridge(options);
else new McpBridge();
