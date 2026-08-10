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
    this.persistTimer = null;
    this.persistingMappings = false;
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
    const mapping = this.mappingFor(id);
    if (mapping) return mapping.enabled !== false;
    if ((native.knownObjectIds || []).includes(id)) return false;
    const parse = value => String(value || '').split(/[\n,]+/).map(x => x.trim()).filter(Boolean);
    const excludes = [...(native.excludePatterns || []), ...parse(native.excludePatternsText)];
    const includes = [...(native.includePatterns || []), ...parse(native.includePatternsText)];
    const excluded = [...new Set(excludes)].some(p => this.match(p, id));
    if (excluded) return false;
    const explicit = [...new Set(includes)].some(p => this.match(p, id));
    const smart = native.includeAllSmartNames !== false && obj?.common?.smartName;
    return Boolean(explicit || smart);
  }

  mappingFor(id) {
    return (this.config.deviceMappings || []).find(entry => entry && entry.objectId === id);
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
    const mapping = this.mappingFor(id) || {};
    const kind = mapping.kind && mapping.kind !== 'auto' ? mapping.kind : this.classify(common);
    const mappedName = String(mapping.name || '').trim();
    const mappedAliases = String(mapping.aliases || '').split(',').map(x => x.trim()).filter(Boolean);
    const writable = mapping.access === 'read' ? false : mapping.access === 'write' ? true : common.write !== false;
    const detectedSensitive = this.sensitive(id, mappedName || name, kind);
    return {
      endpointId: this.endpointId(id),
      objectId: id,
      name: mappedName || name,
      aliases: [...new Set([mappedName || name, ...names, ...mappedAliases])],
      kind,
      role: common.role || '',
      type: common.type || 'mixed',
      unit: common.unit || '',
      min: common.min,
      max: common.max,
      readable: common.read !== false,
      writable,
      sensitive: mapping.sensitive === 'yes' ? true : mapping.sensitive === 'no' ? false : detectedSensitive,
      room: String(mapping.room || '').trim(),
      description: String(mapping.description || '').trim(),
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
    await this.persistDiscoveredMappings(next);
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
    await this.setStateAsync('info.catalogSize', { val: this.catalog.size, ack: true });
    this.log.info(`MCP catalog published: ${this.catalog.size} states`);
  }

  async persistDiscoveredMappings(next) {
    if (this.persistingMappings || this.config.manageMappings === false) return;
    const existing = Array.isArray(this.config.deviceMappings) ? this.config.deviceMappings : [];
    const previouslyKnown = Array.isArray(this.config.knownObjectIds) ? this.config.knownObjectIds : [];
    const known = new Set([...previouslyKnown, ...existing.map(entry => entry?.objectId).filter(Boolean)]);
    const additions = [...next.values()].filter(device => !known.has(device.objectId)).map(device => ({
      objectId: device.objectId,
      enabled: true,
      name: device.name,
      kind: 'auto',
      access: 'auto',
      sensitive: 'auto',
      room: '',
      aliases: '',
      description: ''
    }));
    const nextKnown = [...new Set([...known, ...additions.map(entry => entry.objectId)])].sort();
    if (!additions.length && nextKnown.length === previouslyKnown.length) return;
    this.persistingMappings = true;
    try {
      const instanceId = `system.adapter.${this.namespace}`;
      const instance = await this.getForeignObjectAsync(instanceId);
      if (!instance) return;
      instance.native = instance.native || {};
      instance.native.deviceMappings = [...existing, ...additions].sort((a, b) => a.objectId.localeCompare(b.objectId));
      instance.native.knownObjectIds = nextKnown;
      await this.setForeignObjectAsync(instanceId, instance);
      this.config.deviceMappings = instance.native.deviceMappings;
      this.config.knownObjectIds = nextKnown;
      if (additions.length) this.log.info(`Added ${additions.length} discovered states to the configurable MCP mapping table`);
    } catch (error) {
      this.log.warn(`Could not persist discovered MCP mappings: ${error.message}`);
    } finally {
      this.persistingMappings = false;
    }
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
    if (type === 'nused: --mber') return Number(value);
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
    await this.setStateAsync('info.connection', { val: false, ack: true });
    await this.setStateAsync('info.lastError', { val: '', ack: true });
    let password = String(this.config.mqttPassword || '');
    if (!password && this.config.secretFile) password = fs.readFileSync(this.config.secretFile, 'utf8').trim();
    if (!password) throw new Error('Kein MQTT-Passwort konfiguriert');
    const mqttOptions = {
      username: this.config.mqttUsername,
      password,
      clientId: `iobroker-mcp-${this.host}-${this.instance}`.replace(/[^a-zA-Z0-9_-]/g, '-'),
      rejectUnauthorized: this.config.allowInvalidCertificate !== true,
      clean: true,
      reconnectPeriod: 5000,
      will: { topic: `${this.prefix}/presence/bridge`, payload: JSON.stringify({ online: false }), qos: 1, retain: true }
    };
    if (this.config.caFile) mqttOptions.ca = fs.readFileSync(this.config.caFile);
    this.client = mqtt.connect(this.config.mqttUrl, mqttOptions);
    this.client.on('connect', async () => {
      this.log.info('Connected to MCP MQTT broker');
      await this.setStateAsync('info.connection', { val: true, ack: true });
      await this.setStateAsync('info.lastError', { val: '', ack: true });
      this.client.subscribe(`${this.prefix}/command/+`, { qos: 1 });
      await this.rebuildCatalog();
    });
    this.client.on('close', () => this.setState('info.connection', false, true));
    this.client.on('message', (topic, payload) => this.command(topic, payload));
    this.client.on('error', error => {
      this.log.warn(`MQTT: ${error.message}`);
      this.setState('info.connection', false, true);
      this.setState('info.lastError', error.message, true);
    });
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
      clearTimeout(this.persistTimer);
      if (this.client) {
        this.publishPresence(false);
        this.client.end(true, {}, callback);
      } else callback();
    } catch { callback(); }
  }
}

if (module.parent) module.exports = options => new McpBridge(options);
else new McpBridge();
: No such file or directory
