'use strict';
// AI assistants for the site box: an MCP server (Streamable HTTP, JSON-RPC over
// POST /mcp) that Claude, ChatGPT, Claude Code or Codex can connect to, with a
// sign-in like Novant's: the assistant opens the box's Allow page, the person
// types the setup-page password and clicks Allow, and the box issues it a
// revocable token (OAuth 2.1: dynamic client registration, PKCE, refresh).
//
// What an assistant can do depends on the box setting `assist.mode`:
//   off   nothing (sign-in refused, tokens stop working)
//   read  read everything the box knows: devices, points, live values, trends, health
//   edit  also propose changes (trend on/off, intervals, labels, notes, a scan);
//         every change is shown first and applied only after the assistant
//         confirms; an invalid batch is never partly applied; all of it is in
//         the audit log.
// Nothing here ever writes to a BAS device: the box has no such code path.
const crypto = require('node:crypto');
const { checkPw } = require('./web');

const PROTOCOLS = ['2025-06-18', '2025-03-26', '2024-11-05'];
const PROPOSAL_TTL = 15 * 60000;
const CODE_TTL = 5 * 60000;

const b64url = buf => Buffer.from(buf).toString('base64url');
const sha256 = s => crypto.createHash('sha256').update(s).digest('hex');
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

class Assist {
  constructor(app) {
    this.app = app;
    this.codes = new Map();      // auth codes waiting for the token call
    this.proposals = new Map();  // changes shown to an assistant, waiting for its confirm
    this.fails = [];
  }
  get store() { return this.app.store; }
  settings() { return this.app.config.get().assist || { mode: 'edit', token_days: 90 }; }
  mode() { const m = this.settings().mode; return ['off', 'read', 'edit'].includes(m) ? m : 'edit'; }

  // The box's own address as the assistant sees it (behind a proxy: the forwarded one).
  base(req) {
    const proto = (req.headers['x-forwarded-proto'] || '').split(',')[0].trim() || 'http';
    const host = (req.headers['x-forwarded-host'] || req.headers.host || 'box').split(',')[0].trim();
    const s = this.app.config.get().web || {};
    return (s.public_url ? String(s.public_url).replace(/\/+$/, '') : `${proto}://${host}`);
  }

  // ---------------------------------------------------------------- routing
  async handle(req, res, url) {
    const p = url.pathname;
    if (p === '/.well-known/oauth-authorization-server' || p.startsWith('/.well-known/oauth-authorization-server/')) return this.metaAuth(req, res);
    if (p === '/.well-known/oauth-protected-resource' || p.startsWith('/.well-known/oauth-protected-resource/')) return this.metaResource(req, res);
    if (p === '/oauth/register' && req.method === 'POST') return this.register(req, res);
    if (p === '/oauth/authorize') return req.method === 'POST' ? this.authorizePost(req, res, url) : this.authorizeGet(req, res, url);
    if (p === '/oauth/token' && req.method === 'POST') return this.token(req, res);
    if (p === '/oauth/revoke' && req.method === 'POST') return this.revoke(req, res);
    if (p === '/mcp') return this.mcp(req, res);
    return false;
  }
  json(res, code, obj, extra = {}) {
    res.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store', 'access-control-allow-origin': '*', ...extra });
    res.end(JSON.stringify(obj));
  }
  html(res, code, body) {
    res.writeHead(code, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-frame-options': 'DENY', 'content-security-policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:" });
    res.end(body);
  }
  readBody(req, limit = 1e6) {
    return new Promise((resolve, reject) => {
      let n = 0; const chunks = [];
      req.on('data', c => { n += c.length; if (n > limit) { reject(new Error('too big')); req.destroy(); } else chunks.push(c); });
      req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      req.on('error', reject);
    });
  }
  async readJson(req) { const t = await this.readBody(req); try { return t ? JSON.parse(t) : {}; } catch { return null; } }
  async readForm(req) {
    const t = await this.readBody(req);
    const ct = String(req.headers['content-type'] || '');
    if (ct.includes('application/json')) { try { return JSON.parse(t); } catch { return {}; } }
    return Object.fromEntries(new URLSearchParams(t));
  }

  // ------------------------------------------------------------ OAuth 2.1
  metaAuth(req, res) {
    const b = this.base(req);
    return this.json(res, 200, {
      issuer: b, authorization_endpoint: `${b}/oauth/authorize`, token_endpoint: `${b}/oauth/token`,
      registration_endpoint: `${b}/oauth/register`, revocation_endpoint: `${b}/oauth/revoke`,
      response_types_supported: ['code'], grant_types_supported: ['authorization_code', 'refresh_token'],
      code_challenge_methods_supported: ['S256'], token_endpoint_auth_methods_supported: ['none'],
      scopes_supported: ['read', 'edit'], service_documentation: `${b}/#assistants`,
    });
  }
  metaResource(req, res) {
    const b = this.base(req);
    return this.json(res, 200, { resource: `${b}/mcp`, authorization_servers: [b], scopes_supported: ['read', 'edit'], bearer_methods_supported: ['header'], resource_name: `${this.app.config.get().name} (HEAPY Edge)` });
  }
  async register(req, res) {
    if (this.mode() === 'off') return this.json(res, 403, { error: 'access_denied', error_description: 'AI assistants are turned off on this box.' });
    const b = await this.readJson(req);
    if (!b) return this.json(res, 400, { error: 'invalid_client_metadata' });
    const uris = Array.isArray(b.redirect_uris) ? b.redirect_uris.filter(u => typeof u === 'string' && /^(https:\/\/|http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?(\/|$))/.test(u)) : [];
    if (!uris.length) return this.json(res, 400, { error: 'invalid_redirect_uri', error_description: 'redirect_uris must be https, or http on localhost' });
    const c = { id: 'edge-' + b64url(crypto.randomBytes(12)), name: String(b.client_name || 'AI assistant').slice(0, 80), redirect_uris: uris.slice(0, 10) };
    this.store.addAssistClient(c);
    this.app.log('info', `AI assistant registered: ${c.name}`);
    return this.json(res, 201, { client_id: c.id, client_name: c.name, redirect_uris: c.redirect_uris, token_endpoint_auth_method: 'none', grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], client_id_issued_at: Math.floor(Date.now() / 1000) });
  }
  authParams(q) {
    const client = q.client_id && this.store.assistClient(q.client_id);
    const redirect = q.redirect_uri;
    if (!client) return { error: 'This assistant is not registered with the box. Add the connector again.' };
    if (!redirect || !client.redirect_uris.includes(redirect)) return { error: 'The assistant asked to be sent back to an address it did not register.' };
    if (q.response_type !== 'code') return { client, redirect, error: 'unsupported_response_type' };
    if (!q.code_challenge || (q.code_challenge_method || 'S256') !== 'S256') return { client, redirect, error: 'PKCE (S256) is required.' };
    const scope = String(q.scope || 'read edit').split(/[\s+]+/).filter(s => ['read', 'edit'].includes(s));
    return { client, redirect, scope: scope.length ? scope : ['read', 'edit'], challenge: q.code_challenge, state: q.state || '' };
  }
  authorizeGet(req, res, url) {
    const q = Object.fromEntries(url.searchParams);
    const a = this.authParams(q);
    if (a.error && !a.redirect) return this.html(res, 400, this.page('Cannot sign in', `<p class="err">${esc(a.error)}</p>`));
    if (a.error) return this.back(res, a.redirect, { error: 'invalid_request', error_description: a.error, state: q.state });
    if (this.mode() === 'off') return this.html(res, 403, this.page('AI assistants are off', '<p>AI assistants are turned off on this box. Turn them on under Settings → AI assistants on the setup page, then try again.</p>'));
    return this.html(res, 200, this.consentPage(q, a, ''));
  }
  async authorizePost(req, res, url) {
    const q = { ...Object.fromEntries(url.searchParams), ...(await this.readForm(req)) };
    const a = this.authParams(q);
    if (a.error && !a.redirect) return this.html(res, 400, this.page('Cannot sign in', `<p class="err">${esc(a.error)}</p>`));
    if (a.error) return this.back(res, a.redirect, { error: 'invalid_request', error_description: a.error, state: q.state });
    if (q.decision !== 'allow') return this.back(res, a.redirect, { error: 'access_denied', state: a.state });
    if (this.mode() === 'off') return this.back(res, a.redirect, { error: 'access_denied', error_description: 'AI assistants are turned off on this box', state: a.state });
    const now = Date.now();
    this.fails = this.fails.filter(t => t > now - 15 * 60000);
    if (this.fails.length >= 10) return this.html(res, 429, this.consentPage(q, a, 'Too many tries. Wait 15 minutes.'));
    const secret = this.app.config.secret();
    if (!secret.admin_hash) return this.html(res, 409, this.consentPage(q, a, 'Set the setup page password first (open the setup page).'));
    if (!checkPw(String(q.password || ''), secret.admin_hash)) { this.fails.push(now); return this.html(res, 401, this.consentPage(q, a, 'Wrong password.')); }
    const scope = this.mode() === 'read' ? ['read'] : a.scope;
    const code = b64url(crypto.randomBytes(24));
    this.codes.set(code, { client_id: a.client.id, redirect: a.redirect, challenge: a.challenge, scope, exp: now + CODE_TTL });
    for (const [k, v] of this.codes) if (v.exp < now) this.codes.delete(k);
    this.store.audit('setup page', 'assistant allowed', { assistant: a.client.name, scope });
    this.app.log('info', `AI assistant allowed: ${a.client.name} (${scope.join(' ')})`);
    return this.back(res, a.redirect, { code, state: a.state });
  }
  back(res, redirect, params) {
    const u = new URL(redirect);
    for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== '') u.searchParams.set(k, v);
    res.writeHead(302, { location: u.toString(), 'cache-control': 'no-store' });
    res.end();
  }
  async token(req, res) {
    const b = await this.readForm(req);
    const now = Date.now();
    const days = Math.max(1, Number(this.settings().token_days) || 90);
    const issue = (client_id, scope) => {
      const access = 'edg_' + b64url(crypto.randomBytes(32)), refresh = 'edr_' + b64url(crypto.randomBytes(32));
      this.store.addAssistToken({ hash: sha256(access), client_id, kind: 'access', scope: scope.join(' '), expires: now + days * 86400000 });
      this.store.addAssistToken({ hash: sha256(refresh), client_id, kind: 'refresh', scope: scope.join(' '), expires: now + 2 * days * 86400000 });
      this.store.pruneAssistTokens();
      return this.json(res, 200, { access_token: access, token_type: 'Bearer', expires_in: days * 86400, refresh_token: refresh, scope: scope.join(' ') });
    };
    if (this.mode() === 'off') return this.json(res, 400, { error: 'invalid_grant', error_description: 'AI assistants are turned off on this box' });
    if (b.grant_type === 'authorization_code') {
      const c = this.codes.get(b.code);
      this.codes.delete(b.code); // one use only
      if (!c || c.exp < now) return this.json(res, 400, { error: 'invalid_grant', error_description: 'code unknown or expired' });
      if (b.client_id && b.client_id !== c.client_id) return this.json(res, 400, { error: 'invalid_grant', error_description: 'client mismatch' });
      if (b.redirect_uri && b.redirect_uri !== c.redirect) return this.json(res, 400, { error: 'invalid_grant', error_description: 'redirect mismatch' });
      if (!b.code_verifier || b64url(crypto.createHash('sha256').update(b.code_verifier).digest()) !== c.challenge) return this.json(res, 400, { error: 'invalid_grant', error_description: 'PKCE check failed' });
      return issue(c.client_id, c.scope);
    }
    if (b.grant_type === 'refresh_token') {
      const t = b.refresh_token && this.store.assistToken(sha256(b.refresh_token));
      if (!t || t.kind !== 'refresh' || t.expires < now) return this.json(res, 400, { error: 'invalid_grant', error_description: 'refresh token unknown or expired' });
      if (b.client_id && b.client_id !== t.client_id) return this.json(res, 400, { error: 'invalid_grant' });
      this.store.deleteAssistToken(t.hash);
      let scope = String(t.scope || 'read').split(' ');
      if (this.mode() === 'read') scope = ['read'];
      return issue(t.client_id, scope);
    }
    return this.json(res, 400, { error: 'unsupported_grant_type' });
  }
  async revoke(req, res) {
    const b = await this.readForm(req);
    if (b.token) this.store.deleteAssistToken(sha256(String(b.token)));
    return this.json(res, 200, {});
  }
  // Who is calling /mcp? null = not signed in.
  bearer(req) {
    const m = /^Bearer\s+(\S+)$/i.exec(req.headers.authorization || '');
    if (!m) return null;
    const t = this.store.assistToken(sha256(m[1]));
    if (!t || t.kind !== 'access' || t.expires < Date.now()) return null;
    this.store.touchAssistToken(t.hash);
    const client = this.store.assistClient(t.client_id);
    return { client, scope: String(t.scope || 'read').split(' ') };
  }

  // ------------------------------------------------------------------ pages
  page(title, body) {
    const name = esc(this.app.config.get().name);
    return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} · ${name}</title>
<link rel="stylesheet" href="/brand.css"><link rel="stylesheet" href="/app.css"></head><body>
<header class="hp-band"><div class="hp-logo"><img alt="HEAPY" src="/logo.png"></div><div class="hp-band__title"><h1 class="hp-title"><span>HEAPY Edge</span><span>${name}</span></h1></div></header>
<div class="login"><div class="hp-card"><div class="hp-card__head">${esc(title)}</div><div class="hp-card__body">${body}</div></div></div>
<footer class="hp-footer"><span class="hp-slashes"></span><span>HEAPY Edge · read-only BAS data collection</span></footer></body></html>`;
  }
  consentPage(q, a, err) {
    const host = (() => { try { return new URL(a.redirect).host; } catch { return a.redirect; } })();
    const hidden = ['response_type', 'client_id', 'redirect_uri', 'code_challenge', 'code_challenge_method', 'state', 'scope', 'resource']
      .filter(k => q[k] !== undefined).map(k => `<input type="hidden" name="${k}" value="${esc(q[k])}">`).join('');
    const can = this.mode() === 'read' || !a.scope.includes('edit')
      ? 'read devices, points, live values, trends and box health'
      : 'read devices, points, live values, trends and box health, and propose changes to what is trended (trend on/off, intervals, labels, notes). Each change is shown first and applied only after it is confirmed; nothing is ever written to a BAS device.';
    return this.page('Allow an AI assistant?', `
<p><b>${esc(a.client.name)}</b> wants to connect to this box as you. It will be sent back to <span class="hp-num">${esc(host)}</span>.</p>
<p class="small">With your permission it can ${can} Everything it changes appears in the audit log. You can disconnect it any time under Settings → AI assistants.</p>
<form method="post" action="/oauth/authorize">${hidden}
<label class="hp-label" for="pw">Setup page password</label>
<input class="hp-input wide" id="pw" name="password" type="password" autocomplete="current-password" required autofocus>
<p class="err">${esc(err)}</p>
<button class="hp-btn hp-btn--primary" type="submit" name="decision" value="allow">Allow</button>
<button class="hp-btn" type="submit" name="decision" value="deny" formnovalidate>Deny</button>
</form>`);
  }

  // -------------------------------------------------------------------- MCP
  async mcp(req, res) {
    const b = this.base(req);
    const chal = { 'www-authenticate': `Bearer resource_metadata="${b}/.well-known/oauth-protected-resource"` };
    if (req.method === 'OPTIONS') { res.writeHead(204, { 'access-control-allow-origin': '*', 'access-control-allow-methods': 'POST, GET, DELETE, OPTIONS', 'access-control-allow-headers': 'authorization, content-type, mcp-protocol-version, mcp-session-id' }); return res.end(); }
    if (req.method === 'DELETE') return this.json(res, 200, {});
    if (req.method !== 'POST') return this.json(res, 405, { error: 'POST JSON-RPC here; this box does not stream' }, { allow: 'POST, DELETE' });
    if (this.mode() === 'off') return this.json(res, 403, { error: 'AI assistants are turned off on this box' });
    const who = this.bearer(req);
    if (!who) return this.json(res, 401, { error: 'sign in first' }, chal);
    const body = await this.readJson(req);
    if (!body) return this.json(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'bad JSON' } });
    const msgs = Array.isArray(body) ? body : [body];
    const out = [];
    for (const m of msgs) {
      if (!m || m.jsonrpc !== '2.0' || typeof m.method !== 'string') { out.push({ jsonrpc: '2.0', id: m && m.id !== undefined ? m.id : null, error: { code: -32600, message: 'bad request' } }); continue; }
      if (m.id === undefined) { this.notify(m); continue; }  // notification: no answer
      try { out.push({ jsonrpc: '2.0', id: m.id, result: await this.rpc(m, who) }); }
      catch (e) { out.push({ jsonrpc: '2.0', id: m.id, error: { code: e.code || -32603, message: e.message } }); }
    }
    if (!out.length) { res.writeHead(202, { 'access-control-allow-origin': '*' }); return res.end(); }
    return this.json(res, 200, Array.isArray(body) ? out : out[0]);
  }
  notify() { /* initialized, cancelled: nothing to do */ }
  async rpc(m, who) {
    const p = m.params || {};
    switch (m.method) {
      case 'initialize': {
        const v = PROTOCOLS.includes(p.protocolVersion) ? p.protocolVersion : PROTOCOLS[0];
        return { protocolVersion: v, capabilities: { tools: { listChanged: false } }, serverInfo: { name: 'HEAPY Edge', title: `${this.app.config.get().name} (HEAPY Edge site box)`, version: this.app.version }, instructions: this.instructions(who) };
      }
      case 'ping': return {};
      case 'tools/list': return { tools: this.tools(who).map(({ name, title, description, inputSchema }) => ({ name, title, description, inputSchema })) };
      case 'tools/call': {
        const t = this.tools(who).find(x => x.name === p.name);
        if (!t) throw Object.assign(new Error(`unknown tool ${p.name}`), { code: -32602 });
        try {
          const r = await t.run(p.arguments || {}, who);
          return { content: [{ type: 'text', text: typeof r === 'string' ? r : JSON.stringify(r, null, 1) }], structuredContent: typeof r === 'object' ? r : undefined, isError: false };
        } catch (e) {
          return { content: [{ type: 'text', text: e.message }], isError: true };
        }
      }
      case 'resources/list': return { resources: [] };
      case 'prompts/list': return { prompts: [] };
      default: throw Object.assign(new Error(`method not found: ${m.method}`), { code: -32601 });
    }
  }
  canEdit(who) { return this.mode() === 'edit' && who.scope.includes('edit'); }
  instructions(who) {
    const c = this.app.config.get();
    return `This is ${c.name}, a HEAPY Edge site box: an on-site collector that reads a building automation system (BAS) read-only and buffers the readings. ` +
      `Point keys look like bacnet://1201/analog-input:5 or modbus://meter-1/holding:40001. Times are Unix milliseconds unless stated. ` +
      (this.canEdit(who)
        ? 'You may propose changes (trend on/off, intervals, labels, notes, a scan) with propose_changes; show the proposal to the person, and call apply_changes only after they confirm. '
        : 'This connection is read-only. ') +
      'The box never writes to BAS equipment, so setpoints, schedules and overrides cannot be changed from here.';
  }

  // ------------------------------------------------------------------ tools
  tools(who) {
    const S = this.store, app = this.app;
    const dev = d => ({ id: d.id, key: d.key, name: d.label || d.name, bas_name: d.name, label: d.label || null, driver: d.driver, address: d.route, vendor: d.vendor, model: d.model, status: d.status, last_seen: d.last_seen, last_error: d.last_error || null });
    const pt = (p, dkey) => ({ key: p.key, device: dkey, name: p.label || p.name, bas_name: p.name, label: p.label || null, description: p.description || '', units: p.units || null, states: p.states || null, kind: p.kind,
      trended: !!p.selected, interval_s: p.interval_s, cov: !!p.cov_active, notes: p.notes || null, last_value: p.last_v ?? null, last_time: p.last_t ?? null, last_error: p.last_error || null, missing: !!p.missing });
    const devMap = () => new Map(S.devices().map(d => [d.id, d]));
    const limit = (n, d = 200, max = 2000) => Math.min(max, Math.max(1, Number(n) || d));
    const match = (text, ...fields) => !text || fields.some(f => String(f || '').toLowerCase().includes(text));
    const read = [
      { name: 'box_status', title: 'Box status', description: 'Name, version, health (uptime, backlog, devices offline, late points, disk, last error), drivers and the link to HEAPY Atlas for this site box.',
        inputSchema: { type: 'object', properties: {} },
        run: () => { const s = app.status(); return { name: s.name, version: s.version, host: s.host, started: s.started, health: s.health, drivers: s.drivers, scan: s.scan, link: { paired: s.link.paired, site: s.link.site, server: s.link.server, last_checkin: s.link.last_checkin || null }, assistants_mode: this.mode() }; } },
      { name: 'list_devices', title: 'List devices', description: 'BAS devices the box has found. Filter by text (name, key, vendor, model, address), driver (bacnet-ip, bacnet-mstp, modbus, snmp, haystack, obix) or status (online, offline, error, new).',
        inputSchema: { type: 'object', properties: { search: { type: 'string' }, driver: { type: 'string' }, status: { type: 'string' }, limit: { type: 'integer', default: 200 } } },
        run: a => {
          const q = String(a.search || '').toLowerCase();
          const counts = new Map(S.db.prepare('SELECT device_id d, count(*) n, sum(selected) s FROM points WHERE missing=0 GROUP BY device_id').all().map(r => [r.d, r]));
          const all = S.devices().filter(d => (!a.driver || d.driver === a.driver) && (!a.status || d.status === a.status) && match(q, d.name, d.label, d.key, d.vendor, d.model, d.route));
          return { total: all.length, devices: all.slice(0, limit(a.limit)).map(d => ({ ...dev(d), points: counts.get(d.id)?.n || 0, trended: counts.get(d.id)?.s || 0 })) };
        } },
      { name: 'list_points', title: 'List points', description: 'Points of a device (by key or id) or across the box, with their latest value. Filter by text (name, description, key), trended_only, or has_error. Use offset/limit to page.',
        inputSchema: { type: 'object', properties: { device: { type: 'string', description: 'device key or id; omit for all devices' }, search: { type: 'string' }, trended_only: { type: 'boolean' }, has_error: { type: 'boolean' }, limit: { type: 'integer', default: 200 }, offset: { type: 'integer', default: 0 } } },
        run: a => {
          const dm = devMap();
          let d = null;
          if (a.device !== undefined && a.device !== null && a.device !== '') { d = S.device(String(a.device)) || S.deviceById(Number(a.device)); if (!d) throw new Error(`no device ${a.device}`); }
          const q = String(a.search || '').toLowerCase();
          const all = S.points(d ? d.id : undefined).filter(p => !p.missing && (!a.trended_only || p.selected) && (!a.has_error || p.last_error) && match(q, p.name, p.label, p.description, p.key));
          const off = Math.max(0, Number(a.offset) || 0);
          return { total: all.length, offset: off, points: all.slice(off, off + limit(a.limit)).map(p => pt(p, dm.get(p.device_id)?.key)) };
        } },
      { name: 'get_values', title: 'Current values', description: 'Latest reading of named points (by key) or of every trended point on a device, with how old each reading is in seconds.',
        inputSchema: { type: 'object', properties: { points: { type: 'array', items: { type: 'string' } }, device: { type: 'string' }, search: { type: 'string' } } },
        run: a => {
          const dm = devMap(); const now = Date.now();
          let list = [];
          if (Array.isArray(a.points) && a.points.length) list = a.points.map(k => S.pointByKey(String(k)) || { key: k, missing: 1, not_found: true });
          else if (a.device) { const d = S.device(String(a.device)) || S.deviceById(Number(a.device)); if (!d) throw new Error(`no device ${a.device}`); list = S.points(d.id).filter(p => !p.missing && p.selected); }
          else if (a.search) { const q = String(a.search).toLowerCase(); list = S.points().filter(p => !p.missing && match(q, p.name, p.label, p.description, p.key)).slice(0, 500); }
          else throw new Error('give points, a device or a search');
          return { values: list.map(p => p.not_found ? { key: p.key, error: 'not found' } : { key: p.key, name: p.label || p.name, device: dm.get(p.device_id)?.key, value: p.last_v ?? null, units: p.units || null, states: p.states || null, time: p.last_t ?? null, age_s: p.last_t ? Math.round((now - p.last_t) / 1000) : null, error: p.last_error || null, trended: !!p.selected }) };
        } },
      { name: 'get_trend', title: 'Trend data', description: 'Readings of one point between two times from the box buffer (the box keeps about 30 days). from/to accept ISO dates or Unix ms; defaults to the last 24 hours. Long ranges are thinned to max_points by keeping every n-th reading.',
        inputSchema: { type: 'object', properties: { point: { type: 'string' }, from: { type: ['string', 'number'] }, to: { type: ['string', 'number'] }, max_points: { type: 'integer', default: 500 } }, required: ['point'] },
        run: a => {
          const p = S.pointByKey(String(a.point)); if (!p) throw new Error(`no point ${a.point}`);
          const t = x => x === undefined || x === null || x === '' ? null : (typeof x === 'number' ? x : (isNaN(Number(x)) ? Date.parse(x) : Number(x)));
          const to = t(a.to) ?? Date.now(), from = t(a.from) ?? to - 86400000;
          if (isNaN(from) || isNaN(to) || from > to) throw new Error('bad time range');
          const c = S.sampleCount(p.id, from, to);
          const max = limit(a.max_points, 500, 5000);
          let rows = S.samplesOf(p.id, from, to, 200000);
          const step = Math.ceil(rows.length / max);
          if (step > 1) rows = rows.filter((_, i) => i % step === 0);
          return { point: p.key, name: p.label || p.name, units: p.units || null, states: p.states || null, from, to, readings_in_range: c.n, returned: rows.length, thinned_every: step, samples: rows.map(r => [r.t, r.v]) };
        } },
      { name: 'search', title: 'Search', description: 'Find devices and points whose name, label, description or key contains the text.',
        inputSchema: { type: 'object', properties: { text: { type: 'string' }, limit: { type: 'integer', default: 50 } }, required: ['text'] },
        run: a => {
          const q = String(a.text || '').toLowerCase(); if (!q) throw new Error('give text');
          const dm = devMap(); const n = limit(a.limit, 50, 500);
          return { devices: S.devices().filter(d => match(q, d.name, d.label, d.key, d.vendor, d.model, d.route)).slice(0, n).map(dev),
            points: S.points().filter(p => !p.missing && match(q, p.name, p.label, p.description, p.key)).slice(0, n).map(p => pt(p, dm.get(p.device_id)?.key)) };
        } },
      { name: 'get_settings', title: 'Box settings', description: 'The box settings as shown on the setup page (passwords and keys masked): scan windows, polling, upload, buffer, connections.',
        inputSchema: { type: 'object', properties: {} }, run: () => app.publicSettings() },
      { name: 'audit_log', title: 'Audit log', description: 'Changes made on this box and who made them (setup page, HEAPY Atlas, or an AI assistant), newest first.',
        inputSchema: { type: 'object', properties: { limit: { type: 'integer', default: 50 } } }, run: a => ({ entries: S.auditLog(limit(a.limit, 50, 1000)) }) },
      { name: 'box_log', title: 'Box log', description: 'Recent lines of the box log (warnings, errors, scans, driver restarts).',
        inputSchema: { type: 'object', properties: { limit: { type: 'integer', default: 100 }, level: { type: 'string', description: 'info, warn or error' } } },
        run: a => ({ lines: app.logs.filter(l => !a.level || l.level === a.level).slice(-limit(a.limit, 100, 1000)) }) },
    ];
    if (!this.canEdit(who)) return read;
    const edit = [
      { name: 'propose_changes', title: 'Propose changes', description: 'Propose changes to what the box trends. Each change names a point (by key) or a device (by key) and sets any of: trended (true/false), interval_s (10 to 86400), label (a friendlier name; empty clears it), notes. Devices take label only. Or pass scan: true to propose a device scan. Nothing is applied: the box checks every change, returns a proposal with before/after for the person to confirm, and apply_changes applies it. An invalid batch is rejected whole.',
        inputSchema: { type: 'object', properties: { changes: { type: 'array', items: { type: 'object', properties: { point: { type: 'string' }, device: { type: 'string' }, trended: { type: 'boolean' }, interval_s: { type: 'integer' }, label: { type: ['string', 'null'] }, notes: { type: ['string', 'null'] } } } }, scan: { type: 'boolean' }, reason: { type: 'string', description: 'why, in one line (goes in the audit log)' } } },
        run: (a, w) => this.propose(a, w) },
      { name: 'apply_changes', title: 'Apply a confirmed proposal', description: 'Apply a proposal from propose_changes after the person has confirmed it. Pass confirm: true. All of it is applied in one step or none of it; the result lists what changed. Proposals expire after 15 minutes.',
        inputSchema: { type: 'object', properties: { proposal_id: { type: 'string' }, confirm: { type: 'boolean' } }, required: ['proposal_id', 'confirm'] },
        run: (a, w) => this.apply(a, w) },
    ];
    return read.concat(edit);
  }

  propose(a, who) {
    const S = this.store;
    const changes = Array.isArray(a.changes) ? a.changes : [];
    if (!changes.length && !a.scan) throw new Error('nothing to propose: give changes or scan: true');
    if (changes.length > 500) throw new Error('at most 500 changes in one proposal');
    const rows = [], errors = [];
    const seen = new Set();
    changes.forEach((c, i) => {
      const at = `change ${i + 1}`;
      if (!c || typeof c !== 'object') return errors.push(`${at}: not an object`);
      if (c.point && c.device) return errors.push(`${at}: give point or device, not both`);
      if (!c.point && !c.device) return errors.push(`${at}: give a point key or a device key`);
      const key = String(c.point || c.device);
      if (seen.has(key)) return errors.push(`${at}: ${key} appears twice`);
      seen.add(key);
      if (c.device) {
        const d = S.device(key) || S.deviceById(Number(key));
        if (!d) return errors.push(`${at}: no device ${key}`);
        const extra = Object.keys(c).filter(k => !['device', 'label'].includes(k));
        if (extra.length) return errors.push(`${at}: a device can only take a label (not ${extra.join(', ')})`);
        if (c.label === undefined) return errors.push(`${at}: nothing to change on ${key}`);
        const label = c.label === null || c.label === '' ? null : String(c.label).trim().slice(0, 120);
        return rows.push({ device: d.key, name: d.label || d.name, before: { label: d.label || null }, after: { label } });
      }
      const p = S.pointByKey(key);
      if (!p) return errors.push(`${at}: no point ${key}`);
      if (p.missing) return errors.push(`${at}: ${key} is no longer on its device`);
      const before = {}, after = {};
      const extra = Object.keys(c).filter(k => !['point', 'trended', 'interval_s', 'label', 'notes'].includes(k));
      if (extra.length) return errors.push(`${at}: cannot set ${extra.join(', ')} (only trended, interval_s, label, notes)`);
      if (c.trended !== undefined) { if (typeof c.trended !== 'boolean') return errors.push(`${at}: trended must be true or false`); before.trended = !!p.selected; after.trended = c.trended; }
      if (c.interval_s !== undefined) { const n = Number(c.interval_s); if (!Number.isInteger(n) || n < 10 || n > 86400) return errors.push(`${at}: interval_s must be a whole number of seconds from 10 to 86400`); before.interval_s = p.interval_s; after.interval_s = n; }
      if (c.label !== undefined) { if (c.label !== null && typeof c.label !== 'string') return errors.push(`${at}: label must be text`); before.label = p.label || null; after.label = c.label === null || c.label === '' ? null : c.label.trim().slice(0, 120); }
      if (c.notes !== undefined) { if (c.notes !== null && typeof c.notes !== 'string') return errors.push(`${at}: notes must be text`); before.notes = p.notes || null; after.notes = c.notes === null || c.notes === '' ? null : c.notes.trim().slice(0, 1000); }
      if (!Object.keys(after).length) return errors.push(`${at}: nothing to change on ${key}`);
      rows.push({ point: p.key, name: p.label || p.name, before, after });
    });
    if (a.scan && this.app.scanner.state.running) errors.push('a scan is already running');
    if (errors.length) return { accepted: false, errors, note: 'Nothing was changed. Fix the errors and propose again.' };
    const id = 'prop-' + b64url(crypto.randomBytes(9));
    const prop = { id, who: who.client.name, rows, scan: !!a.scan, reason: String(a.reason || '').slice(0, 300), created: Date.now(), exp: Date.now() + PROPOSAL_TTL };
    this.proposals.set(id, prop);
    for (const [k, v] of this.proposals) if (v.exp < Date.now()) this.proposals.delete(k);
    const summary = rows.map(r => `${r.point || r.device}: ${Object.keys(r.after).map(k => `${k} ${JSON.stringify(r.before[k])} → ${JSON.stringify(r.after[k])}`).join(', ')}`).concat(a.scan ? ['start a device scan'] : []);
    return { accepted: true, proposal_id: id, expires: prop.exp, changes: rows, scan: !!a.scan, summary, next: 'Show this to the person. If they confirm, call apply_changes with this proposal_id and confirm: true.' };
  }
  apply(a, who) {
    if (a.confirm !== true) throw new Error('apply_changes needs confirm: true after the person has confirmed');
    const prop = this.proposals.get(String(a.proposal_id));
    if (!prop) throw new Error('unknown or expired proposal; propose again');
    if (prop.exp < Date.now()) { this.proposals.delete(prop.id); throw new Error('proposal expired; propose again'); }
    const S = this.store;
    // check again at apply time: the point must still be there
    for (const r of prop.rows) {
      if (r.point && !S.pointByKey(r.point)) throw new Error(`${r.point} is gone; nothing applied`);
      if (r.device && !S.device(r.device)) throw new Error(`${r.device} is gone; nothing applied`);
    }
    S.tx(() => {
      const pts = prop.rows.filter(r => r.point).map(r => ({ key: r.point, selected: r.after.trended, interval_s: r.after.interval_s, label: r.after.label, notes: r.after.notes }));
      if (pts.length) S.updatePointsNoTx(pts);
      for (const r of prop.rows.filter(r => r.device)) S.setDeviceLabel(r.device, r.after.label);
    });
    this.proposals.delete(prop.id);
    if (pts_changed(prop)) this.app.scheduler.invalidate();
    S.audit(`assistant: ${who.client.name}`, 'changes applied', { proposal: prop.id, reason: prop.reason || null, changes: prop.rows, scan: prop.scan });
    this.app.log('info', `AI assistant ${who.client.name} applied ${prop.rows.length} change(s)${prop.scan ? ' and started a scan' : ''}${prop.reason ? `: ${prop.reason}` : ''}`);
    if (prop.scan) this.app.scanner.run(`assistant ${who.client.name}`).then(() => this.app.scheduler.invalidate()).catch(() => {});
    return { applied: true, proposal_id: prop.id, changes: prop.rows, scan_started: prop.scan };
  }

  // ------------------------------------------------- setup page (api/assist)
  summary() {
    return { mode: this.mode(), token_days: this.settings().token_days || 90,
      assistants: this.store.assistClients().map(c => ({ id: c.id, name: c.name, connected: c.created, last_used: c.last_used, active: c.tokens > 0 })),
      recent: this.store.auditLog(50) };
  }
  disconnect(id) {
    const c = this.store.assistClient(id);
    if (!c) return false;
    this.store.revokeAssistClient(id);
    this.store.audit('setup page', 'assistant disconnected', { assistant: c.name });
    this.app.log('info', `AI assistant disconnected: ${c.name}`);
    return true;
  }
}
function pts_changed(prop) { return prop.rows.some(r => r.point && (r.after.trended !== undefined || r.after.interval_s !== undefined)); }

module.exports = { Assist };
