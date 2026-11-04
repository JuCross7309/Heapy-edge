'use strict';
// AI assistants: the sign-in (register, Allow page, PKCE token, refresh, revoke),
// the MCP endpoint (initialize, tools, values, trends) and the confirmed-edit
// rules (propose → confirm → apply; invalid batch never partly applied; read-only
// and off modes). Runs with no BAS: devices, points and readings are put straight
// into the buffer. Needs only Node.
//   node tests/assist_check.js
process.env.HEAPY_EDGE_QUIET = '1';
const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

async function run(check) {
  const { EdgeApp } = require('../core/main');
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'edge-assist-'));
  const drivers = Object.fromEntries(['bacnet-ip', 'bacnet-mstp', 'modbus', 'snmp', 'haystack', 'obix'].map(n => [n, { enabled: false }]));
  const app = new EdgeApp({ dataDir, overrides: { web: { port: 0, bind: '127.0.0.1' }, drivers, scan: { at_start: false } } });
  await app.start();
  const base = `http://127.0.0.1:${app.web.port()}`;
  const S = app.store;
  // a small site in the buffer
  const now = Date.now();
  const ahu = S.upsertDevice('bacnet-ip', { key: 'bacnet://1201', route: '10.1.1.11', name: 'AHU-1', vendor: 'Sim', model: 'AHU' }).device;
  const vav = S.upsertDevice('bacnet-ip', { key: 'bacnet://2001', route: '2001:5', name: 'VAV-2-01', vendor: 'Sim', model: 'VAV' }).device;
  S.setDeviceStatus(ahu.id, { status: 'online' }); S.setDeviceStatus(vav.id, { status: 'offline' });
  S.upsertPoint(ahu.id, { key: 'bacnet://1201/analog-input:1', name: 'AHU-1.SA-T', description: 'Supply air temperature', units: 'degrees-fahrenheit', kind: 'analog' }, { selected: true, interval_s: 60 });
  S.upsertPoint(ahu.id, { key: 'bacnet://1201/multi-state-value:1', name: 'AHU-1.OCC-MODE', description: 'Occupancy', kind: 'enum', states: ['Unoccupied', 'Occupied'] }, { selected: false, interval_s: 900 });
  S.upsertPoint(vav.id, { key: 'bacnet://2001/analog-input:1', name: 'VAV-2-01.ZN-T', description: 'Zone temp', units: 'degrees-fahrenheit', kind: 'analog' }, { selected: true, interval_s: 300 });
  const sat = S.pointByKey('bacnet://1201/analog-input:1');
  const rows = []; for (let i = 0; i < 120; i++) rows.push({ p: sat.id, t: now - (120 - i) * 60000, v: 55 + Math.sin(i / 10) });
  S.addSamples(rows);

  const form = o => new URLSearchParams(o).toString();
  const post = (u, body, headers = {}) => fetch(base + u, { method: 'POST', redirect: 'manual', headers: { 'content-type': typeof body === 'string' ? 'application/x-www-form-urlencoded' : 'application/json', ...headers }, body: typeof body === 'string' ? body : JSON.stringify(body) });
  let token = null, refresh = null, client = null, rpcId = 1;
  const rpc = async (method, params, tok = token) => {
    const r = await post('/mcp', { jsonrpc: '2.0', id: rpcId++, method, params }, { authorization: `Bearer ${tok}` });
    return { status: r.status, body: r.status === 202 ? null : await r.json() };
  };
  const call = async (name, args) => { const r = await rpc('tools/call', { name, arguments: args }); assert.strictEqual(r.status, 200, JSON.stringify(r.body)); if (r.body.error) throw new Error(r.body.error.message); return r.body.result; };
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  const redirect = 'http://localhost:9999/callback';

  try {
    await check('assistants: discovery documents point at the box', async () => {
      const r = await (await fetch(base + '/.well-known/oauth-protected-resource')).json();
      assert.strictEqual(r.resource, base + '/mcp');
      const m = await (await fetch(base + '/.well-known/oauth-authorization-server')).json();
      assert.strictEqual(m.token_endpoint, base + '/oauth/token');
      assert.deepStrictEqual(m.code_challenge_methods_supported, ['S256']);
      const u = await fetch(base + '/mcp', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
      assert.strictEqual(u.status, 401);
      assert(/resource_metadata=/.test(u.headers.get('www-authenticate')));
    });
    await check('assistants: register, Allow page needs the password, PKCE token, refresh', async () => {
      const bad = await post('/oauth/register', { client_name: 'Test assistant', redirect_uris: ['http://evil.example/cb'] });
      assert.strictEqual(bad.status, 400, 'http redirect off localhost refused');
      const r = await post('/oauth/register', { client_name: 'Test assistant', redirect_uris: [redirect] });
      assert.strictEqual(r.status, 201); client = await r.json();
      const q = form({ response_type: 'code', client_id: client.client_id, redirect_uri: redirect, code_challenge: challenge, code_challenge_method: 'S256', state: 'xyz', scope: 'read edit' });
      const page = await fetch(base + '/oauth/authorize?' + q);
      assert.strictEqual(page.status, 200);
      assert((await page.text()).includes('Test assistant'));
      // no password yet on the box
      let a = await post('/oauth/authorize?' + q, form({ decision: 'allow', password: 'whatever' }));
      assert.strictEqual(a.status, 409);
      app.config.setSecret({ admin_hash: require('../core/web').hashPw('assist-test-password') });
      a = await post('/oauth/authorize?' + q, form({ decision: 'allow', password: 'wrong-password' }));
      assert.strictEqual(a.status, 401);
      a = await post('/oauth/authorize?' + q, form({ decision: 'deny', password: 'assist-test-password' }));
      assert.strictEqual(a.status, 302); assert(/error=access_denied/.test(a.headers.get('location')));
      a = await post('/oauth/authorize?' + q, form({ decision: 'allow', password: 'assist-test-password' }));
      assert.strictEqual(a.status, 302);
      const loc = new URL(a.headers.get('location'));
      assert.strictEqual(loc.origin + loc.pathname, redirect); assert.strictEqual(loc.searchParams.get('state'), 'xyz');
      const code = loc.searchParams.get('code'); assert(code);
      const badv = await post('/oauth/token', form({ grant_type: 'authorization_code', code, client_id: client.client_id, redirect_uri: redirect, code_verifier: 'not-the-verifier' }));
      assert.strictEqual(badv.status, 400, 'wrong PKCE verifier refused (and the code is spent)');
      // new code for the real exchange
      a = await post('/oauth/authorize?' + q, form({ decision: 'allow', password: 'assist-test-password' }));
      const code2 = new URL(a.headers.get('location')).searchParams.get('code');
      const t = await post('/oauth/token', form({ grant_type: 'authorization_code', code: code2, client_id: client.client_id, redirect_uri: redirect, code_verifier: verifier }));
      assert.strictEqual(t.status, 200); const tj = await t.json();
      assert(tj.access_token && tj.refresh_token && tj.scope === 'read edit');
      token = tj.access_token; refresh = tj.refresh_token;
      const again = await post('/oauth/token', form({ grant_type: 'authorization_code', code: code2, client_id: client.client_id, redirect_uri: redirect, code_verifier: verifier }));
      assert.strictEqual(again.status, 400, 'a code works once');
      const rf = await post('/oauth/token', form({ grant_type: 'refresh_token', refresh_token: refresh, client_id: client.client_id }));
      assert.strictEqual(rf.status, 200); const rj = await rf.json();
      const rf2 = await post('/oauth/token', form({ grant_type: 'refresh_token', refresh_token: refresh, client_id: client.client_id }));
      assert.strictEqual(rf2.status, 400, 'refresh tokens rotate');
      token = rj.access_token; refresh = rj.refresh_token;
    });
    await check('assistants: initialize and the tool list', async () => {
      const r = await rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '1' } });
      assert.strictEqual(r.body.result.protocolVersion, '2025-06-18');
      assert.strictEqual(r.body.result.serverInfo.name, 'HEAPY Edge');
      const n = await post('/mcp', { jsonrpc: '2.0', method: 'notifications/initialized' }, { authorization: `Bearer ${token}` });
      assert.strictEqual(n.status, 202);
      const t = await rpc('tools/list', {});
      const names = t.body.result.tools.map(x => x.name);
      for (const x of ['box_status', 'list_devices', 'list_points', 'get_values', 'get_trend', 'search', 'audit_log', 'propose_changes', 'apply_changes']) assert(names.includes(x), x);
      const u = await rpc('nope/method', {});
      assert.strictEqual(u.body.error.code, -32601);
    });
    await check('assistants: devices, points, values and trends match the buffer', async () => {
      const d = await call('list_devices', {});
      assert.strictEqual(d.structuredContent.total, 2);
      const off = await call('list_devices', { status: 'offline' });
      assert.strictEqual(off.structuredContent.devices[0].name, 'VAV-2-01');
      const p = await call('list_points', { device: 'bacnet://1201' });
      assert.strictEqual(p.structuredContent.total, 2);
      const v = await call('get_values', { points: ['bacnet://1201/analog-input:1', 'bacnet://nope/analog-input:9'] });
      const vals = v.structuredContent.values;
      assert.strictEqual(vals[0].value, S.pointByKey('bacnet://1201/analog-input:1').last_v);
      assert.strictEqual(vals[1].error, 'not found');
      const tr = await call('get_trend', { point: 'bacnet://1201/analog-input:1', from: now - 3 * 3600000, to: now, max_points: 50 });
      const t = tr.structuredContent;
      assert.strictEqual(t.readings_in_range, 120); assert(t.returned <= 50 && t.returned >= 40, `thinned to ${t.returned}`);
      assert.strictEqual(t.samples[0][1], rows[0].v);
      const s = await call('search', { text: 'occ' });
      assert.strictEqual(s.structuredContent.points[0].key, 'bacnet://1201/multi-state-value:1');
      const st = await call('box_status', {});
      assert.strictEqual(st.structuredContent.assistants_mode, 'edit');
    });
    await check('assistants: an invalid batch is rejected whole; a confirmed one is applied in full and audited', async () => {
      const bad = await call('propose_changes', { changes: [{ point: 'bacnet://1201/multi-state-value:1', trended: true }, { point: 'bacnet://1201/analog-input:1', interval_s: 1 }, { point: 'bacnet://nope', trended: true }] });
      assert.strictEqual(bad.structuredContent.accepted, false);
      assert.strictEqual(bad.structuredContent.errors.length, 2);
      assert.strictEqual(S.pointByKey('bacnet://1201/multi-state-value:1').selected, 0, 'nothing applied');
      const good = await call('propose_changes', { changes: [{ point: 'bacnet://1201/multi-state-value:1', trended: true, interval_s: 300, label: 'AHU-1 occupancy' }, { device: 'bacnet://2001', label: 'VAV east 1' }], reason: 'test' });
      const g = good.structuredContent;
      assert.strictEqual(g.accepted, true); assert(g.proposal_id);
      assert.strictEqual(S.pointByKey('bacnet://1201/multi-state-value:1').selected, 0, 'a proposal changes nothing');
      let r = await rpc('tools/call', { name: 'apply_changes', arguments: { proposal_id: g.proposal_id, confirm: false } });
      assert.strictEqual(r.body.result.isError, true, 'needs confirm: true');
      const ap = await call('apply_changes', { proposal_id: g.proposal_id, confirm: true });
      assert.strictEqual(ap.structuredContent.applied, true);
      const p = S.pointByKey('bacnet://1201/multi-state-value:1');
      assert.strictEqual(p.selected, 1); assert.strictEqual(p.interval_s, 300); assert.strictEqual(p.label, 'AHU-1 occupancy');
      assert.strictEqual(S.device('bacnet://2001').label, 'VAV east 1');
      r = await rpc('tools/call', { name: 'apply_changes', arguments: { proposal_id: g.proposal_id, confirm: true } });
      assert.strictEqual(r.body.result.isError, true, 'a proposal applies once');
      const log = await call('audit_log', { limit: 5 });
      const e = log.structuredContent.entries[0];
      assert.strictEqual(e.action, 'changes applied'); assert(e.who.includes('Test assistant')); assert.strictEqual(e.detail.reason, 'test');
      const lp = await call('list_points', { search: 'occupancy' });
      assert.strictEqual(lp.structuredContent.points[0].name, 'AHU-1 occupancy');
    });
    await check('assistants: read-only mode hides the edit tools; off mode refuses everything; disconnect revokes', async () => {
      await app.applySettings({ assist: { mode: 'read' } });
      const t = await rpc('tools/list', {});
      assert(!t.body.result.tools.some(x => x.name === 'apply_changes'));
      const r = await rpc('tools/call', { name: 'propose_changes', arguments: { changes: [] } });
      assert.strictEqual(r.body.error.code, -32602);
      const rf = await post('/oauth/token', form({ grant_type: 'refresh_token', refresh_token: refresh, client_id: client.client_id }));
      const rj = await rf.json(); refresh = rj.refresh_token;
      assert.strictEqual(rj.scope, 'read', 'a token refreshed in read mode is read-only');
      await app.applySettings({ assist: { mode: 'off' } });
      assert.strictEqual((await rpc('ping', {})).status, 403);
      const q = form({ response_type: 'code', client_id: client.client_id, redirect_uri: redirect, code_challenge: challenge, code_challenge_method: 'S256' });
      assert.strictEqual((await fetch(base + '/oauth/authorize?' + q)).status, 403);
      await app.applySettings({ assist: { mode: 'edit' } });
      assert.strictEqual((await rpc('ping', {})).status, 200, 'back on: the token works again');
      const sum = app.assist.summary();
      assert.strictEqual(sum.assistants.length, 1); assert.strictEqual(sum.assistants[0].name, 'Test assistant');
      assert(app.assist.disconnect(client.client_id));
      assert.strictEqual(app.assist.summary().assistants.length, 0);
      assert.strictEqual((await rpc('ping', {})).status, 401, 'disconnected: token refused');
      const rf2 = await post('/oauth/token', form({ grant_type: 'refresh_token', refresh_token: refresh, client_id: client.client_id }));
      assert.strictEqual(rf2.status, 400, 'disconnected: refresh refused');
    });
  } finally {
    await app.stop().catch(() => {});
  }
}

if (require.main === module) {
  let failed = 0;
  run(async (name, fn) => { try { await fn(); console.log(`  ok   ${name}`); } catch (e) { failed++; console.log(`  FAIL ${name}: ${e.stack}`); } })
    .then(() => { console.log(failed ? `${failed} failed` : 'all passed'); process.exit(failed ? 1 : 0); })
    .catch(e => { console.error(e); process.exit(1); });
}
module.exports = { run };
