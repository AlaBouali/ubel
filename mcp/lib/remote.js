'use strict';
// remote.js — probes a running MCP server that is reached over HTTP (Streamable HTTP, or the legacy HTTP+SSE transport).
// It speaks just enough of the protocol to initialise and to list tools, resources and prompts. It never calls a tool.
//
//   1. unauthenticated initialize          does the endpoint answer without credentials?
//   2. 401 → OAuth discovery               protected-resource and authorization-server metadata, read for weak settings
//   3. initialize + list                   with credentials only when the caller supplied them (--use-config-headers / --header / --token)
//   4. unauthenticated endpoints only:     Origin and Host validation (DNS rebinding), CORS preflight, session-id strength,
//                                          reachability on the machine's other network addresses
// A server that requires authentication is not poked further: those checks answer nothing when the auth layer answers first.

import net from 'node:net';
import os from 'node:os';
import { request } from './http.js';
import { StreamableSession, LegacySseSession } from './session.js';
import { analyzeDefinitions } from './defs.js';
import { hostExposure, isLoopbackHost } from './net.js';

const EVIL_ORIGIN = 'https://rebind.invalid';
const CERT_ERR = /^(?:CERT_|DEPTH_ZERO|SELF_SIGNED|UNABLE_TO_(?:VERIFY|GET)|ERR_TLS_CERT|HOSTNAME_MISMATCH|ERR_SSL)/;
const RANK = { loopback: 0, private: 1, public: 2, unknown: 2 };
const short = (s, n = 160) => { const t = String(s).replace(/\s+/g, ' ').trim(); return t.length > n ? `${t.slice(0, n - 1)}…` : t; };

function tcpConnect(host, port, timeoutMs) {
  return new Promise(resolve => {
    const s = net.connect({ host, port });
    const done = ok => { s.destroy(); resolve(ok); };
    s.setTimeout(timeoutMs, () => done(false));
    s.once('connect', () => done(true));
    s.once('error', () => done(false));
  });
}

async function listAll(session, method, key, cap = 500) {
  const items = []; let cursor;
  for (let i = 0; i < 20 && items.length < cap; i++) {
    const r = await session.call(method, cursor ? { cursor } : {});
    if (r.error) return { items, error: r.error };
    const arr = r.result?.[key];
    if (Array.isArray(arr)) items.push(...arr);
    cursor = r.result?.nextCursor;
    if (!cursor || typeof cursor !== 'string') break;
  }
  return { items: items.slice(0, cap) };
}

/** Rough strength of a set of session ids: [{why}] problems. */
export function sessionIdIssues(ids) {
  const out = [];
  const id = ids[0];
  if (!id) return out;
  const charset = (/[a-z]/.test(id) ? 26 : 0) + (/[A-Z]/.test(id) ? 26 : 0) + (/[0-9]/.test(id) ? 10 : 0) + (/[^A-Za-z0-9]/.test(id) ? 16 : 0);
  const compact = id.replace(/[-_]/g, '');
  const bits = Math.floor(compact.length * Math.log2(Math.max(charset, 2)));
  if (bits < 64) out.push(`about ${bits} bits of entropy (${id.length} characters)`);
  if (/^\d+$/.test(id) && id.length < 16) out.push('purely numeric');
  const distinct = new Set(ids);
  if (ids.length > 1 && distinct.size === 1) out.push('the same id was issued for different sessions');
  if (ids.length > 1 && ids.every(x => /^\d+$/.test(x))) { const n = ids.map(Number); if (n.every((v, i) => i === 0 || (v > n[i - 1] && v - n[i - 1] <= 100))) out.push(`sequential (${ids.join(', ')})`); }
  if (ids.length > 1 && distinct.size > 1) {
    const common = ids.reduce((a, b) => { let i = 0; while (i < a.length && a[i] === b[i]) i++; return a.slice(0, i); });
    if (common.length >= ids[0].length - 6 && ids[0].length > 8) out.push('different ids differ only in their last few characters');
  }
  return out;
}

async function getJson(url, o) {
  try {
    const r = await request(url, { headers: { Accept: 'application/json', 'User-Agent': `ubel-mcp/${o.toolVersion}` }, timeoutMs: Math.min(o.timeoutMs, 6000), maxBytes: 262144, insecure: o.insecure });
    if (r.status !== 200) return null;
    const j = JSON.parse(r.body);
    return j && typeof j === 'object' ? j : null;
  } catch { return null; }
}

/** OAuth discovery for a 401: protected-resource metadata, then the authorization server's metadata. Only follows URLs that are not more internal than the server. */
async function discoverAuth(u, wwwAuth, serverExposure, o) {
  const out = { scheme: String(wwwAuth || '').split(/[\s,]/)[0] || null, metadata: null, authServers: [], issues: [], asMetadata: null };
  const hint = String(wwwAuth || '').match(/resource_metadata="?([^",\s]+)"?/i)?.[1];
  const cand = [];
  if (hint) { try { const h = new URL(hint, u); if (h.origin === u.origin) cand.push(h.href); else out.issues.push(`resource_metadata points at another origin (${h.origin}); not fetched`); } catch { /* ignore */ } }
  cand.push(`${u.origin}/.well-known/oauth-protected-resource${u.pathname !== '/' ? u.pathname.replace(/\/$/, '') : ''}`, `${u.origin}/.well-known/oauth-protected-resource`);
  for (const c of [...new Set(cand)]) { const j = await getJson(c, o); if (j) { out.metadata = { url: c, ...pickMeta(j, ['resource', 'authorization_servers', 'scopes_supported', 'bearer_methods_supported']) }; break; } }
  const servers = Array.isArray(out.metadata?.authorization_servers) ? out.metadata.authorization_servers.filter(s => typeof s === 'string').slice(0, 2) : [];
  for (const as of servers) {
    let a; try { a = new URL(as); } catch { out.issues.push(`authorization server "${short(as, 80)}" is not a URL`); continue; }
    out.authServers.push(a.origin + a.pathname.replace(/\/$/, ''));
    const exp = await hostExposure(a.hostname);
    if (RANK[exp] < RANK[serverExposure] && a.origin !== u.origin) { out.issues.push(`authorization server ${a.origin} is on a more internal address (${exp}) than the MCP server (${serverExposure}); not fetched`); continue; }
    if (a.protocol !== 'https:' && !isLoopbackHost(a.hostname)) out.issues.push(`authorization server ${a.origin} is not HTTPS`);
    const path = a.pathname.replace(/\/$/, '');
    const meta = await getJson(`${a.origin}/.well-known/oauth-authorization-server${path}`, o) || await getJson(`${a.origin}/.well-known/openid-configuration${path}`, o) || await getJson(`${a.origin}${path}/.well-known/openid-configuration`, o);
    if (!meta) continue;
    out.asMetadata = pickMeta(meta, ['issuer', 'authorization_endpoint', 'token_endpoint', 'registration_endpoint', 'code_challenge_methods_supported', 'grant_types_supported']);
    for (const k of ['authorization_endpoint', 'token_endpoint', 'registration_endpoint']) {
      const v = meta[k]; if (typeof v !== 'string') continue;
      try { const e = new URL(v); if (e.protocol !== 'https:' && !isLoopbackHost(e.hostname)) out.issues.push(`${k} is not HTTPS (${short(v, 80)})`); } catch { out.issues.push(`${k} is not a URL`); }
    }
    if (Array.isArray(meta.code_challenge_methods_supported) && !meta.code_challenge_methods_supported.includes('S256')) out.issues.push(`PKCE S256 is not offered (code_challenge_methods_supported: ${short(JSON.stringify(meta.code_challenge_methods_supported), 60)})`);
    if (typeof meta.issuer === 'string' && meta.issuer.replace(/\/$/, '') !== (a.origin + path)) out.issues.push(`the issuer in the metadata (${short(meta.issuer, 80)}) does not match the server it was fetched from (${a.origin + path})`);
  }
  return out;
}
const pickMeta = (j, keys) => Object.fromEntries(keys.filter(k => j[k] !== undefined).map(k => [k, j[k]]));

/**
 * @param {string} url
 * @param {{headers?:object, timeoutMs:number, maxBytes:number, insecure:boolean, toolVersion:string, log?:Function, checks?:object, previous?:object}} o
 * @param {{findings:object, server:object}} ctx
 */
export async function probeRemote(url, o, ctx) {
  const { findings, server } = ctx;
  const log = o.log || (() => {});
  const add = (rule, f) => findings.add(rule, { app: server.id, origin: 'app', artifact: f.artifact ?? rec.url, ...f });
  const checks = { origin: true, host: true, cors: true, bind: true, session: true, ...(o.checks || {}) };
  const rec = { url, declaredUrl: url, reachable: false, mcp: false, transport: null, exposure: 'unknown', unauthenticated: null, auth: null, initialize: null, tools: [], resources: [], resourceTemplates: [], prompts: [], tls: null, checks: {}, notes: [], error: null, definitions: null };
  let u;
  try { u = new URL(url); } catch { rec.error = 'invalid URL'; return rec; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') { rec.error = `unsupported scheme ${u.protocol}`; return rec; }
  rec.exposure = await hostExposure(u.hostname);
  const sessOpts = { timeoutMs: o.timeoutMs, maxBytes: o.maxBytes, insecure: o.insecure, toolVersion: o.toolVersion };
  const hasCreds = o.headers && Object.keys(o.headers).length > 0;

  /** One attempt at reaching an initialised session with `headers`. */
  async function establish(headers) {
    let cur = rec.url;
    for (let hop = 0; hop < 3; hop++) {
      const s = new StreamableSession(cur, { ...sessOpts, headers });
      let r;
      try { r = await s.init(); }
      catch (e) {
        if (CERT_ERR.test(e.code || '') && !sessOpts.insecure) {
          add('mcp.remote.tls_invalid', { artifact: cur, key: `tls:${cur}`, severity: hasCreds ? 'high' : 'medium', description: `The TLS certificate of ${new URL(cur).host} does not validate (${e.code}). ${o.insecure ? '' : 'The probe stopped there; --insecure continues without verification to examine the server.'}${hasCreds ? ' This server is configured with credentials, which a client that accepts the certificate would send to whoever presents it.' : ''}`, evidence: [e.code] });
          if (!o.insecure) return { kind: 'error', error: e };
          sessOpts.insecure = true; hop--; continue;
        }
        return { kind: 'error', error: e };
      }
      const res = r.res;
      rec.reachable = true;
      if (res.tls) rec.tls = { protocol: res.tls.protocol, validTo: res.tls.validTo ? new Date(res.tls.validTo).toISOString() : null, subject: res.tls.subject, issuer: res.tls.issuer, authorized: res.tls.authorized };
      if (r.ok) { rec.url = cur; return { kind: 'streamable', session: s, init: r, res }; }
      if (res.status >= 300 && res.status < 400 && res.headers.location) {
        let t; try { t = new URL(res.headers.location, cur); } catch { return { kind: 'none', res }; }
        if (t.origin === new URL(cur).origin) { cur = t.href; continue; }
        return { kind: 'redirect', res, target: t };
      }
      if (res.status === 401 || res.status === 403) return { kind: 'auth', res, url: cur };
      if ([400, 404, 405, 406, 415, 200, 202].includes(res.status)) {
        const sse = new LegacySseSession(cur, { ...sessOpts, headers });
        const op = await sse.open();
        if (op.ok) {
          let ir; try { ir = await sse.init(); } catch (e) { await sse.close(); return { kind: 'none', res }; }
          if (ir.ok) { rec.url = cur; return { kind: 'sse', session: sse, init: ir, res }; }
          await sse.close();
        } else if (op.status === 401 || op.status === 403) return { kind: 'auth', res: { ...res, status: op.status, headers: op.headers || res.headers }, url: cur };
        return { kind: 'none', res };
      }
      return { kind: 'none', res };
    }
    return { kind: 'none', res: null };
  }

  // 1. unauthenticated
  let est = await establish({});
  let unauth = null;
  if (est.kind === 'streamable' || est.kind === 'sse') unauth = true;
  else if (est.kind === 'auth') unauth = false;
  rec.unauthenticated = unauth;
  if (est.kind === 'error') { rec.error = est.error.code || est.error.message; return rec; }
  if (est.kind === 'redirect') {
    rec.notes.push(`The endpoint redirects to ${est.target.origin}; not followed.`);
    add('mcp.remote.redirect_cross_origin', { artifact: rec.url, key: `redirect:${est.target.origin}`, description: `${u.origin}${u.pathname} answers with a redirect (HTTP ${est.res.status}) to ${est.target.origin}${est.target.pathname}. The probe did not follow it.`, evidence: [`${est.res.status} → ${est.target.origin}${est.target.pathname}`] });
    return rec;
  }
  if (est.kind === 'none') { rec.notes.push(`No MCP endpoint here (HTTP ${est.res?.status ?? '?'}).`); return rec; }

  // 2. authentication required
  if (est.kind === 'auth') {
    rec.mcp = true;
    const www = est.res.headers['www-authenticate'] || '';
    rec.auth = { required: true, ...(await discoverAuth(new URL(est.url), www, rec.exposure, sessOpts)) };
    if (rec.auth.issues.length) add('mcp.remote.auth_metadata_weak', { artifact: rec.url, key: 'auth_meta', description: `${u.host} requires authentication and publishes OAuth metadata with ${rec.auth.issues.length} weakness(es).`, evidence: rec.auth.issues.slice(0, 6) });
    if (hasCreds) { est = await establish(o.headers); if (est.kind !== 'streamable' && est.kind !== 'sse') { rec.notes.push(`The configured credentials were not accepted (${est.kind === 'auth' ? `HTTP ${est.res.status}` : est.kind}).`); return rec; } }
    else { rec.notes.push('Authentication is required; without credentials (--use-config-headers, --header, --token) the tools were not listed.'); return rec; }
  }

  // 3. initialised
  rec.mcp = true; rec.transport = est.kind === 'sse' ? 'sse' : 'streamable-http';
  const session = est.session;
  const init = est.init.result;
  rec.initialize = { protocolVersion: init.protocolVersion, serverInfo: init.serverInfo, capabilities: init.capabilities, instructions: typeof init.instructions === 'string' ? init.instructions.slice(0, 4000) : undefined };
  const sessionId = session.sessionId || null;
  rec.sessionId = sessionId ? { present: true } : { present: false };
  log(`  ${rec.url}: ${rec.transport}, ${init.serverInfo?.name || 'unnamed'} ${init.serverInfo?.version || ''}`);
  if (est.kind === 'sse' && session.foreignEndpoint) add('mcp.remote.endpoint_foreign', { artifact: rec.url, key: 'endpoint_foreign', description: `The SSE endpoint event of ${u.host} names ${new URL(session.endpoint).origin} as the place to POST messages.`, evidence: [new URL(session.endpoint).origin] });
  if (est.kind === 'sse' && session.sessionIdInUrl) add('mcp.remote.session_in_url', { artifact: rec.url, key: 'session_url', description: `${u.host} uses the legacy SSE transport, which carries the session id in the message URL (${session.endpoint.replace(/=[^&]{6,}/, '=…')}). URLs are logged and shared.`, evidence: [session.endpoint.replace(/=[^&]{6,}/, '=…')] });
  const exp = rec.tls?.validTo ? Math.floor((Date.parse(rec.tls.validTo) - Date.now()) / 86400000) : null;
  if (exp != null && exp < 14) add('mcp.remote.tls_expiring', { artifact: rec.url, key: 'tls_exp', severity: exp < 0 ? 'medium' : 'low', description: `The certificate of ${u.host} ${exp < 0 ? `expired ${-exp} day(s) ago` : `expires in ${exp} day(s)`}.`, evidence: [rec.tls.validTo] });

  try { await session.notify('notifications/initialized'); } catch { /* servers answer 202 or nothing */ }
  const caps = init.capabilities && typeof init.capabilities === 'object' ? init.capabilities : {};
  const none = Object.keys(caps).length === 0;
  const grab = async (method, key, listKey, flag) => {
    if (!(flag in caps) && !(none && flag === 'tools')) return;
    try { const r = await listAll(session, method, key); rec[listKey] = r.items; if (r.error) rec.notes.push(`${method}: ${short(r.error.message || JSON.stringify(r.error), 100)}`); }
    catch (e) { rec.notes.push(`${method}: ${e.message}`); }
  };
  await grab('tools/list', 'tools', 'tools', 'tools');
  await grab('resources/list', 'resources', 'resources', 'resources');
  if ('resources' in caps) { try { rec.resourceTemplates = (await listAll(session, 'resources/templates/list', 'resourceTemplates')).items; } catch { /* optional */ } }
  await grab('prompts/list', 'prompts', 'prompts', 'prompts');

  // 4. checks that only mean something when anyone can talk to the endpoint
  if (unauth === true) {
    const sevByExposure = { public: 'high', private: 'medium', loopback: 'low', unknown: 'high' }[rec.exposure];
    add('mcp.remote.unauthenticated', {
      artifact: rec.url, key: 'unauth', severity: sevByExposure,
      description: `${u.origin}${u.pathname} answered initialize without credentials and listed ${rec.tools.length} tool(s), ${rec.resources.length} resource(s) and ${rec.prompts.length} prompt(s). It is ${rec.exposure === 'public' ? 'on a public address' : rec.exposure === 'private' ? 'on a private network address' : rec.exposure === 'loopback' ? 'bound to this machine (the Origin check below decides whether a web page can reach it)' : 'at an address that could not be classified'}.`,
      evidence: rec.tools.slice(0, 8).map(t => String(t?.name ?? '?')),
    });
    const post = (hdrs) => new StreamableSession(rec.url, { ...sessOpts, headers: hdrs });
    const sseT = (hdrs) => new LegacySseSession(rec.url, { ...sessOpts, headers: hdrs });
    const reach = rec.exposure === 'public' ? 'public' : rec.exposure === 'private' ? 'private' : 'loopback';
    const test = async (hdrs) => {
      try {
        if (est.kind === 'streamable') { const s = post(hdrs); const r = await s.init(); await s.close(); return r.ok; }
        const s = sseT(hdrs); const op = await s.open(); await s.close(); return !!op.ok;
      } catch { return null; }
    };
    if (checks.origin) {
      const ok = await test({ Origin: EVIL_ORIGIN });
      rec.checks.origin = ok === null ? 'error' : ok ? 'accepted' : 'rejected';
      if (ok) add('mcp.remote.origin_not_validated', { artifact: rec.url, key: 'origin', severity: reach === 'public' ? 'medium' : 'high', description: `A request with Origin: ${EVIL_ORIGIN} was served exactly like one without an Origin. A web page the user visits can send requests to this server from the user's browser${reach === 'public' ? '' : ' (directly, or through DNS rebinding) and, because it needs no credentials, call its tools'}.`, evidence: [`Origin: ${EVIL_ORIGIN} → accepted`] });
    }
    if (checks.host) {
      const ok = await test({ Host: `rebind.invalid:${u.port || (u.protocol === 'https:' ? 443 : 80)}` });
      rec.checks.host = ok === null ? 'error' : ok ? 'accepted' : 'rejected';
      if (ok && reach !== 'public') add('mcp.remote.host_not_validated', { artifact: rec.url, key: 'host', description: 'A request with a Host header that is not one of the server\'s names was served normally. DNS rebinding relies on exactly this.', evidence: ['Host: rebind.invalid → accepted'] });
    }
    if (checks.cors) {
      try {
        const r = await request(rec.url, { method: 'OPTIONS', headers: { Origin: EVIL_ORIGIN, 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'content-type, mcp-session-id', 'User-Agent': `ubel-mcp/${o.toolVersion}` }, timeoutMs: o.timeoutMs, maxBytes: 8192, insecure: sessOpts.insecure });
        const acao = r.headers['access-control-allow-origin'], cred = String(r.headers['access-control-allow-credentials'] || '').toLowerCase() === 'true';
        rec.checks.cors = acao || 'none';
        if (acao === '*' || acao === EVIL_ORIGIN) add('mcp.remote.cors_permissive', { artifact: rec.url, key: 'cors', severity: cred || reach !== 'public' ? 'high' : 'medium', description: `The CORS preflight from ${EVIL_ORIGIN} was answered with Access-Control-Allow-Origin: ${acao}${cred ? ' and Allow-Credentials: true' : ''}. Any website can call this endpoint from a visitor's browser.`, evidence: [`Access-Control-Allow-Origin: ${acao}`] });
      } catch { rec.checks.cors = 'error'; }
    }
    if (checks.session && est.kind === 'streamable' && sessionId) {
      const ids = [sessionId];
      for (let i = 0; i < 2; i++) { try { const s = post({}); const r = await s.init(); if (r.ok && s.sessionId) ids.push(s.sessionId); await s.close(); } catch { break; } }
      const issues = sessionIdIssues(ids);
      rec.sessionId = { present: true, samples: ids.length, issues };
      if (issues.length) add('mcp.remote.weak_session_id', { artifact: rec.url, key: 'session_id', description: `The Mcp-Session-Id values issued by ${u.host} look predictable: ${issues.join('; ')}. A guessable session id lets another client take over a session.`, evidence: ids.map(x => `${x.slice(0, 6)}…(${x.length})`) });
    }
    if (checks.bind && isLoopbackHost(u.hostname)) {
      const addrs = [];
      for (const list of Object.values(os.networkInterfaces())) for (const a of list || []) if (!a.internal && !/^fe80:/i.test(a.address)) addrs.push(a.address);
      const port = Number(u.port) || (u.protocol === 'https:' ? 443 : 80);
      const reachable = [];
      for (const a of [...new Set(addrs)].slice(0, 4)) {
        if (!(await tcpConnect(a, port, 1200))) continue;
        let mcp = false;
        if (u.protocol === 'http:') { try { const t = new URL(rec.url); t.hostname = a.includes(':') ? `[${a}]` : a; const s = new StreamableSession(t.href, { ...sessOpts, timeoutMs: Math.min(o.timeoutMs, 4000), headers: {} }); const r = await s.init(); mcp = r.ok; await s.close(); } catch { /* TCP only */ } }
        reachable.push({ addr: a, mcp });
      }
      rec.checks.bind = reachable.length ? 'network' : 'loopback';
      if (reachable.length) add('mcp.remote.network_exposed', { artifact: rec.url, key: `bind:${port}`, severity: reachable.some(r => r.mcp) ? 'high' : 'medium', description: `The server declared as ${u.host} also accepts connections on this machine's network address${reachable.length > 1 ? 'es' : ''} ${reachable.map(r => r.addr).join(', ')}${reachable.some(r => r.mcp) ? ', where it answers initialize without credentials' : ''}. It is bound to all interfaces, not just loopback; a firewall may still be the only thing in the way.`, evidence: reachable.map(r => `${r.addr}:${port}${r.mcp ? ' (MCP, unauthenticated)' : ''}`) });
    }
  } else rec.notes.push('Origin, Host, CORS, session-id and bind checks were skipped because the endpoint requires authentication.');

  // 5. what the server tells the model
  const prevTools = o.previous?.tools;
  rec.definitions = analyzeDefinitions({ server, tools: rec.tools, resources: rec.resources, resourceTemplates: rec.resourceTemplates, prompts: rec.prompts, instructions: init.instructions, exposure: rec.exposure, unauthenticated: unauth === true, previous: prevTools ? { tools: prevTools } : null }, { findings });
  await session.close();
  return rec;
}
