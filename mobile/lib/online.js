'use strict';
// online.js — the opt-in (--online) checks that need the network. Everything else in ubel-mobile is static; this module is the one place
// that contacts hosts named by the *app*, so it is off by default, never follows redirects, refuses IP literals and private/internal host
// *names* (isPublicHost checks the name only; what a public name resolves to is not checked), only reads (no writes, no authentication
// attempts) and treats every network failure as a coverage gap rather than a pass.
//
//   • Digital Asset Links: for each android:autoVerify host fetch https://<host>/.well-known/assetlinks.json and compare the
//     sha256_cert_fingerprints with the signing certificate read from the package.
//   • Firebase Realtime Database: one unauthenticated GET <db>/.json?shallow=true (shallow: only that the root is readable, never data).
//   • Firebase Remote Config: one unauthenticated fetch with the API key and app id embedded in the app (what the SDK itself sends).
//
// Network access goes through an injectable `fetchImpl` (default: the global fetch) so the logic is testable without a network.

import crypto from 'crypto';
import { gap } from './coverage.js';
import { mask } from './findings.js';

const MAX_BODY = 1024 * 1024;
const MAX_HOSTS = 10;

// Realtime Database hosts: <db>.firebaseio.com (US), and <db>.<region>.firebasedatabase.app for every other location (europe-west1,
// asia-southeast1 …). One definition for the static finding (android.js) and the online probe, so they cannot drift apart.
const FIREBASE_DB_HOST = '(?:[a-z0-9-]+\\.firebaseio\\.com|[a-z0-9-]+(?:\\.[a-z0-9-]+)?\\.firebasedatabase\\.app)';
/** A URL (any path) on a Realtime Database host. The host must end there: `x.firebasedatabase.app.evil.example` is not one. */
export const FIREBASE_DB_URL = new RegExp(`^https://${FIREBASE_DB_HOST}(?=[/:?#]|$)`, 'i');
/** Exactly `new URL(…).origin` of a Realtime Database (no port, no path). */
export const FIREBASE_DB_ORIGIN = new RegExp(`^https://${FIREBASE_DB_HOST}$`, 'i');

/** Non-enumerable per-app scratch space: facts the static scan collects for the online step. Never serialised into the report. */
export function onlineData(app) {
  if (!app._online) Object.defineProperty(app, '_online', { value: { verifyHosts: new Set(), firebase: {}, dbUrls: new Set() }, enumerable: false });
  return app._online;
}

const FIREBASE_RES = { google_app_id: 'appId', google_api_key: 'apiKey', firebase_database_url: 'dbUrl', project_id: 'projectId' };
/** Called with every string resource; remembers the Firebase identifiers. */
export function captureFirebaseResource(app, name, value) {
  const k = FIREBASE_RES[name];
  if (k && typeof value === 'string' && value && value.length < 300) onlineData(app).firebase[k] = value;
}

/** android:autoVerify https hosts of a manifest intent-filter list → host set. `*.example.com` is verified against `example.com`. */
export function collectVerifyHosts(app, hosts) {
  const set = onlineData(app).verifyHosts;
  for (const h of hosts) set.add(String(h).replace(/^\*\./, '').toLowerCase());
}

/** Only public-looking DNS names are contacted: no IPs, no localhost / .local / .internal, nothing with a port or path. */
export function isPublicHost(h) {
  return typeof h === 'string' && h.length <= 253 && /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(h) &&
    !/(^|\.)(localhost|local|internal|lan|home|corp|intranet|test|invalid|example)$/i.test(h);
}

const normFp = s => String(s).replace(/[^0-9a-f]/gi, '').toLowerCase();

async function request(fetchImpl, url, { method = 'GET', body, headers, timeoutMs }) {
  const res = await fetchImpl(url, { method, body, headers: { 'user-agent': 'ubel-mobile', ...headers }, redirect: 'manual', signal: AbortSignal.timeout(timeoutMs) });
  let text = '';
  const reader = res.body && typeof res.body.getReader === 'function' ? res.body.getReader() : null;
  if (reader) {
    const chunks = []; let n = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(Buffer.from(value)); n += value.length;
      if (n > MAX_BODY) { try { await reader.cancel(); } catch { /* ignore */ } break; }
    }
    text = Buffer.concat(chunks).subarray(0, MAX_BODY).toString('utf8');
  } else text = String(await res.text()).slice(0, MAX_BODY);
  return { status: res.status, text };
}

/** Pure verdict on an assetlinks.json body. @returns {{state:'ok'|'invalid'|'package_missing'|'fingerprint_mismatch'|'unverifiable', listed?:string[]}} */
export function judgeAssetLinks(text, pkg, certSha256s) {
  let doc;
  try { doc = JSON.parse(text); } catch { return { state: 'invalid' }; }
  if (!Array.isArray(doc)) return { state: 'invalid' };
  const mine = doc.filter(s => s && Array.isArray(s.relation) && s.relation.includes('delegate_permission/common.handle_all_urls') &&
    s.target && s.target.namespace === 'android_app' && s.target.package_name === pkg);
  if (!mine.length) return { state: 'package_missing' };
  const listed = [...new Set(mine.flatMap(s => (Array.isArray(s.target.sha256_cert_fingerprints) ? s.target.sha256_cert_fingerprints : []).map(normFp)))];
  if (!certSha256s || !certSha256s.length) return { state: 'unverifiable', listed };
  return certSha256s.some(c => listed.includes(normFp(c))) ? { state: 'ok', listed } : { state: 'fingerprint_mismatch', listed };
}

/**
 * @param {object[]} apps  Android app summaries from scanPackage
 * @param {{findings:import('./findings.js').Findings, notes:string[], newScanner:(base:object)=>import('./secrets.js').SecretScanner,
 *          fetchImpl?:Function, timeoutMs?:number, log?:(m:string)=>void}} ctx
 */
export async function runOnlineChecks(apps, ctx) {
  const { findings, notes, newScanner, fetchImpl = globalThis.fetch, timeoutMs = 8000, log = () => {} } = ctx;
  if (typeof fetchImpl !== 'function') { gap(notes, 'Online checks requested but this Node.js has no fetch(); upgrade to Node 18+.'); return; }
  for (const app of apps) {
    if (app.platform !== 'android') continue;
    const data = onlineData(app);
    const base = { app: app.package };
    const art = 'AndroidManifest.xml';
    const result = { assetlinks: [], firebase_database: [], remote_config: null };
    const failed = (what, err) => gap(notes, `Online check not completed (${what}): ${err && err.name === 'TimeoutError' ? 'timed out' : (err && err.cause && err.cause.code) || (err && err.message) || 'request failed'}.`);

    // ── Digital Asset Links ───────────────────────────────────────────────────────────────────────
    const hosts = [...data.verifyHosts].filter(isPublicHost).slice(0, MAX_HOSTS);
    const certs = (app.signing && app.signing.certificates || []).map(c => c.sha256);
    const isBundle = app.module !== undefined;       // an .aab is signed with the upload key; Play re-signs, so its fingerprint is not the one to compare
    const missing = [], mismatch = [];
    for (const host of hosts) {
      const url = `https://${host}/.well-known/assetlinks.json`;
      log(`online: ${url}`);
      try {
        const r = await request(fetchImpl, url, { timeoutMs });
        if (r.status !== 200) { missing.push(`${host} → HTTP ${r.status}${r.status >= 300 && r.status < 400 ? ' (a redirect; Android does not follow redirects here)' : ''}`); result.assetlinks.push({ host, state: `http_${r.status}` }); continue; }
        const v = judgeAssetLinks(r.text, app.package, isBundle ? null : certs);
        result.assetlinks.push({ host, state: v.state });
        if (v.state === 'invalid') missing.push(`${host} → served, but not a valid assetlinks.json array`);
        else if (v.state === 'package_missing') mismatch.push(`${host} → no handle_all_urls statement for ${app.package}`);
        else if (v.state === 'fingerprint_mismatch') mismatch.push(`${host} → lists ${v.listed.slice(0, 3).map(f => mask(f, 6)).join(', ') || 'no fingerprint'}; the package is signed with ${certs.map(c => mask(c, 6)).join(', ')}`);
      } catch (err) { failed(`assetlinks.json for ${host}`, err); }
    }
    if (data.verifyHosts.size > hosts.length) notes.push(`${app.package}: ${data.verifyHosts.size - hosts.length} autoVerify host(s) were not checked online (non-public name or more than ${MAX_HOSTS}).`);
    if (missing.length) findings.add('android.online.assetlinks_missing', { ...base, artifact: art, description: 'android:autoVerify hosts that do not serve a usable Digital Asset Links file. Android cannot verify these links, so another app can claim them.', evidence: missing });
    if (mismatch.length) findings.add('android.online.assetlinks_mismatch', { ...base, artifact: art, description: 'The assetlinks.json of an autoVerify host does not authorise this package / signing certificate, so link verification fails and the links are not exclusive to this app.', evidence: mismatch });

    // ── Firebase ──────────────────────────────────────────────────────────────────────────────────
    const fb = data.firebase;
    const dbUrls = [...new Set([...(fb.dbUrl ? [fb.dbUrl] : []), ...data.dbUrls])].map(u => { try { return new URL(u).origin; } catch { return null; } })
      .filter(o => o && FIREBASE_DB_ORIGIN.test(o)).slice(0, 5);
    const open = [];
    for (const origin of [...new Set(dbUrls)]) {
      log(`online: ${origin}/.json?shallow=true`);
      try {
        const r = await request(fetchImpl, `${origin}/.json?shallow=true`, { timeoutMs });
        const state = r.status === 200 ? 'open' : r.status === 401 || r.status === 403 ? 'protected' : r.status === 404 ? 'no_database' : `http_${r.status}`;
        result.firebase_database.push({ url: origin, state });
        if (state === 'open') {
          let n = null;
          try { const j = JSON.parse(r.text); n = j && typeof j === 'object' ? Object.keys(j).length : null; } catch { /* not JSON */ }
          open.push(`${origin} (HTTP 200 without credentials${n === null ? '' : `; ${n} top-level node(s)`}${r.text.trim() === 'null' ? '; the database is empty' : ''})`);
        }
      } catch (err) { failed(`Firebase database ${origin}`, err); }
    }
    if (open.length) findings.add('android.online.firebase_db_open', { ...base, artifact: 'classes.dex', description: 'The Firebase Realtime Database root can be read by anyone on the internet: no authentication was sent. Only the shallow root listing was requested, no data was read or written.', evidence: open });

    const num = /^\d+:(\d+):android:[0-9a-f]+$/i.exec(fb.appId || '');
    if (fb.apiKey && num) {
      const url = `https://firebaseremoteconfig.googleapis.com/v1/projects/${num[1]}/namespaces/firebase:fetch?key=${encodeURIComponent(fb.apiKey)}`;
      log('online: Firebase Remote Config fetch');
      try {
        const r = await request(fetchImpl, url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ appId: fb.appId, appInstanceId: crypto.randomBytes(11).toString('hex') }), timeoutMs });
        let j = null;
        try { j = JSON.parse(r.text); } catch { /* not JSON */ }
        const entries = r.status === 200 && j && j.entries && typeof j.entries === 'object' ? Object.entries(j.entries) : [];
        result.remote_config = { state: r.status === 200 ? (entries.length ? 'entries_exposed' : 'empty') : r.status === 403 || r.status === 400 ? 'restricted' : `http_${r.status}`, entries: entries.length, api_key: mask(fb.apiKey, 4) };
        if (entries.length) {
          findings.add('android.online.remote_config_exposed', { ...base, artifact: 'resources.arsc', description: `Firebase Remote Config answers an unauthenticated fetch made with the API key and app id embedded in the app (${entries.length} parameter(s)). Remote Config is readable by every installation by design, so nothing secret may be stored in it; the values were scanned for secrets.`,
            evidence: entries.slice(0, 15).map(([k]) => k), evidence_total: entries.length });
          const sc = newScanner({ ...base, artifact: 'Firebase Remote Config (online)' });
          sc.add('Firebase Remote Config (online)', entries.map(([k, v]) => `${k} = "${String(typeof v === 'string' ? v : JSON.stringify(v)).replace(/\r?\n|\r/g, ' ').replace(/"/g, '\\"')}"`).filter(l => l.length <= 4000), () => 'value fetched from Firebase Remote Config');
          sc.run();
        }
      } catch (err) { failed('Firebase Remote Config', err); }
    }
    app.online_checks = { performed: true, assetlinks: result.assetlinks, firebase_database: result.firebase_database, remote_config: result.remote_config };
  }
}
