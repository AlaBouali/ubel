'use strict';
// http.js — the one place `ubel-package` talks to a registry. Node's global fetch, with what a security tool needs on top of it:
//   · a hard size cap while streaming (a registry cannot make the tool buffer an unbounded body)
//   · a timeout per request and a few retries on transient errors (429 / 5xx / network), never on 4xx
//   · redirects followed by hand: credentials are sent to the host they were given for and are dropped when a redirect leaves that origin
//   · plain http only when the user asked for an http registry (or --allow-insecure); a registry that answers with a downgrade to http is refused

export class HttpError extends Error {
  constructor(message, { status = null, url = null, transient = false } = {}) { super(message); this.name = 'HttpError'; this.status = status; this.url = url; this.transient = transient; }
}

const sleep = ms => new Promise(r => setTimeout(r, ms));
const originOf = u => { try { return new URL(u).origin; } catch { return ''; } };

/**
 * @param {string} url
 * @param {object} [o]
 * @param {Record<string,string>} [o.headers]   sent to every origin
 * @param {Record<string,string>} [o.authHeaders] sent only to `authOrigin` (and to its redirects while they stay on that origin)
 * @param {string} [o.authOrigin]
 * @param {number} [o.maxBytes]      body cap (default 64 MB)
 * @param {number} [o.timeoutMs]     per attempt (default 30 s)
 * @param {number} [o.retries]       extra attempts on 429 / 5xx / network errors (default 2)
 * @param {boolean} [o.allowHttp]    allow plain http (otherwise https only)
 * @param {'buffer'|'json'|'text'} [o.as]
 * @returns {Promise<{status:number, url:string, headers:Headers, body:Buffer|object|string}>}
 */
export async function httpGet(url, o = {}) {
  const { headers = {}, authHeaders = {}, authOrigin = originOf(url), maxBytes = 64 * 1048576, timeoutMs = 30000, retries = 2, allowHttp = false, as = 'buffer', allow404 = false } = o;
  let last;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try { return await once(url, { headers, authHeaders, authOrigin, maxBytes, timeoutMs, allowHttp, as, allow404 }); }
    catch (e) {
      last = e;
      if (!(e instanceof HttpError) || !e.transient || attempt === retries) throw e;
      await sleep(400 * (attempt + 1) ** 2);
    }
  }
  throw last;
}

async function once(startUrl, { headers, authHeaders, authOrigin, maxBytes, timeoutMs, allowHttp, as, allow404 }) {
  let url = startUrl;
  for (let hop = 0; hop <= 6; hop++) {
    const u = new URL(url);
    if (u.protocol !== 'https:' && !(u.protocol === 'http:' && allowHttp)) throw new HttpError(`refusing ${u.protocol}// request to ${u.host}: only https is used unless the registry itself was given as http (or --allow-insecure)`, { url });
    const h = { 'user-agent': 'ubel-package', accept: '*/*', ...headers, ...(u.origin === authOrigin ? authHeaders : {}) };
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), timeoutMs);
    let res;
    try { res = await fetch(url, { headers: h, redirect: 'manual', signal: ctl.signal }); }
    catch (e) { clearTimeout(timer); throw new HttpError(`${u.host}: ${e.name === 'AbortError' ? `timed out after ${timeoutMs / 1000}s` : (e.cause?.code || e.message)}`, { url, transient: true }); }
    if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
      clearTimeout(timer);
      try { await res.body?.cancel(); } catch { /* ignore */ }
      url = new URL(res.headers.get('location'), url).href;
      continue;
    }
    try {
      if (res.status === 404 && allow404) { try { await res.body?.cancel(); } catch { /* ignore */ } return { status: 404, url, headers: res.headers, body: null }; }
      if (!res.ok) {
        try { await res.body?.cancel(); } catch { /* ignore */ }
        throw new HttpError(`${u.host}${u.pathname}: HTTP ${res.status}`, { status: res.status, url, transient: res.status === 429 || res.status >= 500 });
      }
      const declared = Number(res.headers.get('content-length'));
      if (declared > maxBytes) { try { await res.body?.cancel(); } catch { /* ignore */ } throw new HttpError(`${u.host}${u.pathname}: ${Math.round(declared / 1048576)} MB is over the ${Math.round(maxBytes / 1048576)} MB limit`, { url }); }
      const chunks = []; let n = 0;
      const reader = res.body.getReader();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        n += value.length;
        if (n > maxBytes) { try { await reader.cancel(); } catch { /* ignore */ } throw new HttpError(`${u.host}${u.pathname}: the body is over the ${Math.round(maxBytes / 1048576)} MB limit`, { url }); }
        chunks.push(value);
      }
      const buf = Buffer.concat(chunks);
      let body = buf;
      if (as === 'text') body = buf.toString('utf8');
      else if (as === 'json') { try { body = JSON.parse(buf.toString('utf8')); } catch { throw new HttpError(`${u.host}${u.pathname}: the response is not valid JSON`, { url }); } }
      return { status: res.status, url, headers: res.headers, body };
    } finally { clearTimeout(timer); }
  }
  throw new HttpError(`too many redirects from ${startUrl}`, { url: startUrl });
}
