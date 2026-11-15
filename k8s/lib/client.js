'use strict';
// client.js — a minimal read-only Kubernetes API client on node:https / node:http. Only GET requests are ever
// sent. List calls are paginated (limit/continue) and every request has a timeout.

import https from 'node:https';
import http from 'node:http';

class ApiError extends Error {
  constructor(message, status, body) { super(message); this.status = status || 0; this.body = body; }
}

const META_ONLY = 'application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1,application/json';

class KubeClient {
  /** @param {ReturnType<import('./kubeconfig.js').resolveConnection>} conn @param {{timeoutMs?:number}} [opts] */
  constructor(conn, opts = {}) {
    this.conn = conn;
    this.timeoutMs = opts.timeoutMs || 30000;
    this.url = new URL(conn.server);
    this.isHttps = this.url.protocol === 'https:';
    this.agent = this.isHttps
      ? new https.Agent({ keepAlive: true, maxSockets: 6, ...(conn.ca ? { ca: conn.ca } : {}), ...(conn.cert && conn.key ? { cert: conn.cert, key: conn.key } : {}), rejectUnauthorized: !conn.insecure, ...(conn.tlsServerName ? { servername: conn.tlsServerName } : {}) })
      : new http.Agent({ keepAlive: true, maxSockets: 6 });
    this.requests = 0;
  }

  close() { this.agent.destroy(); }

  _request(pathAndQuery, { accept = 'application/json', auth = true } = {}) {
    return new Promise((resolve, reject) => {
      const headers = { Accept: accept, 'User-Agent': 'ubel-k8s' };
      if (auth && this.conn.token) headers.Authorization = `Bearer ${this.conn.token}`;
      const lib = this.isHttps ? https : http;
      const req = lib.request({
        protocol: this.url.protocol, hostname: this.url.hostname, port: this.url.port || (this.isHttps ? 443 : 80),
        path: (this.url.pathname.replace(/\/$/, '') || '') + pathAndQuery, method: 'GET', headers,
        agent: this.agent, ...(auth ? {} : { agent: this.isHttps ? new https.Agent({ ...(this.conn.ca ? { ca: this.conn.ca } : {}), rejectUnauthorized: !this.conn.insecure }) : this.agent }),
      }, (res) => {
        const chunks = [];
        let size = 0;
        res.on('data', (d) => { size += d.length; if (size > 512 * 1024 * 1024) { req.destroy(new Error('response too large')); return; } chunks.push(d); });
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let body = null;
          try { body = text ? JSON.parse(text) : null; } catch { body = text; }
          resolve({ status: res.statusCode, body });
        });
      });
      req.setTimeout(this.timeoutMs, () => req.destroy(new Error(`request timed out after ${this.timeoutMs} ms`)));
      req.on('error', reject);
      req.end();
      this.requests++;
    });
  }

  /** GET one object; throws ApiError on non-2xx. */
  async get(p, opts) {
    const r = await this._request(p, opts);
    if (r.status < 200 || r.status >= 300) throw new ApiError(describe(r), r.status, r.body);
    return r.body;
  }

  /** GET without credentials (used for the anonymous-access probe). Never throws on HTTP status. */
  async getAnonymous(p) {
    try { return await this._request(p, { auth: false }); } catch (e) { return { status: 0, error: e.message }; }
  }

  /** Lists every item of a collection (follows `continue`). `metadataOnly` asks the server for object metadata only. */
  async list(p, { metadataOnly = false, limit = 500 } = {}) {
    const items = [];
    let cont = '';
    let kind = null;
    for (let guard = 0; guard < 2000; guard++) {
      const q = `${p}${p.includes('?') ? '&' : '?'}limit=${limit}${cont ? `&continue=${encodeURIComponent(cont)}` : ''}`;
      const body = await this.get(q, metadataOnly ? { accept: META_ONLY } : undefined);
      if (!body || !Array.isArray(body.items)) throw new ApiError(`unexpected response for ${p}`, 200, body);
      kind = body.kind || kind;
      items.push(...body.items);
      cont = body.metadata && body.metadata.continue;
      if (!cont) break;
    }
    return items;
  }
}

function describe(r) {
  const msg = r.body && typeof r.body === 'object' && r.body.message ? r.body.message : (typeof r.body === 'string' ? r.body.slice(0, 160) : '');
  if (r.status === 401) return `unauthorized (401)${msg ? ': ' + msg : ''}`;
  if (r.status === 403) return `forbidden (403)${msg ? ': ' + msg : ''}`;
  if (r.status === 404) return `not found (404)${msg ? ': ' + msg : ''}`;
  return `HTTP ${r.status}${msg ? ': ' + msg : ''}`;
}

export { KubeClient, ApiError };
