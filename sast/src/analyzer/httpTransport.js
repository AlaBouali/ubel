'use strict';

import https from 'https';
import http from 'http';

// ─── Low-level HTTP transport ─────────────────────────────────────────────────

function httpPost(endpoint, headers, body, timeoutMs) {
  return new Promise((resolve, reject) => {
    const urlObj   = new URL(endpoint);
    const useHttps = urlObj.protocol === 'https:';
    const lib      = useHttps ? https : http;

    const options = {
      hostname: urlObj.hostname,
      port:     urlObj.port || (useHttps ? 443 : 80),
      path:     urlObj.pathname + (urlObj.search || ''),
      method:   'POST',
      headers:  {
        'Content-Type':   'application/json',
        'Content-Length': Buffer.byteLength(body),
        ...headers,
      },
    };

    const req = lib.request(options, (res) => {
      let raw = '';
      res.setEncoding('utf8');
      res.on('data', d => { raw += d; });
      res.on('end', () => {
        if (res.statusCode !== 200) {
          const err = new Error(`HTTP ${res.statusCode}: ${raw.slice(0, 300)}`);
          err.statusCode = res.statusCode;
          // Honour Retry-After header (value is seconds or an HTTP-date string)
          const retryAfter = res.headers['retry-after'];
          if (retryAfter) {
            const secs = parseInt(retryAfter, 10);
            err.retryAfterMs = isNaN(secs)
              ? Math.max(0, new Date(retryAfter).getTime() - Date.now())
              : secs * 1000;
          }
          return reject(err);
        }
        resolve(raw);
      });
    });

    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error(`Request timed out after ${timeoutMs / 1000}s`));
    });

    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

export { httpPost };
