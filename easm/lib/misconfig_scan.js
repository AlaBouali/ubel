// easm/lib/misconfig_scan.js
//
// Checks each scanned host for a fixed, deliberately small set of
// well-known web misconfigurations rather than any kind of general
// vulnerability scanning:
//
//   - exposed .env file
//   - exposed .git directory (via .git/HEAD, enriched with .git/config)
//   - WordPress xmlrpc.php reachable (only on hosts WordPress was already
//     detected on, per the fingerprinter's own component inventory)
//   - WordPress user enumeration via wp-json/wp/v2/users (same gating)
//   - exposed phpinfo() output (info.php / phpinfo.php)
//   - missing / weak HTTP security headers on the site root:
//       * Strict-Transport-Security (HSTS) — presence, max-age, and the
//         "explicitly disabled" max-age=0 case
//       * clickjacking protection via X-Frame-Options and/or a CSP
//         frame-ancestors directive
//   - TLS/certificate weaknesses: expiry, trust, hostname match, weak
//     protocol/cipher, explicit legacy-protocol (TLS 1.0/1.1) downgrade
//     acceptance — and outright absence of a working HTTPS listener on a
//     host that isn't serving TLS at all — all via Node's own stdlib
//     `tls` module. No external tool (nmap, testssl.sh, openssl CLI) and
//     no third-party TLS library is used or required; Node's TLS support
//     is backed by the OpenSSL build already bundled with the runtime,
//     the same way every other HTTPS request in this codebase already
//     works.
//
// Each HTTP-based check fetches one specific, well-known path with
// maxRedirects: 0 — a redirect away from e.g. /.env means the path isn't
// directly exposed, which is the opposite of a finding, so this
// deliberately does not follow it. A single soft-404 baseline probe per
// host (a random, guaranteed-nonexistent path) guards against catch-all
// routing (SPAs that return 200 + their index page for any path) being
// misread as every probed path existing.
//
// Same posture as the rest of this module (see ../README.md): passive,
// one well-known path per check, no brute-forcing, no wordlists.

import { httpClient } from "../fingerprint/src/core/httpClient.js";
import { mapLimit } from "../../cloud/lib/concurrency.js";
import { scanContent } from "../../sca/secrets.js";
import tls from "node:tls";
import { URL } from "node:url";

const MAX_CHECK_BODY_BYTES = 2 * 1024 * 1024;

// ── URL parsing ──────────────────────────────────────────────────────────

/**
 * Parses `asset.resolved_url` into a URL, tolerating every shape the
 * fingerprinter actually produces for `asset`:
 *
 *   - a full absolute URL   ("https://host/path")
 *   - a bare authority      ("host", "host:443")
 *   - the pathological case where `new URL("host:443")` "succeeds" by
 *     treating "host" as the scheme and leaving hostname empty
 *
 * Anything without a scheme is assumed HTTPS — the fingerprinter only
 * falls back to HTTP when HTTPS was tried and failed, and a bare hostname
 * that reached this far almost always means "default secure port".
 *
 * Returns null only for input neither shape can parse (empty, garbage,
 * embedded spaces) — callers decide whether that's a skip or an error.
 */
function parseResolvedUrl(raw) {
  if (!raw || typeof raw !== "string") return null;
  const trimmed = raw.trim();
  if (!trimmed) return null;

  // Direct parse first — preserves an explicit http:// or https://.
  let u = null;
  try { u = new URL(trimmed); } catch { /* fall through */ }

  // A URL with no hostname is useless here. This catches "host:443",
  // which the WHATWG parser accepts as scheme="host", path="443".
  if (u && u.hostname) return u;

  // Retry with an explicit HTTPS scheme.
  try {
    const alt = new URL("https://" + trimmed);
    if (alt.hostname) return alt;
  } catch { /* fall through */ }

  return null;
}

// ── Soft-404 baseline ────────────────────────────────────────────────────

async function getSoft404Baseline(origin, timeout) {
  const probePath = `/__ubel_probe_${Math.random().toString(36).slice(2)}_${Date.now()}__`;
  try {
    const res = await httpClient.get(origin + probePath, { timeout, maxRedirects: 0 });
    return { status: res.status_code, bodyLength: res.text.length, bodySample: res.text.slice(0, 500) };
  } catch {
    return null;
  }
}

/** True if `res` looks like the same catch-all response the baseline probe
 *  got for a path that's guaranteed not to exist — i.e. not a real hit. */
function isSoft404(res, baseline) {
  if (!baseline || baseline.status !== 200 || res.status_code !== 200) return false;
  return res.text.length === baseline.bodyLength && res.text.slice(0, 500) === baseline.bodySample;
}

// ── HTTP-based checks ────────────────────────────────────────────────────

async function checkEnvFile(origin, asset, baseline, timeout, findings, errors) {
  const url = origin + "/.env";
  let res;
  try {
    res = await httpClient.get(url, { timeout, maxRedirects: 0 });
  } catch (e) {
    errors.push({ target: asset.target, check: "exposed-env-file", url, error: e.message });
    return;
  }
  if (res.status_code !== 200 || isSoft404(res, baseline)) return;

  const body = res.text;
  if (!body || body.length > MAX_CHECK_BODY_BYTES) return;
  if (/<html[\s>]/i.test(body.slice(0, 500))) return;

  const envLineCount = (body.match(/^[A-Za-z_][A-Za-z0-9_]*\s*=.*/gm) || []).length;
  if (envLineCount < 1) return;

  // Cross-reference with the same secrets rules the Secrets tab uses — a
  // real .env is confirmation enough, but knowing which specific
  // credentials it contains (redacted) is what makes the finding
  // actionable rather than just alarming.
  let secretHits = [];
  try {
    secretHits = scanContent(body, { filePath: ".env", projectRoot: "/" });
  } catch {
    /* non-fatal — the exposure finding stands regardless */
  }

  findings.push({
    id: "exposed-env-file",
    title: "Exposed .env file",
    category: "Exposed File",
    severity: secretHits.length ? "critical" : "high",
    url,
    target: asset.target,
    description: secretHits.length
      ? `A .env file is publicly readable and contains ${secretHits.length} value(s) matching known credential patterns.`
      : `A .env file is publicly readable (${envLineCount} KEY=VALUE line(s) detected). No specific credential pattern matched here, but .env files routinely hold database, API, and session secrets regardless.`,
    evidence: secretHits.slice(0, 10).map((s) => `${s.secret_type}: ${s.match_preview}`),
    remediation:
      "Remove .env from the web root immediately — it belongs outside anything the web server serves at all, not merely blocked by a rule — and rotate every credential it contained; treat all of them as compromised since this was publicly readable. Add a server-level rule denying dotfiles as defense in depth, and confirm the deploy process never copies .env into the served directory in the first place.",
  });
}

async function checkGitExposure(origin, asset, baseline, timeout, findings, errors) {
  const headUrl = origin + "/.git/HEAD";
  let res;
  try {
    res = await httpClient.get(headUrl, { timeout, maxRedirects: 0 });
  } catch (e) {
    errors.push({ target: asset.target, check: "exposed-git-directory", url: headUrl, error: e.message });
    return;
  }
  if (res.status_code !== 200 || isSoft404(res, baseline)) return;

  const body = res.text.trim();
  const looksLikeGitHead = /^ref:\s*refs\/[\w./-]+$/.test(body) || /^[0-9a-f]{40}$/i.test(body);
  if (!looksLikeGitHead) return;

  // Best-effort enrichment only — the finding already stands on HEAD alone.
  let remote = null;
  try {
    const cfgRes = await httpClient.get(origin + "/.git/config", { timeout, maxRedirects: 0 });
    if (cfgRes.status_code === 200 && /\[core\]/.test(cfgRes.text)) {
      const m = cfgRes.text.match(/\[remote\s+"[^"]+"\][^[]*?url\s*=\s*(\S+)/i);
      if (m) remote = m[1];
    }
  } catch {
    /* best-effort only */
  }

  findings.push({
    id: "exposed-git-directory",
    title: "Exposed .git directory",
    category: "Exposed File",
    severity: "critical",
    url: headUrl,
    target: asset.target,
    description:
      `The .git directory is publicly accessible (HEAD: ${body}${remote ? `, remote: ${remote}` : ""}). ` +
      "The entire repository — full commit history, deleted branches, and anything ever committed — can typically be reconstructed from this alone, not just the current checkout.",
    evidence: remote ? [`remote: ${remote}`, `HEAD: ${body}`] : [`HEAD: ${body}`],
    remediation:
      "Remove the .git directory from the production web root — deploy a build artifact or a git archive/export, never the raw working checkout. Treat the repository's full history as disclosed: rotate any credential that ever appeared in any commit, including on deleted branches, not just the current HEAD. Blocking /.git/ at the web server level is reasonable defense in depth, but is not the underlying fix.",
  });
}

async function checkXmlrpc(origin, asset, baseline, timeout, findings, errors) {
  const url = origin + "/xmlrpc.php";
  let res;
  try {
    res = await httpClient.get(url, { timeout, maxRedirects: 0 });
  } catch (e) {
    errors.push({ target: asset.target, check: "wp-xmlrpc-exposed", url, error: e.message });
    return;
  }
  if (isSoft404(res, baseline)) return;
  if (![200, 405].includes(res.status_code)) return;
  if (!/XML-RPC server accepts POST requests only/i.test(res.text)) return;

  findings.push({
    id: "wp-xmlrpc-exposed",
    title: "WordPress XML-RPC enabled (xmlrpc.php reachable)",
    category: "WordPress",
    severity: "medium",
    url,
    target: asset.target,
    description:
      "xmlrpc.php responds and is reachable without authentication. Its pingback and system.multicall methods are routinely abused for DDoS amplification (pingback) and for brute-forcing hundreds of password guesses in a single request, bypassing normal login rate limiting.",
    evidence: [],
    remediation:
      "Disable XML-RPC if it isn't in active use (most sites don't need it once legacy mobile apps/Jetpack aren't relied on) — block both GET and POST to /xmlrpc.php at the web server level (return 403), or use a plugin that disables it cleanly. If it's genuinely needed, restrict access by IP and rate-limit it rather than leaving it open to the internet.",
  });
}

async function checkWpUserEnum(origin, asset, baseline, timeout, findings, errors) {
  const url = origin + "/wp-json/wp/v2/users";
  let res;
  try {
    res = await httpClient.get(url, { timeout, maxRedirects: 0 });
  } catch (e) {
    errors.push({ target: asset.target, check: "wp-user-enumeration", url, error: e.message });
    return;
  }
  if (res.status_code !== 200 || isSoft404(res, baseline)) return;

  let data;
  try {
    data = res.json();
  } catch {
    return;
  }
  if (!Array.isArray(data) || !data.length) return;

  const usernames = data.map((u) => u && (u.slug || u.name)).filter(Boolean).slice(0, 20);
  if (!usernames.length) return;

  findings.push({
    id: "wp-user-enumeration",
    title: "WordPress user list exposed via REST API",
    category: "WordPress",
    severity: "medium",
    url,
    target: asset.target,
    description: `wp-json/wp/v2/users publicly lists ${data.length} user account(s), disclosing usernames/slugs usable for targeted login brute-forcing.`,
    evidence: usernames,
    remediation:
      "Restrict or remove the wp/v2/users REST route for unauthenticated requests (filter it out via the rest_endpoints hook in a small mu-plugin, or a security plugin's user-enumeration protection), and avoid reusing the login username as the public display name — that way exposure of one doesn't hand over the other.",
  });
}

const INFO_PHP_PATHS = ["/info.php", "/phpinfo.php"];

async function checkInfoPhp(origin, asset, baseline, timeout, findings, errors) {
  for (const p of INFO_PHP_PATHS) {
    const url = origin + p;
    let res;
    try {
      res = await httpClient.get(url, { timeout, maxRedirects: 0 });
    } catch (e) {
      errors.push({ target: asset.target, check: "exposed-phpinfo", url, error: e.message });
      continue;
    }
    if (res.status_code !== 200 || isSoft404(res, baseline)) continue;

    const body = res.text;
    if (body.length > MAX_CHECK_BODY_BYTES) continue;
    if (!/phpinfo\(\)/i.test(body) && !/PHP Version/i.test(body)) continue;

    const versionMatch = body.match(/PHP Version\s*(?:<\/td>\s*<td[^>]*>)?\s*([\d.]+)/i);

    findings.push({
      id: "exposed-phpinfo",
      title: "phpinfo() output publicly accessible",
      category: "Exposed File",
      severity: "high",
      url,
      target: asset.target,
      description: `${p} discloses the full PHP configuration${versionMatch ? ` (PHP ${versionMatch[1]})` : ""} — loaded extensions, absolute server file paths, and sometimes environment variables — to anyone who requests it.`,
      evidence: versionMatch ? [`PHP ${versionMatch[1]}`] : [],
      remediation:
        "Delete this file from the server immediately — it should never exist in a production deployment. If phpinfo() output is genuinely needed for debugging, gate it behind authentication or an IP allowlist, and remove it again once done.",
    });
    return; // one finding covers the underlying mistake; no need to flag every alias
  }
}

// ── TLS/SSL checks ───────────────────────────────────────────────────────
// Node's own tls module only — no external tool, no third-party library.
// rejectUnauthorized is deliberately false on every connection here (same
// reasoning httpClient.js already documents): a failed handshake refuses
// to complete at all with verification on, which would hide exactly the
// cert problems this is trying to find. socket.authorized/
// authorizationError carries the real verification result regardless.

const WEAK_CIPHER_PATTERNS = [/\bRC4\b/i, /\bDES\b/i, /\b3DES\b/i, /\bMD5\b/i, /\bNULL\b/i, /EXPORT/i, /aNULL/i, /eNULL/i, /\banon\b/i];

const TLS_TITLES = {
  "tls-cert-expired": "TLS certificate expired",
  "tls-cert-expiring-soon": "TLS certificate expiring soon",
  "tls-cert-not-yet-valid": "TLS certificate not yet valid",
  "tls-cert-untrusted": "TLS certificate not trusted",
  "tls-hostname-mismatch": "TLS certificate hostname mismatch",
  "tls-weak-protocol-negotiated": "Weak TLS/SSL protocol negotiated by default",
  "tls-weak-cipher": "Weak TLS cipher suite negotiated",
  "tls-legacy-protocol-supported": "Legacy TLS protocol still accepted",
  "tls-no-https": "No working HTTPS listener",
  "tls-broken": "TLS handshake fails on an HTTPS URL",
};

function mkTlsFinding(id, severity, target, hostname, port, description, remediation, evidence = []) {
  return {
    id,
    title: TLS_TITLES[id] || id,
    category: "TLS/SSL",
    severity,
    url: `${hostname}:${port}`,
    target,
    description,
    evidence,
    remediation,
  };
}

function originHostPort(asset) {
  const u = parseResolvedUrl(asset.resolved_url);
  if (!u) return null;
  const isHttps = u.protocol === "https:";
  // For an HTTPS URL, use the URL's own port (default 443). For an HTTP
  // URL, always probe the standard HTTPS port (443) for a separate,
  // possibly-misconfigured TLS listener, regardless of which port the
  // HTTP service itself is on — that's exactly the mismatch this check
  // exists to catch. (An http-only host with a working HTTPS listener on
  // 443 gets its cert/header checks; an http-only host with nothing on
  // 443 gets the `tls-no-https` finding instead of silence.)
  const port = isHttps ? (u.port ? parseInt(u.port, 10) : 443) : 443;
  return { hostname: u.hostname, port, isHttps };
}

function tlsConnectOnce(hostname, ip, port, tlsOpts, timeoutMs) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const socket = tls.connect({
      host: ip || hostname,
      port,
      servername: hostname,
      timeout: timeoutMs,
      rejectUnauthorized: false,
      ...tlsOpts,
    });
    const done = (fn, val) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      fn(val);
    };
    socket.once("secureConnect", () => {
      done(resolve, {
        authorized: socket.authorized,
        authorizationError: socket.authorizationError || null,
        protocol: socket.getProtocol(),
        cipher: socket.getCipher(),
        cert: socket.getPeerCertificate(false),
      });
    });
    socket.once("error", (err) => done(reject, err));
    socket.once("timeout", () => done(reject, new Error("TLS connection timed out")));
  });
}

/**
 * @returns {Promise<{findings: object[], httpsAvailable: boolean}>}
 *   `httpsAvailable` is true only if a working TLS handshake completed —
 *   callers use it to decide whether HSTS is worth evaluating, and to
 *   distinguish "no TLS at all" from "TLS present but misconfigured".
 */
async function checkTls(asset, timeout) {
  const info = originHostPort(asset);
  if (!info) return { findings: [], httpsAvailable: false };
  const { hostname, port, isHttps } = info;
  const ip = asset.resolved_ip || null;
  const target = asset.target;
  const timeoutMs = Math.max(1, timeout) * 1000;
  const findings = [];

  let primary;
  try {
    primary = await tlsConnectOnce(hostname, ip, port, {}, timeoutMs);
  } catch (e) {
    if (isHttps) {
      // The URL the fingerprinter recorded is HTTPS, so this host is
      // *supposed* to be serving TLS here. A failed handshake means the
      // scheme it advertises is broken outright — worse than "no HTTPS",
      // since clients will try HTTPS first and fail hard.
      findings.push(
        mkTlsFinding(
          "tls-broken", "critical", target, hostname, port,
          `The site's resolved URL uses HTTPS, but the TLS handshake on ${hostname}:${port} failed (${e.message}). The service is unreachable over the scheme it advertises.`,
          "Restore the TLS listener: confirm the certificate file is readable and valid, that the service is bound to the right interface/port, and that the full chain (including any intermediate certificate) is being presented. Until this is fixed, users and API clients cannot connect over HTTPS at all."
        )
      );
    } else {
      // HTTP URL, and no TLS listener on 443 either — plaintext-only host.
      findings.push(
        mkTlsFinding(
          "tls-no-https", "medium", target, hostname, port,
          `No working TLS listener was found on ${hostname}:${port}. The host serves plaintext HTTP only, so every request and response — including login credentials, session cookies, and any submitted form data — is readable and modifiable by anyone on the network path between client and server.`,
          "Install a TLS certificate (Let's Encrypt is free and fully automatable via certbot/ACME), terminate TLS at the web server or a load balancer/CDN in front of it, then 301-redirect all HTTP traffic to HTTPS. Once that redirect is reliable, add an HSTS header so browsers refuse to downgrade in future."
        )
      );
    }
    return { findings, httpsAvailable: false };
  }

  const cert = primary.cert;
  const now = Date.now();

  // ── Certificate validity window ────────────────────────────────────────
  if (cert && cert.valid_to) {
    const validTo = new Date(cert.valid_to).getTime();
    const daysLeft = (validTo - now) / 86400000;
    if (Number.isFinite(daysLeft) && daysLeft < 0) {
      findings.push(
        mkTlsFinding(
          "tls-cert-expired", "critical", target, hostname, port,
          `The TLS certificate expired ${Math.abs(Math.round(daysLeft))} day(s) ago (${cert.valid_to}).`,
          "Renew the certificate immediately — most browsers and API clients hard-fail on an expired certificate. Automate renewal (e.g. ACME/Let's Encrypt on a cron/systemd timer) so this can't silently recur."
        )
      );
    } else if (Number.isFinite(daysLeft) && daysLeft < 14) {
      findings.push(
        mkTlsFinding(
          "tls-cert-expiring-soon", "high", target, hostname, port,
          `The TLS certificate expires in ${Math.ceil(daysLeft)} day(s) (${cert.valid_to}).`,
          "Renew the certificate now and verify automated renewal is actually running — a certificate this close to expiry usually means the renewal job silently stopped working."
        )
      );
    } else if (Number.isFinite(daysLeft) && daysLeft < 30) {
      findings.push(
        mkTlsFinding(
          "tls-cert-expiring-soon", "medium", target, hostname, port,
          `The TLS certificate expires in ${Math.ceil(daysLeft)} day(s) (${cert.valid_to}).`,
          "Renew the certificate before it expires and confirm automated renewal is configured."
        )
      );
    }
  }
  if (cert && cert.valid_from && new Date(cert.valid_from).getTime() > now) {
    findings.push(
      mkTlsFinding(
        "tls-cert-not-yet-valid", "medium", target, hostname, port,
        `The certificate's validity period doesn't start until ${cert.valid_from}.`,
        "Check the server's clock and how/when this certificate was issued — a not-yet-valid certificate usually means clock skew, or a certificate swapped in ahead of its intended start date."
      )
    );
  }

  // ── Trust / hostname match ─────────────────────────────────────────────
  if (!primary.authorized) {
    const code = (primary.authorizationError && primary.authorizationError.code) || String(primary.authorizationError || "");
    if (/HOSTNAME_MISMATCH|ALTNAME/i.test(code)) {
      findings.push(
        mkTlsFinding(
          "tls-hostname-mismatch", "high", target, hostname, port,
          `The certificate does not cover ${hostname} (${code}).`,
          "Issue or install a certificate whose Subject Alternative Names actually include this hostname — clients will show a trust warning or hard-fail otherwise."
        )
      );
    } else if (/SELF_SIGNED|UNABLE_TO_VERIFY_LEAF_SIGNATURE|UNABLE_TO_GET_ISSUER_CERT/i.test(code)) {
      findings.push(
        mkTlsFinding(
          "tls-cert-untrusted", "high", target, hostname, port,
          `The certificate is not signed by a trusted CA (${code}).`,
          "Replace it with a certificate from a publicly trusted CA (Let's Encrypt is free and automatable) — a self-signed or privately-issued certificate on a public-facing host triggers browser trust warnings and breaks most automated API clients by default."
        )
      );
    } else if (!/CERT_HAS_EXPIRED/i.test(code)) {
      // Expiry is already covered above via valid_to directly; anything
      // else here is a generic chain/trust failure worth surfacing too.
      findings.push(
        mkTlsFinding(
          "tls-cert-untrusted", "high", target, hostname, port,
          `The certificate failed trust verification (${code || "unknown reason"}).`,
          "Investigate the certificate chain — it may be missing an intermediate certificate, or be signed by a CA not present in standard trust stores."
        )
      );
    }
  }

  // ── Negotiated protocol / cipher ───────────────────────────────────────
  const proto = primary.protocol;
  if (proto && /^(SSLv3|TLSv1)$/.test(proto)) {
    findings.push(
      mkTlsFinding(
        "tls-weak-protocol-negotiated", "high", target, hostname, port,
        `The server negotiated ${proto} by default, which is vulnerable to known protocol-level attacks (e.g. POODLE/BEAST) and rejected outright by modern clients and PCI-DSS.`,
        "Disable SSLv3 and TLS 1.0 in the web server/load balancer configuration and require TLS 1.2 or newer."
      )
    );
  } else if (proto === "TLSv1.1") {
    findings.push(
      mkTlsFinding(
        "tls-weak-protocol-negotiated", "medium", target, hostname, port,
        "The server negotiated TLS 1.1 by default, which is deprecated and disabled by default in current browsers.",
        "Disable TLS 1.1 and require TLS 1.2 or newer."
      )
    );
  }

  const cipherName = (primary.cipher && (primary.cipher.standardName || primary.cipher.name)) || "";
  if (cipherName && WEAK_CIPHER_PATTERNS.some((re) => re.test(cipherName))) {
    findings.push(
      mkTlsFinding(
        "tls-weak-cipher", "medium", target, hostname, port,
        `The server negotiated a weak cipher suite by default (${cipherName}).`,
        "Remove legacy cipher suites (RC4, DES/3DES, export-grade, anonymous/NULL ciphers) from the server's configured cipher list and keep only modern AEAD suites."
      )
    );
  }

  // ── Explicit legacy-protocol downgrade probing ─────────────────────────
  // Even when the server prefers something modern by default, it may
  // still accept a connection that explicitly requests TLS 1.0/1.1 — worth
  // checking even when the "negotiated by default" check above found
  // nothing, since deliberately requesting the weak version is exactly how
  // a downgrade attack would probe. A failed probe here is not treated as
  // proof of safety: it's equally consistent with the server correctly
  // refusing the legacy handshake (the good outcome) and with this
  // runtime's own OpenSSL build refusing to even attempt one — either way,
  // there's nothing conclusive to report from that specific outcome.
  for (const legacy of ["TLSv1", "TLSv1.1"]) {
    try {
      await tlsConnectOnce(hostname, ip, port, { minVersion: legacy, maxVersion: legacy }, timeoutMs);
      findings.push(
        mkTlsFinding(
          "tls-legacy-protocol-supported", legacy === "TLSv1" ? "high" : "medium", target, hostname, port,
          `The server still accepts a connection explicitly restricted to ${legacy}, even though a modern client wouldn't negotiate it by default.`,
          `Disable ${legacy} entirely in the server/load balancer TLS configuration rather than relying on client preference order to avoid it.`
        )
      );
    } catch {
      /* refused (good) or untestable here — nothing to report either way */
    }
  }

  return { findings, httpsAvailable: true };
}

// ── HTTP security header checks ─────────────────────────────────────────

/** Case-insensitive lookup across the header shapes httpClient may return
 *  (plain object, array values, or a Headers-like object with .get()). */
function pickHeader(headers, name) {
  if (!headers) return null;
  const want = name.toLowerCase();
  if (typeof headers.get === "function") return headers.get(name) || null;
  for (const k of Object.keys(headers)) {
    if (k.toLowerCase() === want) {
      const v = headers[k];
      return Array.isArray(v) ? v.join(", ") : v;
    }
  }
  return null;
}

// 6 months, per common guidance (Mozilla / OWASP both land around here).
const HSTS_MIN_MAX_AGE = 15768000;

async function checkSecurityHeaders(asset, httpsAvailable, timeout, findings, errors) {
  const u = parseResolvedUrl(asset.resolved_url);
  if (!u) return;

  // Prefer HTTPS whenever a working listener is available: HSTS can only
  // be observed on an HTTPS response (browsers ignore STS delivered over
  // plain HTTP), and the clickjacking headers should be identical on both
  // schemes, so one fetch over HTTPS is enough. If no HTTPS is available,
  // fall back to HTTP so clickjacking protection can still be evaluated.
  const url = httpsAvailable ? `https://${u.hostname}/` : `http://${u.hostname}/`;

  let res;
  try {
    res = await httpClient.get(url, { timeout, maxRedirects: 0 });
  } catch (e) {
    errors.push({ target: asset.target, check: "security-headers", url, error: e.message });
    return;
  }
  // A redirect or 4xx/5xx at the origin root means there's no meaningful
  // page here to evaluate — treat as "nothing to check", not a finding.
  if (res.status_code < 200 || res.status_code >= 300) return;

  const isHttps = url.startsWith("https://");
  const h = res.headers;

  // ── HSTS ─────────────────────────────────────────────────────────────
  if (isHttps) {
    const hsts = pickHeader(h, "strict-transport-security");
    if (!hsts) {
      findings.push({
        id: "missing-hsts",
        title: "Missing HSTS header (Strict-Transport-Security)",
        category: "Security Headers",
        severity: "medium",
        url,
        target: asset.target,
        description:
          "The HTTPS response does not carry a Strict-Transport-Security header. Without HSTS, the very first request of every new session is still sent over plain HTTP before the server can redirect it, leaving an SSL-stripping window on every visit — including for users who type the bare hostname.",
        evidence: [],
        remediation:
          "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on every HTTPS response. Test with a short max-age (e.g. 300) first so you can back out quickly, then raise it. Add `preload` only once you're certain every subdomain is HTTPS-ready, since preload submissions are slow to reverse.",
      });
    } else {
      const m = hsts.match(/max-age\s*=\s*(\d+)/i);
      const maxAge = m ? parseInt(m[1], 10) : 0;
      if (maxAge === 0) {
        findings.push({
          id: "hsts-disabled",
          title: "HSTS explicitly disabled (max-age=0)",
          category: "Security Headers",
          severity: "medium",
          url,
          target: asset.target,
          description:
            "The Strict-Transport-Security header is present but sets max-age=0, which instructs browsers to discard any previously stored HSTS policy for this host — actively removing HTTPS enforcement rather than adding it.",
          evidence: [`Strict-Transport-Security: ${hsts}`],
          remediation:
            "Set max-age to at least 15768000 (6 months) with includeSubDomains. max-age=0 is only appropriate as a deliberate step when permanently decommissioning HSTS for a host.",
        });
      } else if (maxAge < HSTS_MIN_MAX_AGE) {
        findings.push({
          id: "hsts-short-max-age",
          title: "HSTS max-age below recommended minimum",
          category: "Security Headers",
          severity: "low",
          url,
          target: asset.target,
          description: `The Strict-Transport-Security header sets max-age=${maxAge} (~${Math.max(1, Math.round(maxAge / 86400))} day(s)), below the commonly recommended 6-month floor. Short max-age values leave users unprotected between visits more often than necessary and are not eligible for the HSTS preload list.`,
          evidence: [`Strict-Transport-Security: ${hsts}`],
          remediation:
            "Raise max-age to at least 15768000 (6 months); 31536000 (1 year) is typical for production and required for preload-list submission.",
        });
      }
    }
  }

  // ── Clickjacking protection ─────────────────────────────────────────
  const xfo = pickHeader(h, "x-frame-options");
  const csp = pickHeader(h, "content-security-policy");
  const hasFrameAncestors = !!(csp && /frame-ancestors\s+/i.test(csp));
  const xfoValid = !!(xfo && /^\s*(DENY|SAMEORIGIN)\s*$/i.test(xfo));

  if (xfoValid || hasFrameAncestors) return; // protection present

  if (xfo) {
    // Header present but with a value modern browsers ignore.
    findings.push({
      id: "weak-clickjacking-protection",
      title: "X-Frame-Options set to a value browsers ignore",
      category: "Security Headers",
      severity: "low",
      url,
      target: asset.target,
      description: `X-Frame-Options is set to "${xfo}", which is not one of the values modern browsers honor (DENY / SAMEORIGIN). ALLOW-FROM in particular is deprecated and unsupported across current browsers, so this provides no clickjacking protection at all.`,
      evidence: [`X-Frame-Options: ${xfo}`],
      remediation:
        "Use `X-Frame-Options: DENY` (or `SAMEORIGIN` if same-origin framing is needed). Add `Content-Security-Policy: frame-ancestors 'self'` as well — modern browsers prefer CSP, and X-Frame-Options alone is not sufficient going forward.",
    });
  } else {
    findings.push({
      id: "missing-clickjacking-protection",
      title: "Missing clickjacking protection",
      category: "Security Headers",
      severity: "medium",
      url,
      target: asset.target,
      description:
        "Neither X-Frame-Options (DENY/SAMEORIGIN) nor a Content-Security-Policy frame-ancestors directive is set, so the page can be embedded in an iframe on any third-party site and overlaid with decoy UI — the classic clickjacking / UI-redress setup.",
      evidence: [],
      remediation:
        "Send `X-Frame-Options: SAMEORIGIN` (or `DENY` for pages never meant to be framed even by same-origin content) for legacy browser coverage, plus `Content-Security-Policy: frame-ancestors 'self'` for modern browsers. CSP frame-ancestors takes precedence where both are present, so setting both is safe.",
    });
  }
}

// ── Orchestration ────────────────────────────────────────────────────────

function hostsWithWordPress(inventory) {
  const set = new Set();
  for (const item of inventory || []) {
    if (!item.wp_kind) continue;
    for (const a of item.assets || []) set.add(a.target);
  }
  return set;
}

/**
 * Checks every scanned asset for the fixed set of misconfigurations this
 * module knows about. Never throws — a host that fails every check
 * contributes no findings and possibly entries in `errors`, so a
 * misconfiguration problem can't abort a scan that otherwise succeeded.
 *
 * @param {object[]} assets      from scanTargets(); only status "scanned" entries are checked
 * @param {object[]} inventory   from scanTargets(); used only to gate the WordPress-specific checks
 * @param {object} [opts]
 * @param {number} [opts.concurrency]
 * @param {number} [opts.timeout]   seconds per request (default 8 — these are all single
 *   well-known-path probes, not page loads, so a short timeout is appropriate)
 * @param {function} [opts.log]
 * @returns {Promise<{findings: object[], errors: object[], stats: object}>}
 */
export async function scanMisconfigurations(assets, inventory, opts = {}) {
  const { concurrency = 4, timeout = 8, log = () => {} } = opts;

  const crawlable = (assets || []).filter((a) => a.status === "scanned" && a.resolved_url);
  if (!crawlable.length) {
    return { findings: [], errors: [], stats: { hosts_checked: 0, hosts_wp_checked: 0, total: 0, by_severity: {}, by_category: {} } };
  }

  const wpHosts = hostsWithWordPress(inventory);
  log(`[*] Checking ${crawlable.length} host(s) for common misconfigurations...`);

  const results = await mapLimit(crawlable, concurrency, async (asset) => {
    const parsed = parseResolvedUrl(asset.resolved_url);
    if (!parsed) {
      return {
        findings: [],
        errors: [{
          target: asset.target,
          check: "origin",
          error: `unparseable resolved_url: ${JSON.stringify(asset.resolved_url)}`,
        }],
      };
    }
    const origin = `${parsed.protocol}//${parsed.host}`;

    const findings = [];
    const errors = [];
    const isWp = wpHosts.has(asset.target);

    const baseline = await getSoft404Baseline(origin, timeout);

    await checkEnvFile(origin, asset, baseline, timeout, findings, errors);
    await checkGitExposure(origin, asset, baseline, timeout, findings, errors);
    if (isWp) {
      await checkXmlrpc(origin, asset, baseline, timeout, findings, errors);
      await checkWpUserEnum(origin, asset, baseline, timeout, findings, errors);
    }
    await checkInfoPhp(origin, asset, baseline, timeout, findings, errors);

    const tlsResult = await checkTls(asset, timeout).catch(() => ({ findings: [], httpsAvailable: false }));
    findings.push(...tlsResult.findings);

    // Header checks come last, and are gated on whether we actually got a
    // working TLS listener — HSTS only makes sense over HTTPS, and a site
    // that doesn't serve HTTPS at all is already flagged by `checkTls`.
    await checkSecurityHeaders(asset, tlsResult.httpsAvailable, timeout, findings, errors);

    return { findings, errors, isWp };
  });

  const findings = [];
  const errors = [];
  let hostsWpChecked = 0;
  results.forEach((r, i) => {
    if (!r.ok) {
      errors.push({ target: crawlable[i].target, check: "host", error: r.error?.message || String(r.error) });
      return;
    }
    findings.push(...r.value.findings);
    errors.push(...r.value.errors);
    if (r.value.isWp) hostsWpChecked++;
  });

  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  const byCategory = {};
  for (const f of findings) {
    if (f.severity in bySeverity) bySeverity[f.severity]++;
    byCategory[f.category] = (byCategory[f.category] || 0) + 1;
  }

  log(`[*] ${findings.length} misconfiguration(s) found across ${crawlable.length} host(s).`);

  return {
    findings,
    errors,
    stats: {
      hosts_checked: crawlable.length,
      hosts_wp_checked: hostsWpChecked,
      total: findings.length,
      by_severity: bySeverity,
      by_category: byCategory,
    },
  };
}