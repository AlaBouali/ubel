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
//       * Content-Security-Policy — general presence, independent of the
//         frame-ancestors-specific check above
//       * X-Content-Type-Options: nosniff
//       * Referrer-Policy — presence, and the unsafe-url special case
//       * Permissions-Policy — presence
//   - Set-Cookie attributes on the site root response: Secure, HttpOnly,
//     and SameSite (including the SameSite=None-without-Secure case)
//   - risky HTTP methods: the OPTIONS Allow header advertising
//     PUT/DELETE/TRACE/CONNECT, plus an actual (non-destructive) TRACE
//     request to detect Cross-Site Tracing (XST) — see the note above
//     checkHttpMethods() for why PUT/DELETE are read from Allow only and
//     never actually sent
//   - CORS misconfiguration: arbitrary-Origin reflection, reflection
//     combined with Access-Control-Allow-Credentials: true, a wildcard
//     paired with credentials, and acceptance of the 'null' Origin
//   - email authentication (SPF/DMARC/DKIM) DNS records: missing or
//     multiple SPF records, an overly permissive "+all" SPF mechanism,
//     missing DMARC, a DMARC policy of "p=none" (monitoring only),
//     reduced DMARC enforcement via pct=, a DMARC record with no
//     aggregate-report address, and DKIM absence at a short list of
//     commonly-used selectors — see checkSpf/checkDmarc/checkDkim below,
//     the one place in this file that queries DNS instead of HTTP
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
// The method/CORS checks need an explicit request method and custom
// headers (Origin, a marker header for TRACE) that httpClient's GET-only
// wrapper doesn't expose, so they go straight to Node's stdlib http/https
// modules instead — the same reasoning the TLS checks already apply to
// node:tls. rejectUnauthorized is left false there too, for the same
// reason: a host with a broken cert should still get probed for these
// findings rather than have the connection refused outright.
//
// Same posture as the rest of this module (see ../README.md): passive,
// one well-known path per check, no brute-forcing, no wordlists. PUT and
// DELETE are never actually sent, only read off the OPTIONS Allow header —
// issuing a real PUT/DELETE against an unknown, possibly-production
// endpoint is an active write, not a passive check, and out of scope here
// regardless of what Allow advertises.

import { httpClient } from "../fingerprint/src/core/httpClient.js";
import { mapLimit } from "../../cloud/lib/concurrency.js";
import { scanContent } from "../../sca/secrets.js";
import tls from "node:tls";
import http from "node:http";
import https from "node:https";
import dns from "node:dns";
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

// ── Raw HTTP requests (method/headers httpClient doesn't expose) ────────

/**
 * Minimal request supporting an explicit method and custom headers, for
 * the handful of checks httpClient's GET-only interface doesn't fit
 * (method enumeration via OPTIONS/TRACE, Origin-reflection probing for
 * CORS). Same non-verifying TLS posture as checkTls below, for the same
 * reason: a broken cert shouldn't hide a finding that has nothing to do
 * with the cert.
 *
 * Resolves even on early body truncation (past MAX_CHECK_BODY_BYTES) by
 * destroying the socket and settling from the resulting "close" event —
 * every check here only needs status/headers or a short echoed body, never
 * the full response.
 */
function rawRequest(urlStr, { method = "GET", headers = {}, timeoutMs = 8000 } = {}) {
  return new Promise((resolve, reject) => {
    let u;
    try {
      u = new URL(urlStr);
    } catch (e) {
      reject(e);
      return;
    }
    const lib = u.protocol === "https:" ? https : http;
    let settled = false;
    const finish = (result, err) => {
      if (settled) return;
      settled = true;
      if (err) reject(err);
      else resolve(result);
    };

    const req = lib.request(u, { method, headers, timeout: timeoutMs, rejectUnauthorized: false }, (res) => {
      const chunks = [];
      let size = 0;
      res.on("data", (c) => {
        size += c.length;
        if (size <= MAX_CHECK_BODY_BYTES) chunks.push(c);
        else req.destroy();
      });
      const settle = () =>
        finish({ status_code: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString("utf8") });
      res.on("end", settle);
      res.on("close", settle);
    });
    req.on("timeout", () => req.destroy(new Error(`request timed out after ${timeoutMs}ms`)));
    req.on("error", (e) => finish(null, e));
    req.end();
  });
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

// ── Email authentication (SPF / DMARC / DKIM) ────────────────────────────
//
// Unlike every other check in this file, these three read DNS TXT records
// rather than making an HTTP request — a domain's outbound mail posture
// has nothing to do with what its web server answers on 80/443, so this
// is the one place here that reaches for node:dns instead of
// httpClient/rawRequest. Same passive, read-only posture as the rest of
// the module: three kinds of TXT lookup (the apex record, _dmarc.<host>,
// and a short list of common DKIM selectors), nothing sent, nothing
// brute-forced against a wordlist of arbitrary length.
//
// DKIM is the odd one out. SPF and DMARC each live at one well-known,
// fixed location (the apex TXT record, and _dmarc.<domain> respectively),
// but a DKIM public key is published under
// "<selector>._domainkey.<domain>", where the selector is picked by
// whatever's sending the mail (Google Workspace defaults to "google",
// Microsoft 365 to "selector1"/"selector2", Mailchimp/Mandrill to
// "k1"/"k2", Postmark to "pm", etc.) and isn't discoverable from outside
// without already knowing it. Querying a short, curated list of the
// selector names real-world providers actually default to is the same
// "well-known path, not a wordlist" posture the HTTP checks take with
// .env/.git/xmlrpc.php — it can positively confirm DKIM is set up, but a
// miss on every selector in the list is NOT proof DKIM is absent, only
// that it isn't using any of these specific names. The finding text below
// says exactly that and is deliberately lower severity than the
// SPF/DMARC findings, whose fixed locations mean a miss really does mean
// absent.
//
// These run once per scanned host, same granularity as every other check
// in this file (see checkTls et al.) — not deduplicated down to one call
// per registrable/organizational domain, since that would need public-
// suffix-list handling this module doesn't otherwise depend on. A finding
// on a subdomain that doesn't send mail directly (www.example.com, say)
// is a real, if lower-stakes, gap: DMARC in particular is meant to be
// inherited from the organizational domain, so a missing record at a
// subdomain is usually not itself actionable — but SPF is evaluated
// per-hostname by receivers, and no finding here claims otherwise.

// Selectors the checkDkim() comment above explains the reasoning for.
const COMMON_DKIM_SELECTORS = [
  "default",                    // widely reused generic default
  "selector1", "selector2",     // Microsoft 365
  "google",                     // Google Workspace
  "k1", "k2",                   // Mailchimp / Mandrill
  "pm",                         // Postmark
  "mandrill",
  "sendgrid", "s1", "s2",
  "mail", "dkim", "smtp", "email",
  "zoho",
  "amazonses",                  // Amazon SES
];

function resolveTxt(hostname, timeoutMs) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      reject(Object.assign(new Error(`DNS TXT lookup for ${hostname} timed out after ${timeoutMs}ms`), { code: "ETIMEOUT" }));
    }, timeoutMs);
    dns.resolveTxt(hostname, (err, records) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (err) reject(err);
      else resolve(records);
    });
  });
}

/** True for "this name simply has no TXT record" — that absence is the
 *  finding itself, not a scan error. Anything else (timeout, SERVFAIL,
 *  refused) is a real lookup failure the caller should surface instead of
 *  silently reading as "no record". */
function isNoRecordDnsError(err) {
  return !!err && (err.code === "ENOTFOUND" || err.code === "ENODATA");
}

// A record's value can be split across multiple chunks by the DNS wire
// format (any single TXT string over 255 bytes) — join a record's own
// chunks back into one string, but keep separate records separate, since
// e.g. two genuinely distinct SPF records on one name is itself a finding
// (see checkSpf).
function joinTxtRecords(records) {
  return (records || []).map((chunks) => chunks.join(""));
}

const IP_ADDRESS_RE = /^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-f:]+:[0-9a-f:]+$/i;

async function checkSpf(hostname, target, timeout, findings, errors) {
  let records;
  try {
    records = await resolveTxt(hostname, Math.max(1, timeout) * 1000);
  } catch (e) {
    if (isNoRecordDnsError(e)) {
      records = [];
    } else {
      errors.push({ target, check: "email-spf", url: hostname, error: e.message });
      return;
    }
  }

  const spfRecords = joinTxtRecords(records).filter((r) => /^v=spf1\b/i.test(r));

  if (!spfRecords.length) {
    findings.push({
      id: "email-spf-missing",
      title: "No SPF record found",
      category: "Email Security",
      severity: "medium",
      url: hostname,
      target,
      description:
        `${hostname} has no SPF (Sender Policy Framework) TXT record. Without one, receiving mail servers have no way to verify that mail claiming to be from this domain actually came from a server authorized to send it — anyone can forge the From/MAIL FROM address and send phishing mail that appears to originate from ${hostname}.`,
      evidence: [],
      remediation:
        `Publish a TXT record on ${hostname} listing every server/service authorized to send mail for this domain, e.g. "v=spf1 include:_spf.<provider>.com -all". End it with "-all" (hard fail) rather than "~all" (soft fail) or "+all" once the list of authorized senders is confirmed complete, so mail from unauthorized sources is rejected outright instead of merely flagged.`,
    });
    return;
  }

  if (spfRecords.length > 1) {
    findings.push({
      id: "email-spf-multiple-records",
      title: "Multiple SPF records published",
      category: "Email Security",
      severity: "medium",
      url: hostname,
      target,
      description:
        `${hostname} publishes ${spfRecords.length} separate "v=spf1" TXT records. RFC 7208 requires exactly one SPF record per domain — a receiver that finds more than one is required to treat SPF as a permanent error (permerror) and effectively ignore it, which silently defeats whatever protection the records were meant to provide.`,
      evidence: spfRecords,
      remediation:
        "Merge every authorized sender into a single \"v=spf1 ...\" TXT record (chain additional providers together with \"include:\" mechanisms inside that one record) and remove the rest, so exactly one SPF record remains.",
    });
  }

  const allMatch = spfRecords[0].match(/([+?~-]?)all\b/i);
  if (allMatch && allMatch[1] === "+") {
    findings.push({
      id: "email-spf-permissive-all",
      title: "SPF record ends in +all (authorizes any server to send mail)",
      category: "Email Security",
      severity: "high",
      url: hostname,
      target,
      description:
        `${hostname}'s SPF record uses "+all", which explicitly authorizes every server on the internet to send mail as this domain and passes SPF for all of it. This looks stricter than having no SPF record only on the surface — in practice it defeats the check entirely and hands forged mail a passing SPF result.`,
      evidence: [spfRecords[0]],
      remediation:
        "Replace \"+all\" with \"-all\" (or \"~all\" while still validating the authorized-sender list is complete) so only the explicitly listed servers pass.",
    });
  }
}

async function checkDmarc(hostname, target, timeout, findings, errors) {
  const dmarcName = `_dmarc.${hostname}`;
  let records;
  try {
    records = await resolveTxt(dmarcName, Math.max(1, timeout) * 1000);
  } catch (e) {
    if (isNoRecordDnsError(e)) {
      records = [];
    } else {
      errors.push({ target, check: "email-dmarc", url: dmarcName, error: e.message });
      return;
    }
  }

  const dmarcRecords = joinTxtRecords(records).filter((r) => /^v=DMARC1\b/i.test(r));

  if (!dmarcRecords.length) {
    findings.push({
      id: "email-dmarc-missing",
      title: "No DMARC record found",
      category: "Email Security",
      severity: "high",
      url: dmarcName,
      target,
      description:
        `No DMARC TXT record was found at ${dmarcName}. DMARC is what ties SPF and DKIM together into an actual enforcement/reporting policy — without it, receivers still validate SPF/DKIM individually, but nothing tells them what to do with mail that fails either, and this domain gets no visibility, via aggregate reports, into who is currently sending mail as it, spoofed or otherwise.`,
      evidence: [],
      remediation:
        `Publish a TXT record at ${dmarcName}, starting in monitoring mode so current mail flow is visible before anything is enforced: "v=DMARC1; p=none; rua=mailto:<address to receive aggregate reports>". Once the reports confirm every legitimate mail source is covered by SPF/DKIM, move p= to "quarantine" and then "reject".`,
    });
    return;
  }

  const record = dmarcRecords[0];
  if (dmarcRecords.length > 1) {
    findings.push({
      id: "email-dmarc-multiple-records",
      title: "Multiple DMARC records published",
      category: "Email Security",
      severity: "medium",
      url: dmarcName,
      target,
      description:
        `${dmarcName} publishes ${dmarcRecords.length} separate "v=DMARC1" TXT records. Per RFC 7489 a domain must publish exactly one; a receiver that finds more than one is expected to treat DMARC as unset for this domain, discarding whatever policy was intended.`,
      evidence: dmarcRecords,
      remediation: `Remove all but one DMARC TXT record at ${dmarcName}.`,
    });
  }

  const policyMatch = record.match(/(?:^|;)\s*p=(\w+)/i);
  const policy = policyMatch ? policyMatch[1].toLowerCase() : null;
  if (!policy || policy === "none") {
    findings.push({
      id: "email-dmarc-policy-none",
      title: 'DMARC policy is "none" (monitoring only, nothing enforced)',
      category: "Email Security",
      severity: "medium",
      url: dmarcName,
      target,
      description:
        `${dmarcName}'s DMARC policy is${policy ? "" : " missing its required p= tag, which defaults to"} "p=none". Mail that fails SPF/DKIM alignment is delivered anyway — aggregate reports are generated, but nothing is actually blocked or quarantined, so this domain remains fully spoofable in practice despite DMARC being present.`,
      evidence: [record],
      remediation:
        "Once aggregate reports (rua) confirm every legitimate sending source passes SPF/DKIM alignment, move the policy to \"p=quarantine\" and eventually \"p=reject\" to act on failing mail instead of only observing it.",
    });
  }

  const pctMatch = record.match(/(?:^|;)\s*pct=(\d+)/i);
  const pct = pctMatch ? Number(pctMatch[1]) : 100;
  if (policy && policy !== "none" && pct < 100) {
    findings.push({
      id: "email-dmarc-reduced-enforcement-pct",
      title: `DMARC enforcement reduced to ${pct}% of mail (pct=${pct})`,
      category: "Email Security",
      severity: "low",
      url: dmarcName,
      target,
      description:
        `${dmarcName} enforces its "${policy}" policy on only ${pct}% of mail that fails alignment (pct=${pct}); the remainder is let through as if the policy were "none". This is a normal, deliberate step while ramping up enforcement, but leaves a real gap in coverage if left in place long-term.`,
      evidence: [record],
      remediation:
        "Ratchet pct= up toward 100 as monitoring confirms legitimate mail keeps passing under the stricter policy, so full enforcement eventually applies to all mail rather than a sample of it.",
    });
  }

  if (!/(?:^|;)\s*rua=/i.test(record)) {
    findings.push({
      id: "email-dmarc-no-reports",
      title: "DMARC record has no aggregate-report address (rua)",
      category: "Email Security",
      severity: "low",
      url: dmarcName,
      target,
      description:
        `${dmarcName}'s DMARC record has no "rua=" tag, so no aggregate reports are sent anywhere. Reports are what make DMARC actionable — without them, no one is notified which sources are sending mail as this domain, legitimate or spoofed, or whether tightening the policy broke real mail flow.`,
      evidence: [record],
      remediation:
        "Add \"rua=mailto:<address>\" to the record to receive daily aggregate XML reports summarizing which sources pass/fail for this domain.",
    });
  }
}

async function checkDkim(hostname, target, timeout, findings, errors) {
  let foundSelector = null;
  const timeoutMs = Math.max(1, timeout) * 1000;

  for (const selector of COMMON_DKIM_SELECTORS) {
    const name = `${selector}._domainkey.${hostname}`;
    let records;
    try {
      records = await resolveTxt(name, timeoutMs);
    } catch (e) {
      if (isNoRecordDnsError(e)) continue;
      // A real lookup failure (timeout, SERVFAIL) on one selector
      // shouldn't abort the rest of the list — record it and keep going.
      errors.push({ target, check: "email-dkim", url: name, error: e.message });
      continue;
    }
    const hit = joinTxtRecords(records).find((r) => /v=DKIM1/i.test(r) || /(?:^|;)\s*p=/i.test(r));
    if (hit) {
      foundSelector = selector;
      break;
    }
  }

  if (!foundSelector) {
    findings.push({
      id: "email-dkim-not-found-common-selectors",
      title: "No DKIM record found at common selectors",
      category: "Email Security",
      severity: "low",
      url: `_domainkey.${hostname}`,
      target,
      description:
        `None of ${COMMON_DKIM_SELECTORS.length} commonly-used DKIM selectors (${COMMON_DKIM_SELECTORS.join(", ")}) resolved a DKIM key under _domainkey.${hostname}. DKIM lets receivers verify a message wasn't altered in transit and genuinely came from a server holding this domain's private key — without it, SPF/DMARC are the only authentication this domain has. This is a lower-confidence finding than the SPF/DMARC checks above: DKIM selectors are chosen by whoever configured outbound mail and aren't discoverable from outside without already knowing the name, so this only rules out the selector names checked here, not DKIM as a whole.`,
      evidence: [],
      remediation:
        "Confirm with whoever administers this domain's outbound mail (in-house mail server, or a provider such as Google Workspace/Microsoft 365/SendGrid/etc.) whether DKIM signing is enabled and under what selector, and publish it if it isn't. If DKIM is already configured under a selector not in this common list, this specific finding is a false positive.",
    });
  }
}

async function checkEmailAuth(hostname, target, timeout, findings, errors) {
  if (IP_ADDRESS_RE.test(hostname)) return; // SPF/DMARC/DKIM apply to domain names, not bare IPs
  await checkSpf(hostname, target, timeout, findings, errors);
  await checkDmarc(hostname, target, timeout, findings, errors);
  await checkDkim(hostname, target, timeout, findings, errors);
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

  // ── General CSP presence ─────────────────────────────────────────────
  // Independent of the frame-ancestors-specific check above: this fires
  // only when CSP is entirely absent. A CSP that's present but missing
  // just frame-ancestors is already covered by the clickjacking finding
  // above, so it isn't re-flagged here.
  if (!csp) {
    findings.push({
      id: "missing-csp",
      title: "Missing Content-Security-Policy header",
      category: "Security Headers",
      severity: "low",
      url,
      target: asset.target,
      description:
        "No Content-Security-Policy header is set. Beyond the frame-ancestors/clickjacking case already checked separately, CSP is the primary browser-side mitigation against injected-script execution (XSS) and restricts which origins scripts, styles, and other resources may load from.",
      evidence: [],
      remediation:
        "Start with Content-Security-Policy-Report-Only to see what a policy would break, then move to enforcing mode. Even a baseline `default-src 'self'` with explicit exceptions for genuinely third-party resources is far better than no policy at all.",
    });
  }

  // ── X-Content-Type-Options ───────────────────────────────────────────
  const xcto = pickHeader(h, "x-content-type-options");
  if (!xcto) {
    findings.push({
      id: "missing-x-content-type-options",
      title: "Missing X-Content-Type-Options header",
      category: "Security Headers",
      severity: "low",
      url,
      target: asset.target,
      description:
        "The X-Content-Type-Options header is not set, so browsers may MIME-sniff a response's content instead of trusting its declared Content-Type — this is what lets a file that's actually HTML/JS get interpreted (and executed) as such even when served with a benign content type.",
      evidence: [],
      remediation: "Send `X-Content-Type-Options: nosniff` on every response.",
    });
  } else if (!/^\s*nosniff\s*$/i.test(xcto)) {
    findings.push({
      id: "invalid-x-content-type-options",
      title: "X-Content-Type-Options set to an unrecognized value",
      category: "Security Headers",
      severity: "low",
      url,
      target: asset.target,
      description: `X-Content-Type-Options is set to "${xcto}", but the only value browsers act on is "nosniff" — anything else is equivalent to the header being absent.`,
      evidence: [`X-Content-Type-Options: ${xcto}`],
      remediation: "Set the header to exactly `X-Content-Type-Options: nosniff`.",
    });
  }

  // ── Referrer-Policy ───────────────────────────────────────────────────
  const referrerPolicy = pickHeader(h, "referrer-policy");
  if (!referrerPolicy) {
    findings.push({
      id: "missing-referrer-policy",
      title: "Missing Referrer-Policy header",
      category: "Security Headers",
      severity: "low",
      url,
      target: asset.target,
      description:
        "No Referrer-Policy header is set, so the browser's own default applies (which varies by browser and can leak the full referring URL — including path and query string — to third-party sites linked from this page).",
      evidence: [],
      remediation:
        "Send `Referrer-Policy: strict-origin-when-cross-origin` (a safe, widely-supported default), or `no-referrer` if even the bare origin shouldn't be disclosed cross-origin.",
    });
  } else if (/unsafe-url/i.test(referrerPolicy)) {
    findings.push({
      id: "weak-referrer-policy",
      title: "Referrer-Policy set to unsafe-url",
      category: "Security Headers",
      severity: "low",
      url,
      target: asset.target,
      description: `Referrer-Policy is explicitly set to "${referrerPolicy}", which sends the full referring URL — including path and query string — on every cross-origin navigation and subresource request, even from HTTPS down to HTTP.`,
      evidence: [`Referrer-Policy: ${referrerPolicy}`],
      remediation: "Use `strict-origin-when-cross-origin` or a more restrictive policy instead of unsafe-url.",
    });
  }

  // ── Permissions-Policy ────────────────────────────────────────────────
  const permissionsPolicy = pickHeader(h, "permissions-policy") || pickHeader(h, "feature-policy");
  if (!permissionsPolicy) {
    findings.push({
      id: "missing-permissions-policy",
      title: "Missing Permissions-Policy header",
      category: "Security Headers",
      severity: "low",
      url,
      target: asset.target,
      description:
        "No Permissions-Policy (or legacy Feature-Policy) header is set. This header lets a page explicitly disable powerful browser features it doesn't use (camera, microphone, geolocation, USB, payment, etc.), denying an attacker who achieves script execution the ability to invoke them.",
      evidence: [],
      remediation:
        "Send a Permissions-Policy header disabling any feature the site doesn't actively use, e.g. `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()`.",
    });
  }

  checkCookieFlags(h, url, asset, isHttps, findings);
}

const SESSION_COOKIE_NAME_RE = /session|token|auth|jwt|\bsid\b|csrf/i;

/**
 * Case-/shape-tolerant extraction of every Set-Cookie value on a response.
 * Node's raw response headers (what rawRequest() and most fetch polyfills
 * return) already give an array for repeated headers; Headers-like objects
 * expose getSetCookie(). Deliberately not routed through pickHeader():
 * that function comma-joins repeated headers, which corrupts this one
 * specifically, since Expires values inside a cookie string routinely
 * contain commas of their own.
 */
function getSetCookieList(headers) {
  if (!headers) return [];
  if (typeof headers.getSetCookie === "function") return headers.getSetCookie();
  for (const k of Object.keys(headers)) {
    if (k.toLowerCase() === "set-cookie") {
      const v = headers[k];
      return Array.isArray(v) ? v : [v];
    }
  }
  return [];
}

function parseSetCookie(cookieStr) {
  const parts = String(cookieStr).split(";").map((p) => p.trim());
  const name = (parts[0].split("=")[0] || "").trim();
  const attrs = parts.slice(1);
  const lowerAttrs = attrs.map((a) => a.toLowerCase());
  const sameSiteAttr = attrs.find((a) => a.toLowerCase().startsWith("samesite"));
  const sameSite = sameSiteAttr ? (sameSiteAttr.split("=")[1] || "").trim() : null;
  return {
    name: name || "(unnamed)",
    secure: lowerAttrs.includes("secure"),
    httpOnly: lowerAttrs.includes("httponly"),
    sameSite, // null | "Strict" | "Lax" | "None" | ""
  };
}

/**
 * Set-Cookie attribute checks on the same site-root response the other
 * header checks already fetched — no extra request. Aggregated per host
 * rather than per cookie: a site with ten cookies missing HttpOnly gets
 * one finding naming all ten, not ten findings.
 */
function checkCookieFlags(headers, url, asset, isHttps, findings) {
  const cookies = getSetCookieList(headers).map(parseSetCookie);
  if (!cookies.length) return;

  const missingSecure = isHttps ? cookies.filter((c) => !c.secure) : [];
  const missingHttpOnly = cookies.filter((c) => !c.httpOnly);
  const missingSameSite = cookies.filter((c) => !c.sameSite);
  const noneWithoutSecure = cookies.filter((c) => c.sameSite && /^none$/i.test(c.sameSite) && !c.secure);

  if (missingSecure.length) {
    findings.push({
      id: "cookie-missing-secure",
      title: "Cookie set without the Secure attribute",
      category: "Cookies",
      severity: "medium",
      url,
      target: asset.target,
      description: `${missingSecure.length} cookie(s) set on this HTTPS response lack the Secure attribute (${missingSecure.map((c) => c.name).join(", ")}), so they could still be sent over a plain HTTP request — a downgrade, a misconfigured link, or a network attacker forcing plaintext — exposing the cookie's value in transit.`,
      evidence: missingSecure.map((c) => c.name),
      remediation: "Add the Secure attribute to every cookie set on an HTTPS response.",
    });
  }

  if (missingHttpOnly.length) {
    const sensitive = missingHttpOnly.filter((c) => SESSION_COOKIE_NAME_RE.test(c.name));
    findings.push({
      id: "cookie-missing-httponly",
      title: "Cookie set without the HttpOnly attribute",
      category: "Cookies",
      severity: sensitive.length ? "medium" : "low",
      url,
      target: asset.target,
      description: `${missingHttpOnly.length} cookie(s) lack the HttpOnly attribute (${missingHttpOnly.map((c) => c.name).join(", ")})${sensitive.length ? `, including ${sensitive.map((c) => c.name).join(", ")} which look session/auth-related by name` : ""} — any JavaScript running on the page, including script injected via XSS, can read these cookies' values directly.`,
      evidence: missingHttpOnly.map((c) => c.name),
      remediation:
        "Add HttpOnly to every cookie that client-side JavaScript doesn't genuinely need to read — session/auth cookies almost never need to be readable from script.",
    });
  }

  if (noneWithoutSecure.length) {
    findings.push({
      id: "cookie-samesite-none-insecure",
      title: "Cookie sets SameSite=None without Secure",
      category: "Cookies",
      severity: "medium",
      url,
      target: asset.target,
      description: `${noneWithoutSecure.length} cookie(s) set SameSite=None without also setting Secure (${noneWithoutSecure.map((c) => c.name).join(", ")}). SameSite=None requires Secure under the current cookie spec — browsers that enforce this reject the cookie outright, and any that don't yet enforce it are left with the full cross-site exposure SameSite=None opts into, with no compensating transport protection.`,
      evidence: noneWithoutSecure.map((c) => c.name),
      remediation: "Add Secure to every cookie that sets SameSite=None, or switch to Lax/Strict if cross-site delivery isn't actually required.",
    });
  }

  if (missingSameSite.length) {
    findings.push({
      id: "cookie-missing-samesite",
      title: "Cookie set without an explicit SameSite attribute",
      category: "Cookies",
      severity: "low",
      url,
      target: asset.target,
      description: `${missingSameSite.length} cookie(s) don't set SameSite explicitly (${missingSameSite.map((c) => c.name).join(", ")}). Chromium-based browsers default an unset cookie to Lax, but that default isn't universal across every browser/version still in use, and an explicit value is what actually documents the intended behavior.`,
      evidence: missingSameSite.map((c) => c.name),
      remediation: "Set SameSite explicitly on every cookie — Lax is a reasonable default; Strict for cookies that never need to be sent on cross-site navigation.",
    });
  }
}

// ── HTTP method + CORS checks ────────────────────────────────────────────

const RISKY_METHODS = ["PUT", "DELETE", "TRACE", "CONNECT"];

/**
 * Enumerates methods the server advertises via the OPTIONS Allow header,
 * flagging any of RISKY_METHODS found there, then separately sends one
 * real TRACE request — TRACE is read-only by definition (the server is
 * only expected to echo the request back), so actually sending it is safe
 * in a way actually sending PUT/DELETE would not be. PUT/DELETE are never
 * sent; see the module-level note above for why.
 */
async function checkHttpMethods(origin, asset, timeout, findings, errors) {
  const url = origin + "/";

  let res;
  try {
    res = await rawRequest(url, { method: "OPTIONS", timeoutMs: timeout * 1000 });
  } catch (e) {
    errors.push({ target: asset.target, check: "http-methods", url, error: e.message });
    return;
  }

  const allowRaw = pickHeader(res.headers, "allow") || pickHeader(res.headers, "access-control-allow-methods");
  if (allowRaw) {
    const methods = allowRaw.split(",").map((m) => m.trim().toUpperCase()).filter(Boolean);
    const risky = methods.filter((m) => RISKY_METHODS.includes(m));
    if (risky.length) {
      const severity = risky.some((m) => m === "PUT" || m === "DELETE") ? "high" : "medium";
      findings.push({
        id: "risky-http-methods-allowed",
        title: "Potentially dangerous HTTP methods advertised",
        category: "HTTP Methods",
        severity,
        url,
        target: asset.target,
        description: `The server's Allow header advertises ${risky.join(", ")} alongside its other supported methods (${methods.join(", ")}). PUT/DELETE can permit arbitrary file write/deletion if the handler behind them isn't strictly authenticated; TRACE enables Cross-Site Tracing (see the separate finding below if it's actually reachable); CONNECT exposed on a web-facing origin usually indicates a proxy misconfiguration.`,
        evidence: [`Allow: ${allowRaw}`],
        remediation:
          "Restrict routing to only the methods each endpoint actually needs (typically GET/POST/HEAD for a normal web app) and return 405 for the rest. If PUT/DELETE are intentionally used by an API, confirm every route behind them enforces authentication and authorization — advertising them in Allow isn't itself the vulnerability, an unauthenticated handler behind them is.",
      });
    }
  }

  try {
    const marker = Math.random().toString(36).slice(2);
    const traceRes = await rawRequest(url, {
      method: "TRACE",
      headers: { "X-Ubel-Trace-Probe": marker },
      timeoutMs: timeout * 1000,
    });
    if (traceRes.status_code === 200 && traceRes.text.includes(marker)) {
      findings.push({
        id: "trace-method-enabled",
        title: "HTTP TRACE method enabled (Cross-Site Tracing)",
        category: "HTTP Methods",
        severity: "medium",
        url,
        target: asset.target,
        description:
          "The server responds to TRACE requests by echoing the request back verbatim, including headers. Combined with an XSS bug elsewhere on the site, TRACE lets an attacker's script retrieve headers — including cookies — that JavaScript can't normally read directly, the classic Cross-Site Tracing (XST) technique for defeating HttpOnly.",
        evidence: [],
        remediation:
          "Disable the TRACE method at the web server/load balancer (e.g. `TraceEnable off` on Apache; an explicit method restriction on nginx/IIS).",
      });
    }
  } catch {
    /* refused or unsupported here — nothing to report either way */
  }
}

/**
 * Origin-reflection CORS checks: sends the site root a fabricated Origin
 * it could never have legitimately allow-listed and checks whether the
 * response reflects it back — the standard way to distinguish "reflects
 * any origin" from "has a real allowlist that happens to include mine."
 * Then, separately, checks whether Origin: null is accepted, since that's
 * the value sandboxed iframes and data: URIs send.
 */
async function checkCorsMisconfig(origin, asset, timeout, findings, errors) {
  const url = origin + "/";
  const probeOrigin = `https://ubel-cors-probe-${Math.random().toString(36).slice(2)}.example`;

  let res;
  try {
    res = await rawRequest(url, { method: "GET", headers: { Origin: probeOrigin }, timeoutMs: timeout * 1000 });
  } catch (e) {
    errors.push({ target: asset.target, check: "cors-misconfiguration", url, error: e.message });
    return;
  }

  const acao = pickHeader(res.headers, "access-control-allow-origin");
  const acac = pickHeader(res.headers, "access-control-allow-credentials");

  if (acao) {
    const reflectsArbitraryOrigin = acao === probeOrigin;
    const allowsCredentials = /^\s*true\s*$/i.test(String(acac || ""));

    if (reflectsArbitraryOrigin && allowsCredentials) {
      findings.push({
        id: "cors-reflected-origin-with-credentials",
        title: "CORS reflects arbitrary Origin with credentials allowed",
        category: "CORS",
        severity: "critical",
        url,
        target: asset.target,
        description: `The server reflects any Origin header back verbatim in Access-Control-Allow-Origin (tested with a fabricated, never-before-seen origin: ${probeOrigin}) and also sets Access-Control-Allow-Credentials: true. Any other website can therefore issue a credentialed (cookie-carrying) cross-origin request to this site and read the response — a near-complete same-origin-policy bypass for anyone with an active session here.`,
        evidence: [`Origin sent: ${probeOrigin}`, `Access-Control-Allow-Origin: ${acao}`, `Access-Control-Allow-Credentials: ${acac}`],
        remediation:
          "Never reflect an arbitrary Origin when Access-Control-Allow-Credentials is true. Maintain an explicit allowlist of trusted origins, echo back only an origin that matches it, and add `Vary: Origin` so caches don't serve one origin's CORS headers to another.",
      });
    } else if (reflectsArbitraryOrigin) {
      findings.push({
        id: "cors-reflected-origin",
        title: "CORS reflects arbitrary Origin",
        category: "CORS",
        severity: "medium",
        url,
        target: asset.target,
        description: `The server reflects any Origin header back verbatim in Access-Control-Allow-Origin (tested with a fabricated origin: ${probeOrigin}), without credentials involved. This still lets any website read non-credentialed responses cross-origin — only safe if those responses genuinely contain nothing sensitive to an unauthenticated visitor.`,
        evidence: [`Origin sent: ${probeOrigin}`, `Access-Control-Allow-Origin: ${acao}`],
        remediation:
          "Restrict Access-Control-Allow-Origin to an explicit allowlist rather than reflecting whatever was sent — even without credentials, unauthenticated responses can leak information (rate-limit counters, internal IDs, feature flags) that shouldn't be broadly readable.",
      });
    } else if (acao === "*" && allowsCredentials) {
      // Technically invalid per the Fetch spec — browsers reject this
      // exact combination outright — but worth flagging: it signals the
      // same "allow everything" intent as the reflection case above, and
      // some intermediaries (CDNs, reverse proxies) rewrite a wildcard
      // into a reflected origin, which would reintroduce the credentialed
      // bypass this spec restriction is meant to prevent.
      findings.push({
        id: "cors-wildcard-with-credentials",
        title: "CORS wildcard Origin combined with credentials",
        category: "CORS",
        severity: "medium",
        url,
        target: asset.target,
        description:
          "The server sends Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true. Browsers reject this exact combination as-is, so it doesn't currently work, but it signals a CORS policy not built around a real origin allowlist — one that may fail open elsewhere, e.g. behind a proxy that rewrites `*` into the request's actual Origin.",
        evidence: [`Access-Control-Allow-Origin: ${acao}`, `Access-Control-Allow-Credentials: ${acac}`],
        remediation:
          "Replace the wildcard with an explicit allowlist of trusted origins anywhere credentials are involved, and confirm no intermediary rewrites the wildcard into a reflected origin.",
      });
    }
  }

  let nullRes;
  try {
    nullRes = await rawRequest(url, { method: "GET", headers: { Origin: "null" }, timeoutMs: timeout * 1000 });
  } catch {
    return;
  }
  const acaoNull = pickHeader(nullRes.headers, "access-control-allow-origin");
  if (acaoNull === "null") {
    findings.push({
      id: "cors-null-origin-allowed",
      title: "CORS allows the 'null' Origin",
      category: "CORS",
      severity: "high",
      url,
      target: asset.target,
      description:
        "The server sets Access-Control-Allow-Origin: null in response to a request sending Origin: null. Browsers send exactly that value from sandboxed iframes, data: URIs, and some redirect chains — contexts that are untrusted by design — so allow-listing it removes a boundary the browser sandbox model depends on.",
      evidence: [`Access-Control-Allow-Origin: ${acaoNull}`],
      remediation: "Remove 'null' from any Origin allowlist; treat it as untrusted and never echo it back.",
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
    await checkHttpMethods(origin, asset, timeout, findings, errors);
    await checkCorsMisconfig(origin, asset, timeout, findings, errors);

    // DNS-only, independent of everything above — reuses `parsed.hostname`
    // (already validated by parseResolvedUrl) rather than raw asset.target,
    // since target may carry a scheme/port depending on how it was given.
    await checkEmailAuth(parsed.hostname, asset.target, timeout, findings, errors);

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