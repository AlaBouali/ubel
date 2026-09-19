// easm/lib/secrets_crawl.js
//
// Client-side secret exposure: fetch each live host's page, pull out every
// piece of JavaScript it serves — inline <script> blocks and external
// <script src=...> files — and run all of it through the SCA module's
// secrets scanner (../../sca/secrets.js). Anything it flags is a
// credential that a remote, unauthenticated visitor can read straight out
// of the page source, which is a materially different finding from a
// secret committed to a private repo: there's no "but it's internal"
// mitigation available.
//
// Reuses `scanContent()` rather than reimplementing detection, so EASM and
// the SCA/`ubel-secrets` CLI apply the exact same rule set, the same
// allow-rules, the same specific-beats-generic per-line resolution, and the
// same redaction (findings carry a `match_preview`, never the raw
// credential — this report is an artifact that gets shared around).
//
// Scope note: this is not a site crawler. It fetches each host's root
// document and the scripts that document references, one level deep. It
// does not follow links, enumerate routes, or execute JavaScript, so a
// secret that only appears in a lazily-imported chunk on some inner route
// won't be found. That matches the rest of this module's passive,
// one-request-per-target posture (see ../README.md).

import { URL } from "node:url";
import { httpClient } from "../fingerprint/src/core/httpClient.js";
import { mapLimit } from "../../cloud/lib/concurrency.js";
import { scanContent } from "../../sca/secrets.js";

// A minified bundle is routinely megabytes; past a point the scan cost
// stops being worth it and the line/column position stops being useful to
// a human anyway (a single 3MB line). Same spirit as MAX_FILE_SIZE in
// sca/secrets.js.
const MAX_SCRIPT_BYTES = 10 * 1024 * 1024;
// Per-host ceiling on external scripts. A page referencing hundreds of
// script tags is either a build artifact dump or hostile; either way,
// fetching all of them turns one target into a burst of requests against
// someone else's infrastructure, which this module deliberately avoids.
const MAX_SCRIPTS_PER_HOST = 40;

// ── Extraction ───────────────────────────────────────────────────────────

const SCRIPT_TAG_RE = /<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi;
// `(?<![\w-])` so `data-src=`, `data-href=`, `data-type=` don't shadow the
// real attribute. `\b` alone matches after the `-` in `data-`, which meant
// a tag carrying only `data-src="…"` looked like it had a src.
const SRC_ATTR_RE = /(?<![\w-])src\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i;
const TYPE_ATTR_RE = /(?<![\w-])type\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i;

// Script types that aren't JavaScript. JSON-ish payload blocks
// (application/json, importmap, ld+json) ARE kept — a hardcoded API key in
// a __NEXT_DATA__ or ld+json blob is exactly the kind of thing this is
// looking for, and the secrets rules are content-based, not syntax-based.
const NON_JS_TYPES = new Set(["text/template", "text/x-template", "text/html"]);

/** Line number (1-based) of a character offset within a string. */
function lineAtOffset(text, offset) {
  let line = 1;
  for (let i = 0; i < offset && i < text.length; i++) {
    if (text[i] === "\n") line++;
  }
  return line;
}

/**
 * Turn a bare host ("devops.medcity.tn") or a path-less URL into a proper
 * absolute URL with a path. Everything that resolves relative asset paths
 * or fetches a page MUST go through this first: `new URL('/a.js', 'host')`
 * throws, and the thrown error is swallowed by every caller here, so an
 * unnormalized host silently yields zero assets.
 */
function normalizeUrl(url) {
  if (!/^https?:/i.test(url)) url = "https://" + url;
  const parsed = new URL(url);
  if (!parsed.pathname) parsed.pathname = "/";
  return parsed.toString();
}

/**
 * Pulls every script out of an HTML document.
 *
 * Inline blocks carry `lineOffset`: the line in the *page source* where the
 * block's content starts, so a finding's reported line is the line you land
 * on in view-source rather than a line number relative to an anonymous
 * fragment nobody can locate.
 *
 * @param {string} html
 * @param {string} pageUrl  absolute URL used to resolve relative src/href
 * @returns {{inline: {content: string, lineOffset: number}[], external: string[]}}
 */
export function extractScripts(html, pageUrl) {
  const inline = [];
  const external = [];
  const seenExternal = new Set();

  // Defensive: callers occasionally hand us a bare hostname. Resolving
  // relative paths against it throws for every asset; normalizing here
  // means one bad caller can't silently produce an empty result.
  try {
    pageUrl = normalizeUrl(pageUrl);
  } catch {
    // If even normalizeUrl can't make sense of it there is nothing to
    // resolve against; return empty rather than pretend.
    return { inline, external };
  }

  SCRIPT_TAG_RE.lastIndex = 0;
  let m;
  while ((m = SCRIPT_TAG_RE.exec(html)) !== null) {
    const attrs = m[1] || "";
    const body = m[2] || "";

    const typeMatch = TYPE_ATTR_RE.exec(attrs);
    const type = (typeMatch ? (typeMatch[1] ?? typeMatch[2] ?? typeMatch[3] ?? "") : "").trim().toLowerCase();
    if (type && NON_JS_TYPES.has(type)) continue;

    const srcMatch = SRC_ATTR_RE.exec(attrs);
    if (srcMatch) {
      const raw = (srcMatch[1] ?? srcMatch[2] ?? srcMatch[3] ?? "").trim();
      if (!raw || raw.startsWith("data:")) continue;
      let resolved;
      try {
        resolved = new URL(raw, pageUrl).toString();
      } catch {
        continue;
      }
      if (!/^https?:/i.test(resolved)) continue;
      if (!seenExternal.has(resolved)) {
        seenExternal.add(resolved);
        external.push(resolved);
      }
      continue;
    }

    if (!body.trim()) continue;
    // +1: the block's content begins on the line after the tag's own line
    // only when the tag ends with a newline; computing from the content's
    // actual offset handles both shapes without guessing.
    const contentOffset = m.index + m[0].indexOf(">") + 1;
    inline.push({ content: body, lineOffset: lineAtOffset(html, contentOffset) });
  }

  // Look up URLs from <link> tags as well. These routinely carry JS:
  //   <link rel="modulepreload" href="/assets/react-vendor-B9ss9F-Y.js">
  //   <link rel="preload" as="script" href="/static/js/main.abc.js">
  //   <link rel="prefetch" href="/static/js/lazy.js">
  // No rel filter is applied here on purpose — anything the page tells the
  // browser to fetch is fair game for a secret scan; non-JS payloads are
  // harmless to scan because the secrets rules are content-based.
  const LINK_TAG_RE = /<link\b([^>]*)>/gi;
  const HREF_ATTR_RE = /(?<![\w-])href\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i;
  LINK_TAG_RE.lastIndex = 0;
  while ((m = LINK_TAG_RE.exec(html)) !== null) {
    const attrs = m[1] || "";
    const hrefMatch = HREF_ATTR_RE.exec(attrs);
    if (!hrefMatch) continue;                         
    const raw = (hrefMatch[1] ?? hrefMatch[2] ?? hrefMatch[3] ?? "").trim();
    if (raw==="") continue;
    if (!raw || raw.startsWith("data:")) continue;
    if (!raw.endsWith(".js")) continue;

    let resolved;
    try {
      resolved = new URL(raw, pageUrl).toString();
    } catch {
      continue;
    }
    if (!/^https?:/i.test(resolved)) continue;
    if (!seenExternal.has(resolved)) {
      seenExternal.add(resolved);
      external.push(resolved);
    }
  }

  // NB: `inline` and `external` are arrays — interpolating them directly in
  // a template literal calls Array#toString() and produces "[object Object]"
  // / comma-joined URLs / an empty string when the array is empty, which
  // made a page with zero external scripts look like extraction had failed.
  // Log lengths and then list the URLs, one per line.
  console.log(
    `[*] ${inline.length} inline script block(s) and ${external.length} external asset URL(s) found on ${pageUrl}`
  );
  for (const url of external) console.log(`    - ${url}`);

  return { inline, external: external.slice(0, MAX_SCRIPTS_PER_HOST) };
}

// ── Scanning ─────────────────────────────────────────────────────────────

/**
 * Runs one blob of JavaScript through the SCA secrets rules and reshapes
 * each finding for this report.
 *
 * `file_path` from scanContent() is meaningless here (there is no file on
 * disk), so it's replaced with the URL the content actually came from —
 * that URL plus line/column is the whole point: it's what someone needs to
 * go look at the thing themselves.
 */
function scanBlob(content, { url, sourceType, lineOffset = 0, pageUrl }) {
  let findings;
  try {
    findings = scanContent(content, { filePath: "inline.js", projectRoot: "/" });
  } catch {
    return [];
  }

  return findings.map((f) => ({
    id: f.id,
    title: f.title,
    category: f.category,
    severity: f.severity,
    secret_type: f.secret_type,
    match_preview: f.match_preview,
    url,
    page_url: pageUrl,
    source_type: sourceType, // "inline-script" | "js-file"
    line: f.line + lineOffset,
    column_start: f.column_start,
    column_end: f.column_end,
  }));
}

async function fetchText(url, timeout) {
  url = normalizeUrl(url);
  const res = await httpClient.get(url, { timeout, maxRedirects: 3 });
  if (res.status_code < 200 || res.status_code >= 300) return null;
  const text = res.text;
  if (!text || text.length > MAX_SCRIPT_BYTES) return null;
  return text;
}

/**
 * Crawl + scan every scanned asset's JavaScript.
 *
 * External scripts are fetched once globally, not once per host: a shared
 * bundle or a CDN-hosted library referenced by forty subdomains is one
 * fetch and one set of findings, with every page that referenced it
 * recorded on the finding. That mirrors how the component inventory already
 * treats the same software seen on many hosts, and keeps a domain-wide
 * sweep from hammering one CDN URL.
 *
 * Never throws — a host that fails to fetch contributes no findings and an
 * entry in `errors`, so a secrets problem can't abort a scan that otherwise
 * succeeded.
 *
 * @param {object[]} assets      from scanTargets(); only status "scanned" entries are crawled
 * @param {object} [opts]
 * @param {number} [opts.concurrency]
 * @param {number} [opts.timeout]   seconds per request
 * @param {function} [opts.log]
 * @returns {Promise<{findings: object[], stats: object, errors: object[]}>}
 */
export async function crawlAndScanSecrets(assets, opts = {}) {
  const { concurrency = 4, timeout = 15, log = () => {} } = opts;

  const crawlable = (assets || []).filter((a) => a.status === "scanned" && a.resolved_url);

  if (!crawlable.length) {
    return {
      findings: [],
      stats: { pages_crawled: 0, inline_blocks: 0, external_scripts: 0, bytes_scanned: 0 },
      errors: [],
    };
  }

  console.log(`[*] Crawling JavaScript on ${crawlable.length} host(s) for exposed secrets...`);

  const errors = [];
  const rawFindings = [];
  let inlineBlocks = 0;
  let bytesScanned = 0;

  // externalUrl -> Set of page URLs that referenced it
  const externalRefs = new Map();

  // ── Pass 1: page documents + inline scripts ────────────────────────────
  const pageResults = await mapLimit(crawlable, concurrency, async (asset) => {
    // Normalize BEFORE extractScripts: asset.resolved_url is often a bare
    // host ("devops.medcity.tn"). fetchText would silently prepend https://
    // but the original string would still be handed to extractScripts,
    // where `new URL('/a.js', 'devops.medcity.tn')` throws and the asset is
    // silently dropped. Normalize once, use everywhere.
    let pageUrl;
    try {
      pageUrl = normalizeUrl(asset.resolved_url);
    } catch (err) {
      return { pageUrl: asset.resolved_url, ok: false, error: `invalid URL: ${err.message}` };
    }

    const html = await fetchText(pageUrl, timeout);
    if (html === null) {
      return { pageUrl, ok: false, error: "page fetch failed (non-2xx, empty, or > MAX_SCRIPT_BYTES)" };
    }

    const { inline, external } = extractScripts(html, pageUrl);
    for (const url of external) {
      if (!externalRefs.has(url)) externalRefs.set(url, new Set());
      externalRefs.get(url).add(pageUrl);
    }

    const findings = [];
    for (const block of inline) {
      findings.push(
        ...scanBlob(block.content, {
          url: pageUrl,
          sourceType: "inline-script",
          lineOffset: block.lineOffset - 1, // scanContent lines are 1-based already
          pageUrl,
        })
      );
    }
    return { pageUrl, ok: true, inlineCount: inline.length, bytes: html.length, findings };
  });

  let pagesCrawled = 0;
  pageResults.forEach((r, i) => {
    if (!r.ok) {
      errors.push({ url: crawlable[i].resolved_url, stage: "page", error: r.error?.message || String(r.error) });
      return;
    }
    const v = r.value;
    if (!v.ok) {
      errors.push({ url: v.pageUrl, stage: "page", error: v.error || "could not be fetched or was too large" });
      return;
    }
    pagesCrawled++;
    inlineBlocks += v.inlineCount;
    bytesScanned += v.bytes;
    rawFindings.push(...v.findings);
  });

  // ── Pass 2: external scripts, each fetched once ────────────────────────
  const externalUrls = [...externalRefs.keys()];
  if (externalUrls.length) {
    console.log(`[*] Fetching ${externalUrls.length} unique external script(s)...`);
  }

  const scriptResults = await mapLimit(externalUrls, concurrency, async (url) => {
    const js = await fetchText(url, timeout);
    if (js === null) return { url, ok: false, error: "script fetch failed (non-2xx, empty, or > MAX_SCRIPT_BYTES)" };
    const pages = [...externalRefs.get(url)];
    return {
      url,
      ok: true,
      bytes: js.length,
      // A script shared by many pages gets one finding carrying the first
      // referencing page for context; the full list lives on `pages`.
      findings: scanBlob(js, { url, sourceType: "js-file", pageUrl: pages[0] }).map((f) => ({
        ...f,
        referenced_by: pages,
      })),
    };
  });

  let externalScanned = 0;
  scriptResults.forEach((r, i) => {
    if (!r.ok) {
      errors.push({ url: externalUrls[i], stage: "script", error: r.error?.message || String(r.error) });
      return;
    }
    const v = r.value;
    if (!v.ok) {
      errors.push({ url: v.url, stage: "script", error: v.error || "could not be fetched or was too large" });
      return;
    }
    externalScanned++;
    bytesScanned += v.bytes;
    rawFindings.push(...v.findings);
  });

  // ── Deduplicate ───────────────────────────────────────────────────────
  // Same rule firing at the same position in the same URL is one finding,
  // however many pages led there.
  const byKey = new Map();
  for (const f of rawFindings) {
    const key = `${f.url}::${f.id}::${f.line}::${f.column_start}`;
    if (!byKey.has(key)) byKey.set(key, f);
  }
  const findings = [...byKey.values()].sort((a, b) => {
    const rank = { critical: 0, high: 1, medium: 2, low: 3 };
    const d = (rank[a.severity] ?? 4) - (rank[b.severity] ?? 4);
    if (d !== 0) return d;
    return String(a.url).localeCompare(String(b.url)) || a.line - b.line;
  });

  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  const byCategory = {};
  const affectedUrls = new Set();
  for (const f of findings) {
    const sev = String(f.severity || "unknown").toLowerCase();
    bySeverity[sev in bySeverity ? sev : "unknown"]++;
    byCategory[f.category || "other"] = (byCategory[f.category || "other"] || 0) + 1;
    affectedUrls.add(f.url);
  }

  console.log(`[*] ${findings.length} exposed secret(s) found across ${affectedUrls.size} URL(s).`);

  return {
    findings,
    errors,
    stats: {
      pages_crawled: pagesCrawled,
      inline_blocks: inlineBlocks,
      external_scripts: externalScanned,
      external_scripts_referenced: externalUrls.length,
      bytes_scanned: bytesScanned,
      total: findings.length,
      by_severity: bySeverity,
      by_category: byCategory,
      affected_urls: affectedUrls.size,
    },
  };
}