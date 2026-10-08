/**
 * secrets.js — secrets-in-source scanner: file walk + rule-matching engine.
 *
 * Original code (not ported from Trivy) — the ruleset it consumes
 * (vendor/trivy/rules.js, vendor/trivy/allow-rules.js) is ported from Trivy
 * and separately attributed there, in vendor/trivy/NOTICE and
 * vendor/trivy/LICENSE. Only vendor/trivy/ is Apache-2.0; this file is not.
 *
 * Scans the *codebase* (source files) for accidentally-committed secrets.
 * Deliberately independent from any dependency-scanning engine: it never
 * touches node_modules/vendor/target/etc., never resolves a lockfile, and
 * never talks to a vulnerability database. It just walks files on disk and
 * pattern-matches their contents against the ported ruleset.
 *
 * Pure in-memory scanner: scanSecrets() never writes a report to disk — it
 * always returns the findings list. Callers (engine.js) decide what to do
 * with it (fold into the main scan report, HTML, SBOM, SARIF, etc.).
 *
 * Related modules:
 *   secrets_git.js  — git history scanning and staged-changes scanning (reuses scanText)
 *   secrets_cli.js  — extra `ubel-secrets` flags: --history, --staged,
 *                     --install-hook / --uninstall-hook, --write-baseline
 *   secrets_hook.js — install / remove the git pre-commit hook
 *
 * None of these modules edit .gitignore / .dockerignore; main.js does that
 * once, before anything runs (see ignore_files.js).
 *
 * Suppressing findings (see loadIgnoreConfig for the full syntax):
 *   - `.ubelignore` at the scan root: path globs, `rule:<id>`,
 *     `fingerprint:<hex>`, `include-dir:<name>`, `exclude-dir:<name>`,
 *     `unallow:<builtin-allow-rule-id>`
 *   - inline markers: `ubel:ignore`, `ubel:ignore[rule-id,...]`,
 *     `ubel:ignore-next-line`
 */

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { builtinRules } from "./vendor/trivy/rules.js";
import { builtinAllowRules } from "./vendor/trivy/allow-rules.js";

// ── Directories that are never walked, and cannot be re-included: VCS
//    metadata and our own report directory.
const ALWAYS_SKIPPED_DIRS = new Set([".git", ".svn", ".hg", ".ubel"]);

// ── Directories skipped by default: dependency trees, build output, caches.
//    This is what makes the scan "codebase, not deps". Every name here can be
//    re-included with `include-dir:<name>` in .ubelignore or the `includeDirs`
//    option. (`packages`, `bin`, `obj` and `env` are NOT here — see
//    SOFT_IGNORED_DIRS below.)
const IGNORED_DIRS = new Set([
  // JS/Node
  "node_modules", "bower_components",
  // C# / .NET (NuGet cache)
  ".nuget",
  // Go / PHP (vendored deps)
  "vendor",
  // Java / Maven / Gradle / Rust (local repo + build output)
  "target", ".m2", ".gradle",
  // Python (virtualenvs, installed packages, bytecode caches)
  ".venv", "venv", "site-packages", "__pycache__", ".mypy_cache", ".pytest_cache",
  // Ruby / Bundler
  ".bundle",
  // Rust / Cargo global registry cache
  ".cargo",
  // generic build output / editor / caches
  "dist", "build", "out",
  ".next", ".nuxt", ".cache",
  ".idea", ".vscode",
  "coverage", ".secrets-dig", ".snyk", ".trivy",
  ".sass-cache", ".parcel-cache", ".yarn", ".pnpm-store", ".pnpm",
]);

// ── Directories whose names are ambiguous: skipped only when the layout says
//    they hold generated/installed content, and walked otherwise. A monorepo
//    `packages/*` or a Node `bin/` of CLI scripts is source; a NuGet
//    `packages/` or a .NET `bin/`/`obj/` is not.
const DOTNET_PROJECT_FILE = /\.(?:sln|csproj|fsproj|vbproj)$/i;
const SOFT_IGNORED_DIRS = {
  packages: ({ siblingIsDotnet, dirHas }) => siblingIsDotnet || dirHas("repositories.config"),
  bin:      ({ siblingIsDotnet }) => siblingIsDotnet,
  obj:      ({ siblingIsDotnet }) => siblingIsDotnet,
  env:      ({ dirHas }) => dirHas("pyvenv.cfg"),
};

// ── File extensions treated as scannable source/config/text. Anything not
//    in this set (images, archives, binaries, etc.) is skipped outright,
//    except for the key-file sniffing described below.
const TEXT_EXTENSIONS = new Set([
  ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
  ".json", ".yml", ".yaml",
  ".ini", ".conf", ".config", ".cfg",
  ".py", ".rb", ".go", ".java", ".php", ".c", ".h", ".cpp", ".hpp",
  ".cs", ".rs", ".kt", ".swift",
  ".sh", ".bash", ".zsh", ".ps1",
  ".xml", ".html", ".htm", //".css", ".scss",
  ".sql", ".md", ".txt", ".toml", ".properties", ".gradle",
  ".tf", ".tfvars",
  ".pem", ".key",
]);

// ── Extension-less / dotfile names that are still worth scanning.
const NAMED_FILE_ALLOW = new Set([
  "Dockerfile", "Makefile", ".npmrc", ".netrc", ".htpasswd", ".pgpass",
  "settings.xml", "settings-security.xml", // path-scoped Maven rules target these
  ".git-credentials", ".pypirc", ".dockercfg", ".s3cfg", "credentials",
]);

// SSH private keys have no extension (`id_rsa`) or a backup suffix
// (`id_rsa.bak`, `id_ed25519-old`). Always scan them.
const KEY_FILE_NAME = /^id_(?:rsa|dsa|ecdsa|ed25519)(?:[._-].*)?$/;

// Files with no extension, or one of these, are opened and sniffed for a PEM
// private-key header; only those that look like keys are then scanned. This is
// what picks up `server.key.old`, `deploy`, `cert-backup.1` and friends
// without reading every unknown file in full.
const SNIFF_EXTENSIONS = new Set([
  ".bak", ".old", ".orig", ".backup", ".save", ".tmp", ".p8", ".ppk", ".asc",
]);
const SNIFF_BYTES = 2048;
const SNIFF_MAX_FILE_SIZE = 256 * 1024;
const PEM_PRIVATE_HEADER = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY/;

const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB — skip anything larger

// A matched "secret" longer than this is almost always a regex match that
// spanned a minified/bundled line rather than a real credential, so we
// allow dropping it. This is deliberately generous — the old cap of 4096
// silently discarded legitimate long tokens (large JWTs, PEM bodies,
// base64 blobs). Nothing in the finding object scales with the match
// length: `match_preview` is redacted to ~26 chars by redact(), and
// column_end is just a number. A single line can never exceed the file
// size, so MAX_FILE_SIZE is the true upper bound.
const MAX_SECRET_LENGTH = 40960;

// Upper bound on matches of one rule on one line, so a pathological
// minified line can't produce an unbounded number of findings.
const MAX_MATCHES_PER_RULE_PER_LINE = 50;

// Rules whose pattern spans lines (PEM blocks). These run once over the whole
// file text instead of line by line. Value: a cheap literal that must appear
// in the text for the rule to be worth running.
const MULTILINE_RULES = new Map([
  ["private-key", /private key/i],
  ["private-key-with-headers", /private key/i],
]);

// ─────────────────────────────────────────────────────────────────────────────
// Ignore configuration (.ubelignore + options)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Translate one gitignore-style glob into a RegExp over a "/"-separated path.
 *   leading "/"        anchored at the scan root
 *   trailing "/"       directories only (matches everything below them)
 *   no "/" in pattern  matches at any depth
 *   *  ?  **           as in .gitignore ("**" crosses directories)
 * Negation ("!") is intentionally not supported.
 */
function globToRegex(pattern) {
  let p = pattern;
  let anchored = false;
  let dirOnly = false;
  if (p.startsWith("/")) { anchored = true; p = p.slice(1); }
  if (p.endsWith("/")) { dirOnly = true; p = p.slice(0, -1); }
  if (!anchored && p.includes("/")) anchored = true;

  let body = "";
  for (let i = 0; i < p.length; i++) {
    const c = p[i];
    if (c === "*") {
      if (p[i + 1] === "*") {
        i++;
        if (p[i + 1] === "/") { i++; body += "(?:.*/)?"; } else body += ".*";
      } else body += "[^/]*";
    } else if (c === "?") {
      body += "[^/]";
    } else {
      body += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
    }
  }
  return { re: new RegExp(anchored ? `^${body}$` : `^(?:.*/)?${body}$`), dirOnly };
}

// A glob "hits" a path if it matches the path itself or any ancestor
// directory of it (so `secrets/` ignores everything under secrets/).
function globHits({ re, dirOnly }, relPath, isDir) {
  const segs = relPath.split("/");
  let acc = "";
  for (let i = 0; i < segs.length; i++) {
    acc = i === 0 ? segs[i] : `${acc}/${segs[i]}`;
    const last = i === segs.length - 1;
    if (last && dirOnly && !isDir) break;
    if (re.test(acc)) return true;
  }
  return false;
}

export class IgnoreConfig {
  constructor() {
    this.rules = new Set();          // rule ids disabled everywhere
    this.fingerprints = new Set();   // baselined findings
    this.includeDirs = new Set();    // default-skipped dirs to walk anyway
    this.ignoreDirs = new Set();     // extra dir names to skip
    this.unallow = new Set();        // builtin allow-rule ids to switch off
    this.pathGlobs = [];             // unscoped: skip matching files/dirs entirely
    this.scopedGlobs = [];           // `glob rule:<id>`: suppress only that rule
    this.suppressed = 0;             // findings dropped by this config (stats)
  }

  /** Parse .ubelignore-style text and merge it into this config. */
  addText(text) {
    for (const raw of String(text).split(/\r\n|\r|\n/)) {
      const line = raw.replace(/\s+#.*$/, "").trim();
      if (!line || line.startsWith("#")) continue;

      const directive = /^(rule|fingerprint|include-dir|exclude-dir|unallow):(.+)$/.exec(line);
      if (directive) {
        const value = directive[2].trim();
        switch (directive[1]) {
          case "rule":        value.split(",").forEach(id => id.trim() && this.rules.add(id.trim())); break;
          case "fingerprint": this.fingerprints.add(value.toLowerCase()); break;
          case "include-dir": this.includeDirs.add(value.replace(/\/+$/, "")); break;
          case "exclude-dir": this.ignoreDirs.add(value.replace(/\/+$/, "")); break;
          case "unallow":     value.split(",").forEach(id => id.trim() && this.unallow.add(id.trim())); break;
        }
        continue;
      }

      const [glob, ...rest] = line.split(/\s+/);
      const scope = rest.find(t => t.startsWith("rule:"));
      const compiled = globToRegex(glob);
      if (scope) {
        const ids = scope.slice(5).split(",").map(s => s.trim()).filter(Boolean);
        for (const ruleId of ids) this.scopedGlobs.push({ ...compiled, ruleId });
      } else {
        this.pathGlobs.push(compiled);
      }
    }
    return this;
  }

  /** Is this file/dir excluded outright by an unscoped glob? */
  isPathIgnored(relPath, isDir = false) {
    return this.pathGlobs.some(g => globHits(g, relPath, isDir));
  }

  /** Is this rule suppressed for this path by a `glob rule:<id>` line? */
  isRuleIgnoredForPath(ruleId, relPath) {
    return this.scopedGlobs.some(g => g.ruleId === ruleId && globHits(g, relPath, false));
  }
}

const EMPTY_IGNORE = new IgnoreConfig();

/**
 * Build the effective ignore config for a scan.
 *
 * Sources, merged: `<root>/.ubelignore` (or options.ignoreFile), then options.
 *
 * .ubelignore syntax (one entry per line, `#` starts a comment):
 *   docs/generated/            skip a directory (and everything under it)
 *   *.snap                     skip files by glob, at any depth
 *   /fixtures/keys/*.pem       leading "/" anchors to the scan root
 *   src/seed.js rule:generic-key-value-credential
 *                              suppress one rule (comma list ok) on matching paths
 *   rule:generic-fallback      disable a rule everywhere
 *   fingerprint:<hex>          baseline one specific finding (see finding.fingerprint)
 *   include-dir:packages       walk a directory that is skipped by default
 *   exclude-dir:generated      skip a directory name wherever it appears
 *   unallow:tests              switch off a builtin allow-rule (e.g. scan test paths)
 *
 * Inline markers (in the scanned file itself, any comment syntax):
 *   ubel:ignore                suppress findings on this line
 *   ubel:ignore[rule-a,rule-b] suppress only those rules on this line
 *   ubel:ignore-next-line      same, for the following line
 *
 * @param {string} root
 * @param {object} [options]
 * @param {string}   [options.ignoreFile]      explicit path instead of <root>/.ubelignore
 * @param {boolean}  [options.useIgnoreFile=true]
 * @param {string[]} [options.ignorePatterns]  extra .ubelignore-syntax lines
 * @param {string[]} [options.ignoreDirs]      extra dir names to skip
 * @param {string[]} [options.includeDirs]     default-skipped dir names to walk
 * @param {string[]} [options.unallow]         builtin allow-rule ids to disable
 * @param {IgnoreConfig} [options.ignore]      pre-built config (returned as is)
 */
export function loadIgnoreConfig(root, options = {}) {
  if (options.ignore instanceof IgnoreConfig) return options.ignore;
  const cfg = new IgnoreConfig();

  if (options.useIgnoreFile !== false) {
    const file = options.ignoreFile
      ? path.resolve(options.ignoreFile)
      : path.join(root, ".ubelignore");
    try {
      cfg.addText(fs.readFileSync(file, "utf8"));
    } catch (e) {
      // A missing default file is normal; an explicitly requested one is not.
      if (options.ignoreFile) throw new Error(`Cannot read ignore file ${file}: ${e.message}`);
    }
  }
  if (options.ignorePatterns?.length) cfg.addText(options.ignorePatterns.join("\n"));
  for (const d of options.ignoreDirs ?? []) cfg.ignoreDirs.add(d);
  for (const d of options.includeDirs ?? []) cfg.includeDirs.add(d);
  for (const id of options.unallow ?? []) cfg.unallow.add(id);
  return cfg;
}

// Inline suppression markers.
const INLINE_IGNORE = /ubel:ignore(?!-next-line)(?:\[([A-Za-z0-9_.,\- ]+)\])?/;
const INLINE_IGNORE_NEXT = /ubel:ignore-next-line(?:\[([A-Za-z0-9_.,\- ]+)\])?/;

function markerCovers(match, ruleId) {
  if (!match) return false;
  if (!match[1]) return true; // bare marker: every rule
  return match[1].split(",").map(s => s.trim()).includes(ruleId);
}

function isInlineIgnored(lines, idx, ruleId) {
  if (markerCovers(INLINE_IGNORE.exec(lines[idx] ?? ""), ruleId)) return true;
  return idx > 0 && markerCovers(INLINE_IGNORE_NEXT.exec(lines[idx - 1] ?? ""), ruleId);
}

/**
 * Stable identity of a finding that survives line moves and re-scans:
 * sha256(ruleId \0 path \0 secret), first 64 bits. Safe to commit in
 * .ubelignore — it cannot be reversed for a high-entropy secret, and the raw
 * secret is never stored anywhere.
 */
export function fingerprint(ruleId, relPath, secret) {
  return crypto.createHash("sha256")
    .update(`${ruleId}\0${relPath}\0${secret}`)
    .digest("hex")
    .slice(0, 16);
}


// extra-rules.js
export const extraRules = [
  // ── Already present ──
  {
    id: "anthropic-api-key",
    category: "Anthropic",
    severity: "CRITICAL",
    title: "Anthropic API Key",
    keywords: ["sk-ant-"],
    path: null,
    regex: new RegExp(String.raw`(?:^|[^0-9A-Za-z_])(?<secret>sk-ant-[A-Za-z0-9_-]{95})(?:[^0-9A-Za-z_]|$)`, ""),
    allowRules: [],
  },
  {
    id: "google-api-key",
    category: "Google",
    severity: "HIGH",
    title: "Google Cloud API Key",
    keywords: ["AIza"],
    path: null,
    regex: new RegExp(String.raw`(?:^|[^0-9A-Za-z_])(?<secret>AIza[0-9A-Za-z\-_]{35})(?:[^0-9A-Za-z_]|$)`, ""),
    allowRules: [],
  },
  {
    id: "vault-token",
    category: "HashiCorp",
    severity: "CRITICAL",
    title: "HashiCorp Vault Token",
    keywords: ["hvs."],
    path: null,
    regex: new RegExp(String.raw`(?:^|[^0-9A-Za-z_])(?<secret>hvs\.[A-Za-z0-9_-]{36})(?:[^0-9A-Za-z_]|$)`, ""),
    allowRules: [],
  },
  {
    id: "generic-fallback",
    category: "Generic",
    severity: "HIGH",
    title: "Generic High‑Entropy Token",
    generic: true,
    keywords: ["sk-", "pk_", "xoxb", "xoxp", "api_", "key_", "token_"],
    path: null,
    // `value` is the part after the vendor-style prefix. The entropy gate is
    // measured on it (not on the prefix), so a run like token_aaaa… or a
    // snake_case identifier is rejected while random-looking tokens pass.
    regex: new RegExp(String.raw`(?<secret>\b(?:sk-|pk_|xox[baprs]|api_|key_|token_)(?<value>[0-9A-Za-z_\-+/]{32,}))`, ""),
    // Minimum Shannon entropy in bits per character: base62/base64-ish
    // bodies need >= 4.0; pure hex bodies (max 4.0 by alphabet) need >= 3.0.
    entropy: { min: 4.0, minHex: 3.0 },
    allowRules: [],
  },
  {
    id: "generic-key-value-credential",
    category: "Generic",
    severity: "HIGH",
    title: "Generic Key‑Value Credential",
    generic: true,
    keywords: ["password", "secret", "token", "api_key", "private_key"],
    path: null,
    regex: new RegExp(String.raw`(?:password|secret|token|api[_\s-]?key|private[_\s-]?key)\s*[:=]\s*["']?(?<secret>[A-Za-z0-9/+_\-]{32,})["']?`, "i"),
    allowRules: [],
  },
  {
    id: "openrouter-api-key",
    category: "OpenRouter",
    severity: "CRITICAL",
    title: "OpenRouter API Key",
    keywords: ["sk-or-v1-"],
    path: null,
    regex: new RegExp(String.raw`(?:^|[^0-9A-Za-z_])(?<secret>sk-or-v1-[A-Za-z0-9_-]{20,100})`, ""),
    allowRules: [],
  },

  // ── NEW (sensitive only) ──
  {
    id: "firebase-token",
    category: "Firebase",
    severity: "HIGH",
    title: "Firebase Server Token",
    keywords: ["AAAA"],
    path: null,
    regex: new RegExp(String.raw`(?:^|[^0-9A-Za-z_])(?<secret>AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140})(?:[^0-9A-Za-z_]|$)`, ""),
    allowRules: [],
  },
  {
    id: "google-oauth-token",
    category: "Google",
    severity: "HIGH",
    title: "Google OAuth Access Token",
    keywords: ["ya29."],
    path: null,
    regex: new RegExp(String.raw`(?:^|[^0-9A-Za-z_])(?<secret>ya29\.[0-9A-Za-z\-_]+)(?:[^0-9A-Za-z_]|$)`, ""),
    allowRules: [],
  },
  {
    id: "amazon-mws-auth-token",
    category: "AWS",
    severity: "CRITICAL",
    title: "Amazon MWS Auth Token",
    keywords: ["amzn.mws."],
    path: null,
    regex: new RegExp(String.raw`(?<secret>amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`, "i"),
    allowRules: [],
  },
  {
    id: "facebook-access-token",
    category: "Facebook",
    severity: "HIGH",
    title: "Facebook Access Token",
    keywords: ["EAACEdEose0cBA"],
    path: null,
    regex: new RegExp(String.raw`(?:^|[^0-9A-Za-z_])(?<secret>EAACEdEose0cBA[0-9A-Za-z]+)(?:[^0-9A-Za-z_]|$)`, ""),
    allowRules: [],
  },
  // ── DISABLED ON PURPOSE (too noisy) ──────────────────────────────────────
  // auth-basic, auth-bearer, auth-api-key, twilio-account-sid and
  // twilio-app-sid are commented out below. The Twilio SID patterns are just
  // "AC"/"AP" + 32 chars with no checksum or distinguishing context, so they
  // fire on ordinary identifiers and hashes and drowned real findings in
  // noise. Do not re-enable without a contextual prefilter (e.g. requiring a
  // "twilio" / "account_sid" key name on the same line).
  /*{
    id: "auth-basic",
    category: "Authorization",
    severity: "HIGH",
    title: "HTTP Basic Auth Credentials",
    keywords: ["basic "],
    path: null,
    regex: new RegExp(String.raw`(?:^|[^0-9A-Za-z_])basic\s+(?<secret>[a-zA-Z0-9=:_\+\/-]{5,100})(?:[^0-9A-Za-z_]|$)`, "i"),
    allowRules: [],
  },
  {
  id: "auth-bearer",
  category: "Authorization",
  severity: "HIGH",
  title: "HTTP Bearer Token",
  keywords: ["bearer "],
  path: null,
  regex: new RegExp(
    String.raw`(?:^|[^0-9A-Za-z_])bearer\s+["']?(?<secret>(?![\${\s])(?=.*[0-9\-_=:+/.])(?!\${)[A-Za-z0-9_\-\.=:_\+\/]{20,200})["']?(?:[^0-9A-Za-z_]|$)`,
    "i"
  ),
  allowRules: [
    {
      id: "bearer-placeholder",
      description: "Ignore obvious placeholders and environment variables",
      regex: /bearer\s+(?:token|['"]?\${\s*[^}]*\s*}|process\.env|['"]?[a-z]{1,20}['"]?)/i,
    },
  ],
},
  {
    id: "auth-api-key",
    category: "Authorization",
    severity: "MEDIUM",
    title: "API Key in Header/Value",
    keywords: ["api", "key"],
    path: null,
    regex: new RegExp(String.raw`(?:^|[^0-9A-Za-z_])(?:api[_\s-]?key)\s*[:=]\s*["']?(?<secret>[a-zA-Z0-9_\-]{5,100})["']?`, "i"),
    allowRules: [],
  },
  {
    id: "twilio-account-sid",
    category: "Twilio",
    severity: "HIGH",
    title: "Twilio Account SID",
    keywords: ["AC"],
    path: null,
    regex: new RegExp(String.raw`(?<secret>AC[a-zA-Z0-9_\-]{32})`, ""),
    allowRules: [],
  },
  {
    id: "twilio-app-sid",
    category: "Twilio",
    severity: "HIGH",
    title: "Twilio App SID",
    keywords: ["AP"],
    path: null,
    regex: new RegExp(String.raw`(?<secret>AP[a-zA-Z0-9_\-]{32})`, ""),
    allowRules: [],
  },*/
  {
    id: "braintree-access-token",
    category: "PayPal",
    severity: "CRITICAL",
    title: "Braintree Access Token",
    keywords: ["access_token$production$"],
    path: null,
    regex: new RegExp(String.raw`(?<secret>access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32})`, "i"),
    allowRules: [],
  },
  {
    id: "square-oauth-secret",
    category: "Square",
    severity: "HIGH",
    title: "Square OAuth Secret",
    keywords: ["sq0csp-", "sq0"],
    path: null,
    regex: new RegExp(String.raw`(?<secret>(?:sq0csp-[0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}))`, ""),
    allowRules: [],
  },
  {
    id: "square-access-token",
    category: "Square",
    severity: "HIGH",
    title: "Square Access Token",
    keywords: ["sq0atp-", "EAAA"],
    path: null,
    // `EAAA` is also just four base64 characters (a zero-padded run encodes to
    // "AAAA"), so the unbounded Trivy pattern matched inside inlined wasm /
    // data-URI blobs and produced dozens of false positives per file. A real
    // token is a standalone string: it must not sit inside a longer
    // base64/base64url run — no base64 character directly before or after
    // (`=` is fine before it: TOKEN=EAAA...) — and, being random base62, it
    // must clear an entropy check, which rejects padding-heavy blob fragments.
    // (The legacy prefix is "sq0atp-" with a ZERO. It was spelled with a
    // letter O here, so this alternative was dead code; such tokens were only
    // ever caught by square-oauth-secret's broader `sq0[a-z]{3}-` pattern.)
    regex: new RegExp(String.raw`(?<![0-9A-Za-z+/_-])(?<secret>(?:sq0atp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}))(?![0-9A-Za-z+/=_-])`, ""),
    entropy: { min: 4.0, minHex: 4.0 },
    allowRules: [],
  },
  {
    id: "stripe-restricted-key",
    category: "Stripe",
    severity: "CRITICAL",
    title: "Stripe Restricted API Key",
    // Live keys only: test-mode keys (rk_test_) can't touch real money or
    // customer data, so they are deliberately out of scope.
    keywords: ["rk_live_"],
    path: null,
    regex: new RegExp(String.raw`(?:^|[^0-9A-Za-z_])(?<secret>rk_live_[0-9a-zA-Z]{24})(?:[^0-9A-Za-z_]|$)`, "i"),
    allowRules: [],
  },
  {
    id: "github-basic-auth-url",
    category: "GitHub",
    severity: "HIGH",
    title: "GitHub Credentials in URL",
    keywords: ["@github.com"],
    path: null,
    regex: new RegExp(String.raw`(?<secret>[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com)`, ""),
    allowRules: [],
  },
  {
    // Everything except github.com, which has its own rule above. Matches
    // https://user:token@<host>/... for the well-known git hosts, for
    // self-hosted instances whose hostname starts with a git-forge name
    // (git.corp.example, gitlab.internal, gitea.acme.io, ...), and for any
    // other host when the URL path ends in ".git" (a git remote). The
    // `secret` group is the password/token only, so the redacted preview
    // shows something useful instead of the host name.
    id: "git-url-credentials",
    category: "Git",
    severity: "HIGH",
    title: "Git Credentials in URL",
    keywords: [
      "@gitlab", "@bitbucket", "@dev.azure.com", ".visualstudio.com",
      "@codeberg", "@gitea", "@gitee", "@git.", "@forgejo", "@gogs", ".git",
    ],
    path: null,
    regex: new RegExp(
      String.raw`(?:https?|git\+https?)://[A-Za-z0-9_.~%-]+:(?<secret>[A-Za-z0-9_.~%-]{6,})@(?:(?:gitlab\.com|bitbucket\.org|(?:ssh\.)?dev\.azure\.com|[A-Za-z0-9-]+\.visualstudio\.com|codeberg\.org|gitea\.com|gitee\.com|git\.sr\.ht|(?:git|gitlab|bitbucket|gitea|gogs|forgejo)[A-Za-z0-9-]*\.[A-Za-z0-9.-]+)(?::\d+)?(?=[/\s'"?#:]|$)|[A-Za-z0-9.-]+(?::\d+)?/[^\s'"]*\.git(?=[/\s'"?#]|$))`,
      "i"
    ),
    allowRules: [
      {
        id: "git-url-placeholder",
        description: "Ignore obvious placeholder passwords in documentation-style URLs",
        regex: /:(?:password|passwd|pass|pwd|token|secret|changeme|placeholder|x{4,}|\*{3,}|your[_-]?\w*)@/i,
      },
    ],
  },

  // ── Database / broker connection strings ───────────────────────────────────
  // Three shapes, one rule each. In all three the `secret` group is the
  // password only, so the redacted preview shows the credential, not the host.
  // Values that are obviously not real are skipped by the shared character
  // class (no `$`, `{`, `<`, `%`, `@`, `#`, `(` or `[` as the first character:
  // ${VAR}, $VAR, {0}, <password>, %PWD%, @param, #{pw}) and by allowRules.

  // 1. URI form:  postgres://user:pass@host/db   redis://:pass@host
  //    mongodb+srv://u:p@cluster/…   postgresql+psycopg2://u:p@host/db
  {
    id: "database-url-credentials",
    category: "Database",
    severity: "HIGH",
    title: "Database Credentials in Connection URL",
    keywords: [
      "postgres", "mysql", "mariadb", "mongodb", "redis", "amqp", "mssql",
      "sqlserver", "cockroachdb", "clickhouse", "neo4j", "bolt",
    ],
    path: null,
    // The host is consumed (optionally) only so the default-credential
    // allow-rule below can tell a local/compose host from a real one.
    regex: new RegExp(
      String.raw`(?<![A-Za-z0-9])(?:postgres(?:ql)?|mysql|mariadb|mongodb|rediss?|amqps?|mssql|sqlserver|cockroachdb|clickhouse|neo4j|bolt)(?:\+[a-z0-9_]+)*:\/\/[^\s:@\/'"<>{}$\x60\\]*:(?<secret>[^\s@\/'"<>{}$\x60\\]{3,})@(?:[A-Za-z0-9_.-]+|\[[0-9a-f:]+\])?`,
      "i"
    ),
    allowRules: [
      {
        id: "db-url-placeholder",
        description: "Placeholder passwords in documentation-style URLs",
        regex: /:(?:password|passwd|pass|pwd|secret|changeme|change[_-]?me|placeholder|redacted|x{3,}|\*{3,}|\.{3,}|(?:your|my)[_-]?\w*|%(?:\(\w+\))?[sd])@/i,
      },
      {
        id: "db-url-user-equals-password",
        description: "user:user credentials (guest:guest, root:root) are defaults, not secrets",
        regex: /:\/\/([^:@\/\s]+):\1@/i,
      },
      {
        id: "db-url-local-default",
        description: "Well-known default password against a local or docker-compose host",
        regex: /:(?:postgres|root|admin|guest|test|mysql|redis|mongo|mariadb|rabbitmq?|demo|dev|changeit|1234\d*|qwerty)@(?:localhost|127\.0\.0\.1|0\.0\.0\.0|host\.docker\.internal|\[::1\]|[a-z0-9_-]+)$/i,
      },
    ],
  },

  // 2. key=value form (ADO.NET, ODBC, libpq):
  //    Server=db;Database=app;User Id=sa;Password=...;   host=db user=u password=...
  {
    id: "database-connection-string-password",
    category: "Database",
    severity: "HIGH",
    title: "Password in Database Connection String",
    keywords: ["password", "pwd"],
    path: null,
    // Requires a host/database key earlier on the same line, so a bare
    // `password=` (handled by the generic rule) does not count as a connection string.
    regex: new RegExp(
      String.raw`(?<![A-Za-z0-9_])(?:server|data source|host|address|addr|network address|initial catalog|database|dsn|driver)\s*=[^\n]{0,300}?[;\s'"](?:password|pwd)\s*=\s*['"]?(?<secret>[^\s;'"&$<{%@#(\[\\][^\s;'"&]{3,})`,
      "i"
    ),
    allowRules: [
      {
        id: "db-conn-placeholder",
        description: "Placeholder passwords in documentation-style connection strings",
        regex: /(?:password|pwd)\s*=\s*['"]?(?:password|passwd|pass|pwd|secret|changeme|change[_-]?me|placeholder|redacted|x{3,}|\*{3,}|\.{3,}|(?:your|my)[_-]?\w*)$/i,
      },
    ],
  },

  // 3. JDBC with credentials in the query/parameters:
  //    jdbc:mysql://host/db?user=u&password=...   jdbc:sqlserver://h;user=u;password=...
  {
    id: "jdbc-url-password",
    category: "Database",
    severity: "HIGH",
    title: "Password in JDBC URL",
    keywords: ["jdbc:"],
    path: null,
    regex: new RegExp(
      String.raw`jdbc:[a-z0-9]+:[^\s'"]{0,300}?[?;&]\s*(?:password|pwd)\s*=\s*(?<secret>[^\s;'"&$<{%@#(\[\\][^\s;'"&]{3,})`,
      "i"
    ),
    allowRules: [
      {
        id: "jdbc-placeholder",
        description: "Placeholder passwords in documentation-style JDBC URLs",
        regex: /(?:password|pwd)\s*=\s*(?:password|passwd|pass|pwd|secret|changeme|change[_-]?me|placeholder|redacted|x{3,}|\*{3,}|\.{3,}|(?:your|my)[_-]?\w*)$/i,
      },
    ],
  },
];

builtinRules.push(...extraRules);

// ── AWS rule fixes ───────────────────────────────────────────────────────────
// The ported AWS patterns only accepted whitespace or end-of-line after the
// key (optionally preceded by a quote and one of . ,). So the most common ways
// a key actually appears in code were missed:
//     const k = "AKIA...";        AWS_ACCESS_KEY_ID=AKIA...;        [“AKIA...”)]
// Instead of requiring a particular terminator, require that the key does NOT
// continue: no further word character or base64 character (+ / =) follows it.
// That still rejects over-long strings (AKIA + 17 chars) and base64 blobs, but
// accepts ; ) ] } > and every other delimiter. rules.js is generated from
// upstream and must not be hand-edited, so the fix lives here, next to the
// other rule extensions.
{
  const accessKeyId = builtinRules.find(r => r.id === "aws-access-key-id");
  if (accessKeyId) {
    accessKeyId.regex = new RegExp(
      String.raw`(?:^|[^0-9A-Za-z_])(?<secret>(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})(?![0-9A-Za-z_+/=])`,
      "");
    // "A3T" keys were unreachable: the keyword prefilter never listed that prefix.
    if (!accessKeyId.keywords.includes("A3T")) accessKeyId.keywords = [...accessKeyId.keywords, "A3T"];
  }
  const secretAccessKey = builtinRules.find(r => r.id === "aws-secret-access-key");
  if (secretAccessKey) {
    secretAccessKey.regex = new RegExp(
      String.raw`["']?aws_?(?:sec(?:ret)?)?_?(?:access)?_?key["']?\s*(?::|=>|=)?\s*["']?(?<secret>[A-Za-z0-9\/\+=]{40})(?![A-Za-z0-9\/\+=])`,
      "i");
  }
}

// Encrypted/legacy PEM and PGP private keys carry header lines between the
// BEGIN marker and the base64 body ("Proc-Type: 4,ENCRYPTED", "DEK-Info: ...",
// "Version: ..."), which the ported private-key pattern doesn't allow. Like
// private-key it spans lines, so it is listed in MULTILINE_RULES. When both
// match the same key, overlap resolution keeps one finding.
builtinRules.push({
  id: "private-key-with-headers",
  category: "AsymmetricPrivateKey",
  severity: "HIGH",
  title: "Asymmetric Private Key (PEM with headers)",
  keywords: ["-----"],
  path: null,
  regex: new RegExp(String.raw`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[ \t]*\n(?:[A-Za-z0-9-]+:[^\n]*\n)+[ \t]*\n(?<secret>[A-Za-z0-9=+/\\][A-Za-z0-9=+/\\\s]{30,}[A-Za-z0-9=+/\\])\s*-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----`, ""),
  allowRules: [],
});

const ExtraAllowRules = [
  {
    id: "bearer-placeholder",
    description: "Ignore bearer tokens that are placeholders",
    regex: /bearer\s+token/i,  // matches "Bearer Token" anywhere in the matched text
  },
  {
    id: "lockfiles",
    description: "Ignore dependency lock files (pnpm-lock.yaml, package-lock.json, etc.)",
    path: /(?:^|[\/\\])(?:pnpm-lock\.yaml|package-lock\.json|yarn\.lock|composer\.lock|Gemfile\.lock)$/,
  },
  {
    id: "env-var-secret",
    description: "Ignore environment variable references as secret values",
    content: /process\.env\.[A-Za-z0-9_]+/,
  },
  {
    id: "template-literal-placeholder",
    description: "Ignore template literal placeholders",
    content: /\$\{[^}]*\}/,
  },
  /*{
    id: "short-bearer-token",
    description: "Ignore short alphabetic bearer tokens (≤20 letters)",
    content: /bearer\s+[A-Za-z]{1,20}/i,
  },
  {
    id: "short-api-key",
    description: "Ignore short alphabetic API key assignments (≤15 letters)",
    content: /api[_\-]?key\s*[:=]\s*['"]?[A-Za-z]{1,15}['"]?/i,
  },*/
]

builtinAllowRules.push(...ExtraAllowRules);

// ─────────────────────────────────────────────────────────────────────────────
// Path classification (pure — no filesystem access, so the git-history
// scanner can reuse it on paths that do not exist on disk)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * "scan"  — scan the content
 * "sniff" — unknown type (no/odd extension): scan only if the content starts
 *           like a PEM private key
 * "skip"  — never scan
 */
export function classifyPath(relPath, { includeEnvFiles = false } = {}) {
  const base = path.posix.basename(relPath);
  // ── .env* files: skipped in repository scans (they are not meant to be
  //    committed), but scanned in container-image scans, where a baked-in
  //    .env is a real leak that ships with the image. ──
  if (base.startsWith(".env")) return includeEnvFiles ? "scan" : "skip";
  if (NAMED_FILE_ALLOW.has(base) || KEY_FILE_NAME.test(base)) return "scan";
  const ext = path.posix.extname(base).toLowerCase();
  if (TEXT_EXTENSIONS.has(ext)) return "scan";
  if (ext === "" || SNIFF_EXTENSIONS.has(ext)) return "sniff";
  return "skip";
}

/** True if any directory component of relPath is skipped by default/config. */
export function pathInSkippedDir(relPath, ignore = EMPTY_IGNORE) {
  const dirs = relPath.split("/").slice(0, -1);
  return dirs.some(name => {
    if (ALWAYS_SKIPPED_DIRS.has(name)) return true;
    if (ignore.ignoreDirs.has(name)) return true;
    if (ignore.includeDirs.has(name)) return false;
    return IGNORED_DIRS.has(name);
  });
}

/**
 * Full path-level decision: skipped dirs, .ubelignore globs, extension rules
 * and the builtin path allow-list, in one place. Returns "scan" | "sniff" | "skip".
 */
export function classifyForScan(relPath, { includeEnvFiles = false, ignore = EMPTY_IGNORE } = {}) {
  if (pathInSkippedDir(relPath, ignore)) return "skip";
  if (ignore.isPathIgnored(relPath, false)) return "skip";
  const cls = classifyPath(relPath, { includeEnvFiles });
  if (cls === "skip") return "skip";
  if (isPathAllowed(relPath, ignore.unallow)) return "skip";
  return cls;
}

function sniffLooksLikeKey(fullPath) {
  let fd;
  try {
    const stat = fs.statSync(fullPath);
    if (stat.size === 0 || stat.size > SNIFF_MAX_FILE_SIZE) return false;
    fd = fs.openSync(fullPath, "r");
    const buf = Buffer.alloc(Math.min(SNIFF_BYTES, stat.size));
    fs.readSync(fd, buf, 0, buf.length, 0);
    return PEM_PRIVATE_HEADER.test(buf.toString("latin1"));
  } catch {
    return false;
  } finally {
    if (fd !== undefined) try { fs.closeSync(fd); } catch { /* ignore */ }
  }
}

function isLikelyBinary(buffer) {
  const len = Math.min(buffer.length, 8000);
  for (let i = 0; i < len; i++) {
    if (buffer[i] === 0) return true;
  }
  return false;
}

function shouldSkipDir(name, fullPath, relPath, siblingIsDotnet, ignore) {
  if (ALWAYS_SKIPPED_DIRS.has(name)) return true;
  if (ignore.ignoreDirs.has(name) || ignore.isPathIgnored(relPath, true)) return true;
  if (ignore.includeDirs.has(name)) return false;
  if (IGNORED_DIRS.has(name)) return true;
  const dirHas = (f) => fs.existsSync(path.join(fullPath, f));
  if (Object.hasOwn(SOFT_IGNORED_DIRS, name) && SOFT_IGNORED_DIRS[name]({ siblingIsDotnet, dirHas })) return true;
  // A Python virtualenv under any name (env/, .env/, myenv/ ...).
  return dirHas("pyvenv.cfg");
}

function walk(dir, files, opts) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return; // unreadable directory — skip silently
  }
  const siblingIsDotnet = entries.some(e => e.isFile() && DOTNET_PROJECT_FILE.test(e.name));

  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue;

    const fullPath = path.join(dir, entry.name);
    const relPath = path.relative(opts.root, fullPath).split(path.sep).join("/");

    if (entry.isDirectory()) {
      if (shouldSkipDir(entry.name, fullPath, relPath, siblingIsDotnet, opts.ignore)) continue;
      walk(fullPath, files, opts);
      continue;
    }

    if (!entry.isFile()) continue;
    const cls = classifyForScan(relPath, opts);
    if (cls === "skip") continue;
    if (cls === "sniff" && !sniffLooksLikeKey(fullPath)) continue;
    files.push(fullPath);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Rule matching helpers
// ─────────────────────────────────────────────────────────────────────────────

// Pre-split rules into keyword sets for fast case (in)sensitive pre-filtering,
// avoiding running every regex against every line.
function keywordHit(line, lowerLine, keywords, caseInsensitive) {
  if (!keywords.length) return true; // no keyword hint — always try the regex
  for (const kw of keywords) {
    if (caseInsensitive ? lowerLine.includes(kw.toLowerCase()) : line.includes(kw)) {
      return true;
    }
  }
  return false;
}

export function isPathAllowed(relPath, unallow = EMPTY_IGNORE.unallow) {
  for (const rule of builtinAllowRules) {
    if (unallow.has(rule.id)) continue;
    if (rule.path && rule.path.test(relPath)) return rule;
  }
  return null;
}

function isContentAllowed(matchedText, unallow) {
  for (const rule of builtinAllowRules) {
    if (unallow.has(rule.id)) continue;
    if (rule.content && rule.content.test(matchedText)) return rule;
  }
  return null;
}

// Shannon entropy in bits per character. Used by rules that opt in via an
// `entropy: { min, minHex }` field, to reject low-randomness matches (long
// repeated runs, snake_case identifiers) that the regex alone can't tell
// apart from a real token.
function shannonEntropy(str) {
  if (!str) return 0;
  const counts = new Map();
  for (const ch of str) counts.set(ch, (counts.get(ch) || 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / str.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function passesEntropy(rule, value) {
  if (!rule.entropy) return true;
  const threshold = /^[0-9a-fA-F]+$/.test(value) ? rule.entropy.minHex : rule.entropy.min;
  return shannonEntropy(value) >= threshold;
}

// Redacted preview for human review — first 4 / last 2 chars only, rest
// masked. Never returns enough to reconstruct the original secret, but
// gives a reviewer enough shape ("sk-ant-***********…**yz") to sanity-check
// a finding without the report itself becoming a new copy of the leak.
function redact(value) {
  const s = String(value || "");
  if (s.length <= 8) return "*".repeat(s.length);
  return `${s.slice(0, 4)}${"*".repeat(Math.min(s.length - 6, 20))}${s.slice(-2)}`;
}

// Rule regexes are stored without the `g` flag. Scanning for *every* match on
// a line needs a global clone (with `d` for exact group offsets where the
// runtime supports it), cached per rule.
const globalRegexCache = new WeakMap();
function globalRegexFor(rule) {
  let re = globalRegexCache.get(rule);
  if (!re) {
    const flags = rule.regex.flags.replace(/[gyd]/g, "");
    try { re = new RegExp(rule.regex.source, `${flags}gd`); }
    catch { re = new RegExp(rule.regex.source, `${flags}g`); }
    globalRegexCache.set(rule, re);
  }
  re.lastIndex = 0;
  return re;
}

// Exact position of the `secret` group (or the whole match for the handful of
// rules that don't define one, e.g. gcp-service-account).
function secretSpan(match) {
  const idx = match.indices?.groups?.secret;
  if (idx) return { start: idx[0], end: idx[1], text: match.groups.secret };
  const text = match.groups?.secret;
  if (text) {
    const off = match[0].indexOf(text);
    if (off !== -1) return { start: match.index + off, end: match.index + off + text.length, text };
  }
  return { start: match.index, end: match.index + match[0].length, text: match[0] };
}

// ─────────────────────────────────────────────────────────────────────────────
// Core engine
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Scan an array of lines. This is the one place rules are applied; the file
 * scanner, scanContent(), the git-history scanner and the pre-commit scanner
 * all go through it.
 *
 * - Every match of every rule is reported (not just the first per rule/line).
 * - Overlapping matches on one line collapse to one finding: specific rules
 *   beat generic ones, then rule order decides.
 * - PEM-style rules (MULTILINE_RULES) run over the whole text, so a key that
 *   spans many lines is found; its finding points at the BEGIN line and
 *   carries `end_line`.
 *
 * @param {string[]} lines
 * @param {string}   relPath          forward-slash path, relative to the scan root
 * @param {object}   [ctx]
 * @param {number}   [ctx.lineOffset=0]  added to line numbers (diff hunks)
 * @param {IgnoreConfig} [ctx.ignore]
 * @returns {object[]} findings, ordered by line then column
 */
export function scanText(lines, relPath, { lineOffset = 0, ignore = EMPTY_IGNORE } = {}) {
  const baseName = path.posix.basename(relPath);
  const candidates = [];

  // Lazily built whole-text view for multi-line rules.
  let text = null;
  let lineStarts = null;
  const ensureText = () => {
    if (text !== null) return;
    text = lines.join("\n");
    lineStarts = new Array(lines.length);
    let off = 0;
    for (let i = 0; i < lines.length; i++) { lineStarts[i] = off; off += lines[i].length + 1; }
  };
  const lineIndexAt = (offset) => {
    let lo = 0, hi = lineStarts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (lineStarts[mid] <= offset) lo = mid; else hi = mid - 1;
    }
    return lo;
  };

  for (let ruleIdx = 0; ruleIdx < builtinRules.length; ruleIdx++) {
    const rule = builtinRules[ruleIdx];
    if (ignore.rules.has(rule.id)) continue;
    // Path‑scoped rules (e.g. Maven settings.xml) only run against matching files.
    if (rule.path && !rule.path.test(relPath) && !rule.path.test(baseName)) continue;

    const generic = rule.generic === true; // undefined → false (specific)
    const caseInsensitive = rule.regex.flags.includes("i");
    const re = globalRegexFor(rule);

    // Checks shared by single-line and multi-line matches. Returns true if the
    // match should be dropped.
    const rejected = (m, valueForEntropy) => {
      // Rule‑scoped allow‑rules (e.g. jwt‑token's stateless‑ghs‑jwt) apply
      // to this specific rule's full match text only.
      if (rule.allowRules?.some(ar => ar.regex.test(m[0]))) return true;
      // Global content‑based allow‑rules (e.g. "example" placeholders)
      // apply to the matched text of any rule.
      if (isContentAllowed(m[0], ignore.unallow)) return true;
      // Entropy gate for rules that opt in (e.g. generic-fallback).
      if (rule.entropy && !passesEntropy(rule, valueForEntropy)) return true;
      return false;
    };

    // ── multi-line rules: one pass over the whole text ──
    const gate = MULTILINE_RULES.get(rule.id);
    if (gate) {
      ensureText();
      if (!gate.test(text)) continue;
      let n = 0, m;
      while (n < MAX_MATCHES_PER_RULE_PER_LINE && (m = re.exec(text)) !== null) {
        n++;
        const matchEnd = m.index + m[0].length;
        re.lastIndex = Math.max(m.index + 1, matchEnd);
        const span = secretSpan(m);
        if (span.text.length > MAX_SECRET_LENGTH) continue;
        if (rejected(m, m.groups?.value ?? m.groups?.secret ?? m[0])) continue;
        const lineIdx = lineIndexAt(m.index);
        const endLineIdx = lineIndexAt(Math.max(m.index, matchEnd - 1));
        const lineStart = lineStarts[lineIdx];
        candidates.push({
          rule, ruleIdx, generic, lineIdx, endLineIdx,
          cs: m.index - lineStart,
          ce: Math.min(matchEnd, lineStart + lines[lineIdx].length) - lineStart,
          secret: span.text,
        });
      }
      continue;
    }

    // ── single-line rules: every match on every line ──
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!line) continue;
      const lowerLine = caseInsensitive ? line.toLowerCase() : line;
      if (!keywordHit(line, lowerLine, rule.keywords, caseInsensitive)) continue;

      re.lastIndex = 0;
      let n = 0, m;
      while (n < MAX_MATCHES_PER_RULE_PER_LINE && (m = re.exec(line)) !== null) {
        n++;
        const span = secretSpan(m);
        // Resume at the end of the secret, not the end of the match: most
        // patterns consume a trailing delimiter that the *next* secret on the
        // line needs as its leading one ("KEY1,KEY2").
        re.lastIndex = Math.max(m.index + 1, span.end);
        if (span.text.length > MAX_SECRET_LENGTH) continue;
        if (rejected(m, m.groups?.value ?? m.groups?.secret ?? m[0])) continue;
        candidates.push({
          rule, ruleIdx, generic, lineIdx: i, endLineIdx: i,
          cs: span.start, ce: span.end, secret: span.text,
        });
      }
    }
  }

  // ── Resolve overlaps: specific beats generic, then rule order. ──
  candidates.sort((a, b) =>
    (a.generic - b.generic) || (a.ruleIdx - b.ruleIdx) || (a.lineIdx - b.lineIdx) || (a.cs - b.cs));
  const accepted = [];
  const byLine = new Map();
  for (const c of candidates) {
    const taken = byLine.get(c.lineIdx) ?? [];
    if (taken.some(o => c.cs < o.ce && o.cs < c.ce)) continue;
    taken.push(c);
    byLine.set(c.lineIdx, taken);
    accepted.push(c);
  }
  accepted.sort((a, b) => (a.lineIdx - b.lineIdx) || (a.cs - b.cs));

  // ── Apply suppressions, build findings. ──
  const findings = [];
  for (const c of accepted) {
    const { rule } = c;
    const fp = fingerprint(rule.id, relPath, c.secret);
    if (
      ignore.isRuleIgnoredForPath(rule.id, relPath) ||
      ignore.fingerprints.has(fp) ||
      isInlineIgnored(lines, c.lineIdx, rule.id)
    ) {
      ignore.suppressed++;
      continue;
    }
    const finding = {
      id: rule.id,
      title: rule.title,
      category: rule.category,
      severity: rule.severity,
      secret_type: rule.title,
      file_path: relPath,
      line: lineOffset + c.lineIdx + 1,
      column_start: c.cs + 1,   // SARIF columns are 1-based
      column_end: c.ce + 1,     // exclusive, per SARIF convention
      // Redacted preview only — never the raw secret. Enough for a
      // reviewer to sanity-check the finding without re-exposing the
      // credential in a report artifact (SARIF upload, HTML report, etc.).
      match_preview: redact(c.secret),
      fingerprint: fp,
    };
    if (c.endLineIdx !== c.lineIdx) finding.end_line = lineOffset + c.endLineIdx + 1;
    findings.push(finding);
  }
  return findings;
}

// ─── File scanning ───────────────────────────────────────────────────────

function scanFile(filePath, projectRoot, findings, ignore) {
  let stat;
  try {
    stat = fs.statSync(filePath);
  } catch {
    return;
  }
  if (stat.size === 0 || stat.size > MAX_FILE_SIZE) return;

  const relPath = path.relative(projectRoot, filePath).split(path.sep).join("/");

  let buffer;
  try {
    buffer = fs.readFileSync(filePath);
  } catch {
    return;
  }
  if (isLikelyBinary(buffer)) return;

  const lines = buffer.toString("utf8").split(/\r\n|\r|\n/);
  findings.push(...scanText(lines, relPath, { ignore }));
}

// ─── Exportable function: scan arbitrary data ────────────────────────────

/**
 * Scan provided data (string or Buffer) for secrets, using the same built‑in rules.
 * Path‑based allow‑list checks are NOT applied here; only content‑based allow‑rules
 * and rule‑specific allow‑rules are respected.
 *
 * @param {string|Buffer} data           - The content to scan.
 * @param {object} [options]
 * @param {string} [options.filePath]   - Optional file path (used for relative path in findings).
 * @param {string} [options.projectRoot]- Optional project root (defaults to dirname of filePath or cwd).
 * @param {IgnoreConfig} [options.ignore] - Optional ignore config (see loadIgnoreConfig).
 * @returns {object[]}                  - Array of finding objects.
 */
export function scanContent(data, options = {}) {
  const { filePath, projectRoot, ignore } = options;

  // Convert Buffer to string if needed.
  const content = typeof data === "string" ? data : data.toString("utf8");
  const lines = content.split(/\r\n|\r|\n/);

  // Determine a sensible project root.
  let root = projectRoot;
  if (!root) {
    root = filePath ? path.dirname(filePath) : process.cwd();
  }
  // If no filePath is given, use a dummy path inside the project root.
  const fpath = filePath || path.join(root, "data.txt");
  const relPath = path.relative(root, fpath).split(path.sep).join("/");

  return scanText(lines, relPath, { ignore: ignore ?? EMPTY_IGNORE });
}

// ─── Main project scanner ────────────────────────────────────────────────

/**
 * scanSecrets() — walk projectRoot's source tree and return exposed secrets.
 *
 * Never writes anything to disk — purely in-memory. Callers that want a
 * persisted report (JSON/HTML/SBOM/SARIF) are responsible for saving the
 * returned findings themselves.
 *
 * @param {string} projectRoot  Absolute (or relative) path to scan.
 * @param {object} [options]
 * @param {boolean} [options.includeEnvFiles=false]  Also scan `.env*` files. Off for
 *   repository scans; engine.js turns it on for container-image scans.
 * @param {string}   [options.ignoreFile]     Path to an ignore file (default `<root>/.ubelignore`).
 * @param {boolean}  [options.useIgnoreFile=true]
 * @param {string[]} [options.ignorePatterns] Extra .ubelignore-syntax lines.
 * @param {string[]} [options.ignoreDirs]     Extra directory names to skip.
 * @param {string[]} [options.includeDirs]    Default-skipped directory names to scan anyway
 *   (e.g. ["dist", "build"]).
 * @param {string[]} [options.unallow]        Builtin allow-rule ids to switch off
 *   (e.g. ["tests", "examples"] to scan test and example paths).
 * @param {boolean}  [options.includeHistory=false]  Also scan git history (see secrets_git.js).
 * @param {object}   [options.history]        Passed to scanGitHistory (rev, since, maxCommits).
 * @returns {Promise<{ findings: Array, count: number, projectRoot: string, suppressed: number, history?: object }>}
 */
export async function scanSecrets(projectRoot, options = {}) {
  const { includeEnvFiles = false, includeHistory = false, history = {} } = options;
  console.log(`Scanning for secrets in ${projectRoot || process.cwd()}...`);
  const resolvedRoot = path.resolve(projectRoot || process.cwd());
  const ignore = loadIgnoreConfig(resolvedRoot, options);

  const files = [];
  walk(resolvedRoot, files, { root: resolvedRoot, includeEnvFiles, ignore });

  const findings = [];
  for (const filePath of files) {
    scanFile(filePath, resolvedRoot, findings, ignore);
  }

  let historyInfo;
  if (includeHistory) {
    const { scanGitHistory } = await import("./secrets_git.js");
    const h = await scanGitHistory(resolvedRoot, { ...history, ignore });

    // A secret still present in the working tree is already in `findings`;
    // annotate it with where it entered the history rather than listing it twice.
    const byFingerprint = new Map(findings.map(f => [f.fingerprint, f]));
    let historyOnly = 0;
    for (const hf of h.findings) {
      const live = byFingerprint.get(hf.fingerprint);
      if (live) {
        live.commit = hf.commit;
        live.commit_date = hf.commit_date;
        live.author = hf.author;
        live.in_history = true;
      } else {
        findings.push({ ...hf, history_only: true });
        historyOnly++;
      }
    }
    historyInfo = {
      commits_scanned: h.commitsScanned,
      shallow: h.shallow,
      warnings: h.warnings,
      history_only_findings: historyOnly,
    };
  }

  const result = {
    findings,
    count: findings.length,
    projectRoot: resolvedRoot,
    suppressed: ignore.suppressed,
  };
  if (historyInfo) result.history = historyInfo;
  return result;
}

export default scanSecrets;