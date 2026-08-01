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
 */

import fs from "node:fs";
import path from "node:path";
import { builtinRules } from "./vendor/trivy/rules.js";
import { builtinAllowRules } from "./vendor/trivy/allow-rules.js";

// ── Directories never walked into: VCS metadata, dependency trees, build
//    output, caches. This is what makes the scan "codebase, not deps".
const IGNORED_DIRS = new Set([
  // VCS / tool metadata
  ".git", ".svn", ".hg", ".ubel",
  // JS/Node
  "node_modules", "bower_components",
  // C# / .NET (NuGet restore + build output)
  "obj", "bin", "packages", ".nuget",
  // Go (vendored deps)
  "vendor",
  // Java / Maven / Gradle (local repo + build output)
  "target", ".m2", ".gradle",
  // Python (virtualenvs, installed packages, bytecode caches)
  ".venv", "venv", "env", "site-packages", "__pycache__", ".mypy_cache", ".pytest_cache",
  // Ruby / Bundler
  ".bundle",
  // Rust / Cargo — target already covered above; global registry cache
  ".cargo",
  // generic build output / editor / caches
  "dist", "build", "out",
  ".next", ".nuxt", ".cache",
  ".idea", ".vscode",
  "coverage",".secrets-dig", ".snyk", ".trivy", ".cache", ".gradle", ".pytest_cache",
  ".sass-cache", ".parcel-cache", ".yarn", ".pnpm-store", ".pnpm",
  ".ubel"
]);

// ── File extensions treated as scannable source/config/text. Anything not
//    in this set (images, archives, binaries, etc.) is skipped outright.
const TEXT_EXTENSIONS = new Set([
  ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
  ".json", ".yml", ".yaml",
  ".ini", ".conf", ".config", ".cfg",
  ".py", ".rb", ".go", ".java", ".php", ".c", ".h", ".cpp", ".hpp",
  ".cs", ".rs", ".kt", ".swift",
  ".sh", ".bash", ".zsh", ".ps1",
  ".xml", ".html", ".htm", ".css", ".scss",
  ".sql", ".md", ".txt", ".toml", ".properties", ".gradle",
  ".tf", ".tfvars",
  ".pem", ".key",
]);

// ── Extension-less / dotfile names that are still worth scanning.
const NAMED_FILE_ALLOW = new Set([
  "Dockerfile", "Makefile", ".npmrc", ".netrc", ".htpasswd", ".pgpass",
  "settings.xml", "settings-security.xml", // path-scoped Maven rules target these
]);

const MAX_FILE_SIZE = 2 * 1024 * 1024; // 2MB — skip anything larger

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
    regex: new RegExp(String.raw`(?<secret>\b(?:sk-|pk_|xox[baprs]|api_|key_|token_)[0-9A-Za-z_\-+/]{32,})`, ""),
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
  },*/
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
  },
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
    keywords: ["sqOatp-", "EAAA"],
    path: null,
    regex: new RegExp(String.raw`(?<secret>(?:sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}))`, ""),
    allowRules: [],
  },
  {
    id: "stripe-restricted-key",
    category: "Stripe",
    severity: "CRITICAL",
    title: "Stripe Restricted API Key",
    keywords: ["rk_live_"],
    path: null,
    regex: new RegExp(String.raw`(?:^|[^0-9A-Za-z_])(?<secret>rk_(live|test)_[0-9a-zA-Z]{24})(?:[^0-9A-Za-z_]|$)`, "i"),
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
];

builtinRules.push(...extraRules);

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

function shouldScanFile(fullPath) {
  const base = path.basename(fullPath);
  // ── Skip .env* files (they are not meant to be committed) ──
  if (base.startsWith(".env")) return false;
  // Allow specific well-known files
  if (NAMED_FILE_ALLOW.has(base)) return true;
  // Check extension
  return TEXT_EXTENSIONS.has(path.extname(fullPath).toLowerCase());
}

function isLikelyBinary(buffer) {
  const len = Math.min(buffer.length, 8000);
  for (let i = 0; i < len; i++) {
    if (buffer[i] === 0) return true;
  }
  return false;
}

function walk(dir, files) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return; // unreadable directory — skip silently
  }

  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue;

    const fullPath = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      if (IGNORED_DIRS.has(entry.name)) continue;
      walk(fullPath, files);
      continue;
    }

    if (!entry.isFile()) continue;
    if (!shouldScanFile(fullPath)) continue;
    files.push(fullPath);
  }
}

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

function isPathAllowed(relPath) {
  for (const rule of builtinAllowRules) {
    if (rule.path && rule.path.test(relPath)) return rule;
  }
  return null;
}

function isContentAllowed(matchedText) {
  for (const rule of builtinAllowRules) {
    if (rule.content && rule.content.test(matchedText)) return rule;
  }
  return null;
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

function scanLines(lines, filePath, projectRoot) {
  const relPath = path.relative(projectRoot, filePath).split(path.sep).join("/");
  const baseName = path.basename(filePath);

  // Per‑line best finding: specific beats generic.
  const lineFindings = new Map(); // lineNum -> { finding: object, isGeneric: boolean }

  for (const rule of builtinRules) {
    // Path‑scoped rules (e.g. Maven settings.xml) only run against matching files.
    if (rule.path && !rule.path.test(relPath) && !rule.path.test(baseName)) continue;

    const caseInsensitive = rule.regex.flags.includes("i");
    const isGeneric = rule.generic === true; // undefined → false (specific)

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!line) continue;
      const lowerLine = caseInsensitive ? line.toLowerCase() : line;
      if (!keywordHit(line, lowerLine, rule.keywords, caseInsensitive)) continue;

      const match = rule.regex.exec(line);
      if (!match) continue;

      // Rule‑scoped allow‑rules (e.g. jwt‑token's stateless‑ghs‑jwt) apply
      // to this specific rule's full match text only.
      if (rule.allowRules?.some(ar => ar.regex.test(match[0]))) continue;

      // Global content‑based allow‑rules (e.g. "example" placeholders)
      // apply to the matched text of any rule.
      if (isContentAllowed(match[0])) continue;

      const lineNum = i + 1;
      const existing = lineFindings.get(lineNum);

      // Prefer the narrower named `secret` capture group for the exact
      // column span (most rules define one); fall back to the full match
      // for the handful of rules that don't (e.g. gcp-service-account,
      // symfony-default-secret — literal-string matches with no group).
      const secretText = match.groups?.secret;
      let startIdx = match.index;
      let spanLen  = match[0].length;
      if (secretText) {
        const offsetInMatch = match[0].indexOf(secretText);
        if (offsetInMatch !== -1) {
          startIdx = match.index + offsetInMatch;
          spanLen  = secretText.length;
        }
      }
      const column_start = startIdx + 1;       // SARIF columns are 1-based
      const column_end   = startIdx + spanLen + 1; // exclusive, per SARIF convention
      // Redacted preview only — never the raw secret. Enough for a
      // reviewer to sanity-check the finding without re-exposing the
      // credential in a report artifact (SARIF upload, HTML report, etc.).
      const previewSource = secretText || match[0];
      const match_preview = redact(previewSource);

      if (!existing) {
        lineFindings.set(lineNum, {
          finding: {
            id: rule.id,
            title: rule.title,
            category: rule.category,
            severity: rule.severity,
            secret_type: rule.title,
            file_path: relPath,
            line: lineNum,
            column_start,
            column_end,
            match_preview,
          },
          isGeneric,
        });
        continue;
      }

      // If existing is generic and the new rule is specific, upgrade.
      if (existing.isGeneric && !isGeneric) {
        lineFindings.set(lineNum, {
          finding: {
            id: rule.id,
            title: rule.title,
            category: rule.category,
            severity: rule.severity,
            secret_type: rule.title,
            file_path: relPath,
            line: lineNum,
            column_start,
            column_end,
            match_preview,
          },
          isGeneric: false,
        });
      }
      // Otherwise keep the existing (first) finding (order in builtinRules).
    }
  }

  // Collect all winning findings.
  const findings = [];
  for (const [, { finding }] of lineFindings) {
    findings.push(finding);
  }
  return findings;
}

// ─── Original file‑scanning function (now uses scanLines) ──────────────

function scanFile(filePath, projectRoot, findings) {
  let stat;
  try {
    stat = fs.statSync(filePath);
  } catch {
    return;
  }
  if (stat.size === 0 || stat.size > MAX_FILE_SIZE) return;

  const relPath = path.relative(projectRoot, filePath).split(path.sep).join("/");
  // Global path‑based allow‑list (vendor dirs, test/example paths, etc.)
  if (isPathAllowed(relPath)) return;

  let buffer;
  try {
    buffer = fs.readFileSync(filePath);
  } catch {
    return;
  }
  if (isLikelyBinary(buffer)) return;

  const lines = buffer.toString("utf8").split(/\r\n|\r|\n/);
  const newFindings = scanLines(lines, filePath, projectRoot);
  findings.push(...newFindings);
}

// ─── New exportable function: scan arbitrary data ────────────────────────

/**
 * Scan provided data (string or Buffer) for secrets, using the same built‑in rules.
 * Path‑based allow‑list checks are NOT applied here; only content‑based allow‑rules
 * and rule‑specific allow‑rules are respected.
 *
 * @param {string|Buffer} data           - The content to scan.
 * @param {object} [options]
 * @param {string} [options.filePath]   - Optional file path (used for relative path in findings).
 * @param {string} [options.projectRoot]- Optional project root (defaults to dirname of filePath or cwd).
 * @returns {object[]}                  - Array of finding objects.
 */
export function scanContent(data, options = {}) {
  const { filePath, projectRoot } = options;

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

  return scanLines(lines, fpath, root);
}

// ─── Main project scanner (unchanged, but now uses scanLines internally) ───

/**
 * scanSecrets() — walk projectRoot's source tree and return exposed secrets.
 *
 * Never writes anything to disk — purely in-memory. Callers that want a
 * persisted report (JSON/HTML/SBOM/SARIF) are responsible for saving the
 * returned findings themselves.
 *
 * @param {string} projectRoot  Absolute (or relative) path to scan.
 * @returns {Promise<{ findings: Array, count: number, projectRoot: string }>}
 */
export async function scanSecrets(projectRoot) {
  const resolvedRoot = path.resolve(projectRoot || process.cwd());

  const files = [];
  walk(resolvedRoot, files);

  const findings = [];
  for (const filePath of files) {
    scanFile(filePath, resolvedRoot, findings);
  }

  return {
    findings,
    count: findings.length,
    projectRoot: resolvedRoot,
  };
}

export default scanSecrets;