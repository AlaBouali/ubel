// poetry_runner.js
//
// Poetry firewall for `ubel-poetry` — same dry-run → scan → gated-install shape as
// the other Python-family firewalls (pypi_runner.js, conda_runner.js), implemented
// as a subclass so the pip/uv/pipx/conda code paths are untouched. Poetry owns a
// project manifest (pyproject.toml) and a lockfile (poetry.lock), so the flow is the
// one the cargo firewall uses rather than the venv-based one pip/uv use:
//
//   runDryRun(args, projectRoot)   → resolves in a SCRATCH COPY of the project:
//                                      args given  → `poetry add --lock <args>`
//                                      no args     → the project's own poetry.lock
//                                                    (`poetry lock` only when none exists)
//                                    then reads the resulting poetry.lock — the exact
//                                    set Poetry would install — as the inventory.
//   runRealInstall(projectRoot)    → writes the scanned pyproject.toml + poetry.lock into
//                                    the project and runs `poetry install --no-root`
//                                    against them; restores the originals on failure.
//   cleanup()                      → removes the scratch directory.
//   initPoetryProject(projectRoot) → `poetry init --no-interaction` when there is no
//                                    pyproject.toml (idempotent), for `ubel-poetry init`.
//   getInstalled(...)              → health mode: the inherited venv scan, plus the
//                                    project's Poetry environment (which usually lives
//                                    outside the project, in Poetry's cache dir).
//
// Why a scratch copy: `check` leaves the project untouched (no lockfile to back up and
// revert), and the real install can only ever use the pyproject.toml + poetry.lock pair
// that was scanned — both are SHA-256 pinned between the scan and the install.
//
// Why the lockfile is the inventory: poetry.lock already contains the full transitive
// closure with exact versions AND the dependency edges (`[package.dependencies]`) and the
// dependency groups, so — unlike uv's flat dry-run output — the report gets a real
// dependency graph, introduced-by paths and prod/dev scopes.
//
// Safety properties of the real install:
//   * `poetry install` (never `update`) installs exactly what poetry.lock pins, and
//     refuses to run if pyproject.toml has drifted from the lock's content-hash.
//   * `--no-root`: the project's own package is not built/installed, so its build backend
//     (arbitrary code) is not executed by the firewall.
//   * Source distributions are refused through Poetry's `installer.only-binary = :all:`
//     setting (set via POETRY_INSTALLER_ONLY_BINARY for that one process). Support for
//     that setting is VERIFIED against the installed Poetry before anything is installed;
//     if it isn't honoured the install is aborted (fails closed) rather than silently
//     allowing sdist builds. Same trade-off as `--only-binary=:all:` in pip/uv: an
//     sdist-only package can't be installed through this tool.
//
// Known limitation: while LOCKING, Poetry can still build a source distribution to read its
// metadata when the index doesn't publish it (rare for PyPI). That step is Poetry's own and
// cannot be turned off from outside; it only happens for packages with no wheel metadata.
//
// Vulnerability matching: registry packages (PyPI or any Poetry `legacy` index, treated
// like a custom --index-url is for pip) are reported as pkg:pypi/... and matched against
// OSV. Packages locked from git / a URL / a local file or directory are NOT the registry
// package of the same name, so they carry the purl qualifier engine.js recognises
// (UNVERIFIED_SOURCE_RE) and stay "undetermined" instead of being reported "safe".
//
// Zero third-party runtime dependencies (Node stdlib only) — hence the small TOML reader
// below instead of a TOML package.

import fs     from "fs";
import os     from "os";
import path   from "path";
import crypto from "crypto";
import { spawnSync } from "child_process";

import { PypiManagerInstance } from "./pypi_runner.js";
import { PythonVenvScanner }   from "./python_runner.js";

const SUBPROCESS_TIMEOUT = 300_000; // ms — resolution can be slow

// ═════════════════════════════════════════════════════════════════════════════
// Minimal TOML reader
// ═════════════════════════════════════════════════════════════════════════════
//
// Covers what pyproject.toml and poetry.lock use: comments, bare/quoted/dotted keys,
// [tables], [[arrays of tables]], basic / literal / multi-line strings, integers, floats,
// booleans, dates (kept as strings), arrays (multi-line, trailing commas, comments inside)
// and inline tables. Tables are null-prototype objects, so a key such as `__proto__` in an
// untrusted pyproject.toml is plain data and can never reach Object.prototype.

function tomlError(src, pos, msg) {
  const line = src.slice(0, pos).split("\n").length;
  return new Error(`TOML parse error at line ${line}: ${msg}`);
}

export function parseToml(text) {
  const src = String(text).replace(/\r\n?/g, "\n");
  let i = 0;

  const table = () => Object.create(null);
  const root  = table();

  const isBareKeyChar = (c) => /[A-Za-z0-9_-]/.test(c);

  const skipInlineWs = () => { while (i < src.length && (src[i] === " " || src[i] === "\t")) i++; };
  const skipComment  = () => { if (src[i] === "#") while (i < src.length && src[i] !== "\n") i++; };
  // whitespace + newlines + comments (inside arrays / between lines)
  const skipAll = () => {
    for (;;) {
      while (i < src.length && /\s/.test(src[i])) i++;
      if (src[i] === "#") skipComment(); else break;
    }
  };

  function parseBasicString() {            // at the opening quote
    const multi = src.startsWith('"""', i);
    i += multi ? 3 : 1;
    if (multi && src[i] === "\n") i++;
    let out = "";
    for (;;) {
      if (i >= src.length) throw tomlError(src, i, "unterminated string");
      const c = src[i];
      if (multi ? src.startsWith('"""', i) : c === '"') {
        if (multi) {                       // up to two extra quotes may precede the closer
          let extra = 0;
          while (src[i + 3 + extra] === '"' && extra < 2) extra++;
          out += '"'.repeat(extra);
          i += 3 + extra;
        } else i++;
        return out;
      }
      if (!multi && c === "\n") throw tomlError(src, i, "newline in single-line string");
      if (c === "\\") {
        const n = src[i + 1];
        const simple = { b: "\b", t: "\t", n: "\n", f: "\f", r: "\r", '"': '"', "\\": "\\" };
        if (n in simple) { out += simple[n]; i += 2; continue; }
        if (n === "u" || n === "U") {
          const len = n === "u" ? 4 : 8;
          const hex = src.slice(i + 2, i + 2 + len);
          if (!/^[0-9A-Fa-f]+$/.test(hex) || hex.length !== len) throw tomlError(src, i, "bad unicode escape");
          out += String.fromCodePoint(parseInt(hex, 16));
          i += 2 + len; continue;
        }
        if (multi && /[ \t\n]/.test(n)) {  // line-ending backslash: trim following whitespace
          i++;
          while (i < src.length && /\s/.test(src[i])) i++;
          continue;
        }
        throw tomlError(src, i, `bad escape \\${n}`);
      }
      out += c; i++;
    }
  }

  function parseLiteralString() {          // at the opening quote
    const multi = src.startsWith("'''", i);
    i += multi ? 3 : 1;
    if (multi && src[i] === "\n") i++;
    const end = src.indexOf(multi ? "'''" : "'", i);
    if (end === -1) throw tomlError(src, i, "unterminated literal string");
    const out = src.slice(i, end);
    if (!multi && out.includes("\n")) throw tomlError(src, i, "newline in literal string");
    i = end + (multi ? 3 : 1);
    return out;
  }

  function parseKey() {                    // dotted key → array of parts
    const parts = [];
    for (;;) {
      skipInlineWs();
      if (src[i] === '"')      parts.push(parseBasicString());
      else if (src[i] === "'") parts.push(parseLiteralString());
      else {
        const s = i;
        while (i < src.length && isBareKeyChar(src[i])) i++;
        if (i === s) throw tomlError(src, i, "expected a key");
        parts.push(src.slice(s, i));
      }
      skipInlineWs();
      if (src[i] === ".") { i++; continue; }
      return parts;
    }
  }

  function parseValue() {
    skipInlineWs();
    const c = src[i];
    if (c === '"') return parseBasicString();
    if (c === "'") return parseLiteralString();
    if (c === "[") return parseArray();
    if (c === "{") return parseInlineTable();
    const s = i;
    while (i < src.length && !/[\s,\]}#]/.test(src[i])) i++;
    const tok = src.slice(s, i).trim();
    if (!tok) throw tomlError(src, s, "missing value");
    if (tok === "true")  return true;
    if (tok === "false") return false;
    if (/^[+-]?(inf|nan)$/.test(tok)) return Number(tok.replace("inf", "Infinity").replace("nan", "NaN"));
    if (/^[+-]?(0|[1-9][0-9_]*)$/.test(tok))                     return parseInt(tok.replace(/_/g, ""), 10);
    if (/^0x[0-9A-Fa-f_]+$/.test(tok))                           return parseInt(tok.slice(2).replace(/_/g, ""), 16);
    if (/^[+-]?[0-9][0-9_]*(\.[0-9_]+)?([eE][+-]?[0-9_]+)?$/.test(tok)) return parseFloat(tok.replace(/_/g, ""));
    return tok;                            // dates/times: kept verbatim
  }

  function parseArray() {
    i++;                                   // [
    const arr = [];
    for (;;) {
      skipAll();
      if (src[i] === "]") { i++; return arr; }
      arr.push(parseValue());
      skipAll();
      if (src[i] === ",") { i++; continue; }
      if (src[i] === "]") { i++; return arr; }
      throw tomlError(src, i, "expected ',' or ']' in array");
    }
  }

  function parseInlineTable() {
    i++;                                   // {
    const t = table();
    skipInlineWs();
    if (src[i] === "}") { i++; return t; }
    for (;;) {
      const keys = parseKey();
      skipInlineWs();
      if (src[i] !== "=") throw tomlError(src, i, "expected '='");
      i++;
      setPath(t, keys, parseValue());
      skipInlineWs();
      if (src[i] === ",") { i++; skipInlineWs(); continue; }
      if (src[i] === "}") { i++; return t; }
      throw tomlError(src, i, "expected ',' or '}' in inline table");
    }
  }

  function descend(base, keys) {           // walk/create tables; arrays resolve to their last element
    let t = base;
    for (const k of keys) {
      let next = t[k];
      if (next === undefined) { next = table(); t[k] = next; }
      if (Array.isArray(next)) next = next[next.length - 1];
      if (next === null || typeof next !== "object") throw new Error(`TOML: key '${k}' is not a table`);
      t = next;
    }
    return t;
  }

  function setPath(base, keys, value) {
    const parent = descend(base, keys.slice(0, -1));
    parent[keys[keys.length - 1]] = value;
  }

  let cur = root;
  for (;;) {
    skipAll();
    if (i >= src.length) break;

    if (src[i] === "[") {
      const isArr = src[i + 1] === "[";
      i += isArr ? 2 : 1;
      const keys = parseKey();
      skipInlineWs();
      if (src[i] !== "]") throw tomlError(src, i, "expected ']'");
      i++;
      if (isArr) {
        if (src[i] !== "]") throw tomlError(src, i, "expected ']]'");
        i++;
        const parent = descend(root, keys.slice(0, -1));
        const last   = keys[keys.length - 1];
        if (parent[last] === undefined) parent[last] = [];
        if (!Array.isArray(parent[last])) throw tomlError(src, i, `'${last}' is not an array of tables`);
        cur = table();
        parent[last].push(cur);
      } else {
        cur = descend(root, keys);
      }
    } else {
      const keys = parseKey();
      skipInlineWs();
      if (src[i] !== "=") throw tomlError(src, i, "expected '='");
      i++;
      setPath(cur, keys, parseValue());
    }

    skipInlineWs();
    skipComment();
    if (i < src.length && src[i] !== "\n") throw tomlError(src, i, "unexpected characters after value");
  }
  return root;
}

// ═════════════════════════════════════════════════════════════════════════════
// Helpers
// ═════════════════════════════════════════════════════════════════════════════

const sha256 = (buf) => crypto.createHash("sha256").update(buf).digest("hex");

/** PEP 503 normalisation. */
const normName = (n) => String(n).toLowerCase().replace(/[-_.]+/g, "-");

/** Poetry `source.type` values that are NOT the registry package of the same name. */
const UNVERIFIED_SOURCE_TYPES = new Set(["git", "url", "file", "directory"]);

function sourceQualifier(source) {
  const type = String(source?.type || "").toLowerCase();
  if (!UNVERIFIED_SOURCE_TYPES.has(type)) return "";
  const ref = source.resolved_reference || source.reference || "";
  const loc = String(source.url || "") + (type === "git" && ref ? `@${ref}` : "");
  if (type === "git") return `?vcs_url=${encodeURIComponent(loc)}`;
  if (type === "url") return `?download_url=${encodeURIComponent(loc)}`;
  return `?file=${encodeURIComponent(loc)}`;      // file | directory
}

/** Files Poetry reads next to pyproject.toml that a scratch resolution needs. */
function declaredReadmes(pyprojectText) {
  const out = [];
  try {
    const doc = parseToml(pyprojectText);
    const cands = [doc.project?.readme, doc.tool?.poetry?.readme];
    for (const r of cands) {
      for (const v of (Array.isArray(r) ? r : [r])) {
        const p = typeof v === "string" ? v : v?.file;
        if (typeof p === "string") out.push(p);
      }
    }
  } catch { /* an unparsable pyproject.toml is reported by Poetry itself */ }
  return out;
}

export class PoetryManagerInstance extends PypiManagerInstance {

  constructor() {
    super("pip");                    // base class only accepts pip|uv; overridden next line
    this.installer       = "poetry";
    this._poetryBinPath  = null;     // cached by _resolvePoetryBin()
    this._scratchDir     = null;     // scratch project the dry-run resolved in
    this._scanned        = null;     // { pyproject, lock, origPyprojectSha } as scanned
  }

  // ── poetry binary resolution ────────────────────────────────────────────────
  //
  // Same problem as uv/conda: the installer scripts add Poetry to PATH from an rc
  // file spawnSync never sources, so fall back through the documented install locations.

  _probePoetryVersion(bin) {
    try {
      const r = spawnSync(bin, ["--version"], { encoding: "utf8", timeout: 30_000 });
      if (r.status !== 0) return null;
      // "Poetry (version 1.8.3)"  /  "Poetry (version 2.1.1)"
      const m = /Poetry[^\d]*(\d+\.\d+[^\s)]*)/i.exec(`${r.stdout || ""}\n${r.stderr || ""}`);
      return m ? m[1] : null;
    } catch {
      return null;
    }
  }

  _resolvePoetryBin() {
    if (this._poetryBinPath) return this._poetryBinPath;

    const home = os.homedir();
    const candidates = ["poetry"];       // bare command, resolved via PATH
    if (process.platform === "win32") {
      const appdata = process.env.APPDATA || path.join(home, "AppData", "Roaming");
      candidates.push(
        path.join(appdata, "Python", "Scripts", "poetry.exe"),
        path.join(appdata, "pypoetry", "venv", "Scripts", "poetry.exe"),
        path.join(home, ".local", "bin", "poetry.exe"),
      );
    } else {
      candidates.push(
        path.join(home, ".local", "bin", "poetry"),                                   // official installer / pipx
        path.join(home, ".poetry", "bin", "poetry"),                                  // legacy installer
        path.join(home, "Library", "Application Support", "pypoetry", "venv", "bin", "poetry"), // macOS installer
        "/opt/homebrew/bin/poetry",
        "/usr/local/bin/poetry",
        "/usr/bin/poetry",
      );
    }

    for (const candidate of candidates) {
      if (candidate !== "poetry" && !fs.existsSync(candidate)) continue;
      if (this._probePoetryVersion(candidate)) {
        this._poetryBinPath = candidate;
        return candidate;
      }
    }
    return null;
  }

  assertPoetryAvailable() {
    if (!this._resolvePoetryBin()) {
      throw new Error(
        `'poetry' was not found on PATH or in any known install location ` +
        `(~/.local/bin, ~/.poetry/bin, Homebrew, ...) — ubel-poetry requires Poetry to be ` +
        `installed, the same way ubel-pnpm requires pnpm. If you just installed it, open a ` +
        `new terminal (or 'source' your shell rc file) so PATH picks it up.`
      );
    }
  }

  getPoetryVersion() {
    const bin = this._resolvePoetryBin();
    return bin ? this._probePoetryVersion(bin) : null;
  }

  // ── environment for every Poetry subprocess ────────────────────────────────

  _env(extra = {}) {
    return { ...process.env, POETRY_NO_INTERACTION: "1", ...extra };
  }

  /**
   * Source distributions run arbitrary build code. Poetry's `installer.only-binary`
   * setting refuses them, but only Poetry releases that know the setting honour it — and an
   * unknown POETRY_* variable is silently ignored — so ask Poetry what it will actually use.
   */
  _assertOnlyBinaryHonoured(poetryBin, cwd) {
    const r = spawnSync(poetryBin, ["config", "installer.only-binary"], {
      cwd, encoding: "utf8", timeout: 30_000,
      env: this._env({ POETRY_INSTALLER_ONLY_BINARY: ":all:" }),
    });
    if (r.status !== 0 || !String(r.stdout || "").includes(":all:")) {
      throw new Error(
        `The installed Poetry does not support the 'installer.only-binary' setting, so UBEL cannot ` +
        `guarantee that no source distribution (arbitrary build code) is built during the install. ` +
        `Upgrade Poetry and retry — nothing was installed.`
      );
    }
  }

  // ── init ─────────────────────────────────────────────────────────────────────

  /**
   * Create a minimal pyproject.toml with `poetry init --no-interaction` if the project
   * has none. Idempotent. Returns the absolute project path.
   */
  initPoetryProject(projectRoot) {
    this.assertPoetryAvailable();
    const root = path.resolve(projectRoot);
    if (fs.existsSync(path.join(root, "pyproject.toml"))) return root;

    fs.mkdirSync(root, { recursive: true });
    const r = spawnSync(this._resolvePoetryBin(), ["init", "--no-interaction"], {
      cwd: root, encoding: "utf8", env: this._env(),
    });
    if (r.status !== 0) {
      throw new Error(`'poetry init' failed in ${root} (exit ${r.status}):\n${r.stderr || r.stdout || ""}`);
    }
    return root;
  }

  // ── dry-run ─────────────────────────────────────────────────────────────────

  /**
   * Resolve `initialArgs` in a scratch copy of the project and return the PURL ids of
   * everything poetry.lock would pin; full records land in this.inventoryData.
   * The project itself is never modified.
   *
   *   args    → `poetry add --lock <args>`   (adds to the main group, locks, installs nothing)
   *   no args → the project's existing poetry.lock as-is; `poetry lock` only if there is none
   */
  runDryRun(initialArgs, projectRoot) {
    this.assertPoetryAvailable();
    const poetryBin = this._resolvePoetryBin();

    const poetryVersion = this.getPoetryVersion();
    if (poetryVersion === null) throw new Error("Failed to determine Poetry version (`poetry --version` did not succeed)");
    this.engineVersion = poetryVersion;

    const args = initialArgs.filter(a => a !== "--");
    // engine.js already rejects these; re-checked so this class is safe to call directly.
    // An option-shaped "package" could add a git/path/URL source to the resolution.
    const bad = args.find(a => a.startsWith("-") || /[\s/\\:;]/.test(a));
    if (bad) throw new Error(`Refusing unsafe package argument: ${bad}`);

    const root = path.resolve(projectRoot);
    const pyprojectPath = path.join(root, "pyproject.toml");
    if (!fs.existsSync(pyprojectPath)) {
      throw new Error(
        `No pyproject.toml in ${root} — ubel-poetry check/install works on a Poetry project. ` +
        `Run 'ubel-poetry init' (or 'poetry init') first.`
      );
    }

    this.cleanup();                                      // a previous dry-run's scratch dir, if any
    const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "ubel-poetry-dryrun-"));
    this._scratchDir = scratch;

    const origPyproject = fs.readFileSync(pyprojectPath);
    fs.writeFileSync(path.join(scratch, "pyproject.toml"), origPyproject);
    for (const f of ["poetry.lock", "poetry.toml"]) {   // poetry.toml: local config (sources, venv settings)
      const p = path.join(root, f);
      if (fs.existsSync(p)) fs.copyFileSync(p, path.join(scratch, f));
    }
    for (const rel of declaredReadmes(origPyproject.toString("utf8"))) {
      const abs = path.resolve(root, rel);
      if (abs.startsWith(root + path.sep) && fs.existsSync(abs) && fs.statSync(abs).isFile()) {
        fs.mkdirSync(path.dirname(path.join(scratch, path.relative(root, abs))), { recursive: true });
        fs.copyFileSync(abs, path.join(scratch, path.relative(root, abs)));
      }
    }

    const hasLock = fs.existsSync(path.join(scratch, "poetry.lock"));
    let cmd = null;
    if (args.length)    cmd = ["add", "--lock", "--no-interaction", ...args];
    else if (!hasLock)  cmd = ["lock", "--no-interaction"];

    if (cmd) {
      const r = spawnSync(poetryBin, cmd, {
        cwd: scratch, encoding: "utf8", timeout: SUBPROCESS_TIMEOUT, maxBuffer: 64 * 1024 * 1024,
        // Resolution only: never create or touch a virtualenv. Also ask Poetry to refuse
        // sdists where the release honours it (harmless where it doesn't — see the header).
        env: this._env({ POETRY_VIRTUALENVS_CREATE: "false", POETRY_INSTALLER_ONLY_BINARY: ":all:" }),
      });
      if (r.error || r.status !== 0) {
        this.cleanup();
        throw new Error(
          `poetry dry-run failed:\n` +
          `CMD: ${poetryBin} ${cmd.join(" ")}\n` +
          `${(r.stderr || "").trim() || (r.stdout || "").trim() || r.error?.message || "(no output)"}\n` +
          (cmd[1] === "--lock" ? `(\`poetry add --lock\` needs a Poetry release that supports --lock; this is Poetry ${poetryVersion}.)` : "")
        );
      }
    }

    const lockPath = path.join(scratch, "poetry.lock");
    if (!fs.existsSync(lockPath)) {
      this.cleanup();
      throw new Error("poetry dry-run produced no poetry.lock — refusing to treat that as 'nothing to block'.");
    }

    const pyprojectOut = fs.readFileSync(path.join(scratch, "pyproject.toml"));
    const lockOut      = fs.readFileSync(lockPath);

    let components;
    try {
      components = this._componentsFromLock(lockOut.toString("utf8"));
    } catch (e) {
      this.cleanup();
      throw e;
    }
    if (!components.length) {
      // Fail closed: "resolved nothing" must never read as "nothing to block".
      this.cleanup();
      throw new Error("poetry.lock contains no packages — there is nothing to scan.");
    }

    components.push({
      id: `pkg:pypi/poetry@${poetryVersion}`,
      name: "poetry",
      version: poetryVersion,
      type: "tool",
      license: "MIT",
      dependencies: [],
      paths: [],
      ecosystem: "python",
      scopes: ["dev", "env", "prod"],
      state: "undetermined",
    });

    this._scanned = {
      pyproject: pyprojectOut, pyprojectSha: sha256(pyprojectOut),
      lock: lockOut,           lockSha: sha256(lockOut),
      origPyprojectSha: sha256(origPyproject),
    };

    this.inventoryData = this.buildDependencySequences(this.mergeInventoryByPurl(components));
    return this.inventoryData.map(c => c.id);
  }

  // ── poetry.lock → components ────────────────────────────────────────────────

  _componentsFromLock(lockText) {
    const doc = parseToml(lockText);
    const packages = Array.isArray(doc.package) ? doc.package : [];

    // name → purls (a lock may pin one name more than once, for different Python/platform markers)
    const purlsByName = new Map();
    const entries = [];
    for (const pkg of packages) {
      const name = typeof pkg?.name === "string" ? pkg.name : null;
      if (!name) continue;
      const version = pkg.version === undefined || pkg.version === null ? "" : String(pkg.version);
      const norm    = normName(name);
      const purl    = `pkg:pypi/${encodeURIComponent(norm)}@${version}${sourceQualifier(pkg.source)}`;
      entries.push({ pkg, name, norm, version, purl });
      if (!purlsByName.has(norm)) purlsByName.set(norm, []);
      purlsByName.get(norm).push(purl);
    }

    return entries.map(({ pkg, norm, version, purl }) => {
      const deps = [];
      for (const dep of Object.keys(pkg.dependencies || {})) {
        for (const p of (purlsByName.get(normName(dep)) || [])) if (p !== purl) deps.push(p);
      }
      // lock-version 2.x: `groups = [...]`; 1.x: `category = "main" | "dev"`.
      const groups = Array.isArray(pkg.groups) ? pkg.groups : [pkg.category || "main"];
      return {
        id: purl,
        name: norm,
        version,
        type: "library",
        license: "unknown",             // poetry.lock carries no license data
        dependencies: [...new Set(deps)],
        paths: [],
        ecosystem: "python",
        scopes: [groups.includes("main") ? "prod" : "dev"],
        state: "undetermined",
      };
    });
  }

  // ── real install ────────────────────────────────────────────────────────────

  /**
   * Install exactly what runDryRun() scanned. Writes the scanned pyproject.toml and
   * poetry.lock into the project, then `poetry install --no-root` (see the header for
   * why that command and those flags). The originals are restored if the install fails.
   */
  runRealInstall(projectRoot) {
    if (!this._scratchDir || !this._scanned) throw new Error("No scanned Poetry resolution — runDryRun() must run first.");
    this.assertPoetryAvailable();
    const poetryBin = this._resolvePoetryBin();
    const root = path.resolve(projectRoot);
    const s = this._scanned;

    // The scratch files must still be byte-for-byte what was scanned…
    const scratchPyproject = path.join(this._scratchDir, "pyproject.toml");
    const scratchLock      = path.join(this._scratchDir, "poetry.lock");
    if (sha256(fs.readFileSync(scratchPyproject)) !== s.pyprojectSha || sha256(fs.readFileSync(scratchLock)) !== s.lockSha) {
      throw new Error("The scanned pyproject.toml / poetry.lock changed between scan and install — install aborted.");
    }
    // …and the project's pyproject.toml must not have been edited meanwhile (we'd overwrite that edit).
    const pyprojectPath = path.join(root, "pyproject.toml");
    const lockPath      = path.join(root, "poetry.lock");
    const curPyproject  = fs.readFileSync(pyprojectPath);
    if (sha256(curPyproject) !== s.origPyprojectSha) {
      throw new Error("pyproject.toml was modified after the scan — install aborted so that edit is not overwritten. Re-run the scan.");
    }

    this._assertOnlyBinaryHonoured(poetryBin, root);

    const origLock = fs.existsSync(lockPath) ? fs.readFileSync(lockPath) : null;
    const restore = () => {
      try {
        fs.writeFileSync(pyprojectPath, curPyproject);
        if (origLock) fs.writeFileSync(lockPath, origLock); else fs.rmSync(lockPath, { force: true });
        console.error("[~] Original pyproject.toml / poetry.lock restored.");
      } catch (e) {
        console.error(`[!] Could not restore the original pyproject.toml / poetry.lock: ${e.message}`);
      }
    };

    fs.writeFileSync(pyprojectPath, s.pyproject);
    fs.writeFileSync(lockPath, s.lock);

    const cmd = ["install", "--no-root", "--no-interaction"];
    const r = spawnSync(poetryBin, cmd, {
      cwd: root, stdio: "inherit",
      env: this._env({ POETRY_INSTALLER_ONLY_BINARY: ":all:" }),
    });
    if (r.error || r.status !== 0) {
      console.error(`[!] Package install failed (exit ${r.status}): ${poetryBin} ${cmd.join(" ")}`);
      restore();
      throw new Error(`poetry install failed (exit ${r.status})`);
    }
    return r;
  }

  /** Removes the scratch directory (safe to call repeatedly). */
  cleanup() {
    if (this._scratchDir) {
      try { fs.rmSync(this._scratchDir, { recursive: true, force: true }); } catch { /* ignore */ }
      this._scratchDir = null;
    }
  }

  // ── health mode ─────────────────────────────────────────────────────────────

  /**
   * The inherited scan finds a project-local .venv. Poetry keeps its environments in its own
   * cache directory unless `virtualenvs.in-project` is set, so also ask Poetry for the
   * project's environment and scan that.
   */
  getInstalled(startDir, opts = {}) {
    const ids = super.getInstalled(startDir, opts);
    if (opts.scanVenv === false) return ids;

    try {
      if (!this._resolvePoetryBin() || !fs.existsSync(path.join(path.resolve(startDir), "pyproject.toml"))) return ids;
      const r = spawnSync(this._resolvePoetryBin(), ["env", "info", "--path"], {
        cwd: path.resolve(startDir), encoding: "utf8", timeout: 30_000, env: this._env(),
      });
      const envPath = r.status === 0 ? String(r.stdout || "").trim().split("\n").pop().trim() : "";
      if (!envPath || !fs.existsSync(envPath)) return ids;
      if (path.resolve(envPath).startsWith(path.resolve(startDir) + path.sep)) return ids; // already covered

      const scanner = new PythonVenvScanner();
      scanner.getInstalled(path.resolve(envPath));
      const merged = this.mergeInventoryByPurl([...this.inventoryData, ...scanner.inventoryData]);
      this.inventoryData = merged;
      return merged.map(c => c.id);
    } catch {
      return ids;                       // a failing Poetry probe must never break health mode
    }
  }
}

export default PoetryManagerInstance;