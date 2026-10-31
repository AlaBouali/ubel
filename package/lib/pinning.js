'use strict';
// pinning.js — how firmly a declared dependency is fixed. One classifier per ecosystem's version syntax.
//
//   exact         one version (`1.2.3`, `==1.2.3`, `=1.2.3`, `[1.2.3]`); resolves to the same release every time
//   floor         a lower bound that the resolver installs when nothing else asks for more: NuGet `1.2.3` (= >=1.2.3, lowest applicable wins) and
//                 Go `require m v1.2.3` (minimal version selection). The version in the file is what a plain build gets.
//   range         bounded or compatible-release ranges (`^1.2`, `~1.2`, `~=1.2`, `1.2.*`, `>=1,<2`): a new release can change what is installed
//   open          no usable bound (`*`, `latest`, a dist-tag, `>=1`, empty, `any`): whatever is newest at install time
//   non_registry  git / URL / path / alias source: the registry's checks (advisories, malware takedowns, yanks) do not apply;
//                 `immutable` says whether the reference is fixed (a commit hash / a digest-checked URL) or can move (branch, tag, plain URL)
//
// `version` is set only for exact and floor: it is the version that can be looked up in OSV.dev.

const SEMVER = /^v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$/;
const HEX40 = /(?:^|[#@/=])[0-9a-f]{40}(?:$|[&?#])/i;

const out = (pin, extra = {}) => ({ pin, version: null, source: 'registry', immutable: null, detail: null, ...extra });

// ── npm ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
export function classifyNpm(spec) {
  const s = String(spec ?? '').trim();
  if (s.startsWith('npm:')) {                                                       // alias: `npm:real-name@1.2.3`
    const m = /^npm:(@?[^@]+)(?:@(.*))?$/.exec(s);
    const inner = classifyNpm(m?.[2] ?? '*');
    return { ...inner, detail: `alias of ${m?.[1] || '?'}${inner.detail ? `; ${inner.detail}` : ''}`, alias: m?.[1] || null };
  }
  if (/^(?:git\+|git:|git@|github:|gitlab:|bitbucket:|gist:|ssh:)/i.test(s) || /^[\w.-]+\/[\w.-]+(?:#.*)?$/.test(s) && !/^\d/.test(s)) {
    return out('non_registry', { source: 'git', immutable: HEX40.test(s), detail: HEX40.test(s) ? 'git commit' : 'git reference that can move (branch / tag / default branch)' });
  }
  if (/^https?:\/\//i.test(s)) return out('non_registry', { source: 'url', immutable: false, detail: 'tarball URL (no integrity check unless a lockfile records one)' });
  if (/^(?:file:|link:|portal:|\.{1,2}\/|\/|~\/)/.test(s)) return out('non_registry', { source: 'path', immutable: false, detail: 'local path' });
  if (/^workspace:/.test(s)) return out('non_registry', { source: 'workspace', immutable: false, detail: 'monorepo workspace link' });
  const exact = SEMVER.exec(s.replace(/^=\s*/, ''));
  if (exact) return out('exact', { version: exact[1] });
  if (s === '' || s === '*' || s === 'x' || s === 'X' || /^(?:latest|next|beta|alpha|canary|rc|nightly|dev|stable|[a-z][\w-]*)$/i.test(s)) return out('open', { detail: s === '' || s === '*' ? 'any version' : `dist-tag "${s}"` });
  if (/^>=?\s*[\d.x]+\s*$/.test(s) || /^>/.test(s) && !/[<]/.test(s) && !/\|\|/.test(s)) return out('open', { detail: 'no upper bound' });
  return out('range', { detail: s });
}

// ── PyPI (PEP 508 requirement strings) ───────────────────────────────────────────────────────────────────────────────────────────
/** Parses `name[extra1,extra2] (>=1,<2) ; marker` or `name @ https://…`. */
export function parsePep508(line) {
  const t = String(line).replace(/\s+#.*$/, '').trim();
  if (!t || t.startsWith('#') || t.startsWith('-')) return null;
  const [req, ...mk] = t.split(/\s*;\s*/);
  const marker = mk.join('; ') || null;
  let m = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[([^\]]*)\])?\s*@\s*(\S+)/.exec(req);
  if (m) return { name: m[1], extras: m[2] ? m[2].split(/\s*,\s*/) : [], spec: `@ ${m[3]}`, url: m[3], marker };
  m = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[([^\]]*)\])?\s*\(?\s*([^)]*?)\s*\)?\s*$/.exec(req);
  if (!m) return null;
  return { name: m[1], extras: m[2] ? m[2].split(/\s*,\s*/) : [], spec: m[3] || '', url: null, marker };
}

export function classifyPypi(parsed) {
  if (parsed.url) return out('non_registry', { source: /^git\+/.test(parsed.url) ? 'git' : /^file:/.test(parsed.url) ? 'path' : 'url', immutable: HEX40.test(parsed.url) || /#sha256=/.test(parsed.url), detail: 'direct reference' });
  const spec = parsed.spec.trim();
  if (!spec) return out('open', { detail: 'any version' });
  const parts = spec.split(',').map(x => x.trim()).filter(Boolean);
  if (parts.length === 1) {
    const m = /^(===?)\s*([^\s*]+)$/.exec(parts[0]);
    if (m && !m[2].includes('*')) return out('exact', { version: m[2] });
  }
  const hasUpper = parts.some(p => /^(?:<|<=|~=|==.*\*|!=)/.test(p) && !/^!=/.test(p));
  if (parts.some(p => /^~=/.test(p) || /^==.*\*/.test(p)) || hasUpper) return out('range', { detail: spec });
  return out('open', { detail: 'no upper bound' });
}

// ── Cargo ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
export function classifyCargo(decl) {
  if (typeof decl === 'string') return classifyCargoReq(decl);
  if (decl && typeof decl === 'object') {
    if (decl.git) {
      const rev = decl.rev && /^[0-9a-f]{7,40}$/i.test(decl.rev);
      return out('non_registry', { source: 'git', immutable: Boolean(rev), detail: rev ? 'git revision' : `git ${decl.tag ? `tag ${decl.tag}` : decl.branch ? `branch ${decl.branch}` : 'default branch'} (can move)` });
    }
    if (decl.path) return out('non_registry', { source: 'path', immutable: false, detail: 'local path' });
    if (decl.workspace) return out('non_registry', { source: 'workspace', immutable: false, detail: 'workspace dependency' });
    const r = classifyCargoReq(decl.version ?? '*');
    return decl.registry ? { ...r, source: 'alternate-registry', detail: `registry "${decl.registry}"` } : r;
  }
  return out('open', { detail: 'no version' });
}
function classifyCargoReq(v) {
  const s = String(v).trim();
  const m = /^=\s*(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$/.exec(s);
  if (m) return out('exact', { version: m[1] });
  if (s === '*' || s === '') return out('open', { detail: 'any version' });
  if (/^>=?\s*[\d.]+$/.test(s)) return out('open', { detail: 'no upper bound' });
  return out('range', { detail: /^\d/.test(s) ? `^${s} (a bare version is a caret range)` : s });
}

// ── Go ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
export function classifyGo(version) {
  const v = String(version);
  if (/^v\d+\.\d+\.\d+-(?:[0-9A-Za-z.]*\.)?\d{14}-[0-9a-f]{12}$/.test(v)) return out('exact', { version: v, immutable: true, detail: 'pseudo-version (a commit)' });
  if (/^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+incompatible)?$/.test(v)) return out('floor', { version: v, detail: 'minimal version selection: the build uses this version unless another module requires a newer one' });
  return out('unknown', { detail: v });
}

// ── RubyGems requirement arrays ─────────────────────────────────────────────────────────────────────────────────────────────────
export function classifyGem(requirements) {
  const reqs = (requirements || []).map(r => (Array.isArray(r) ? [String(r[0]).trim(), String(r[1]?.version ?? r[1] ?? '').trim()] : null)).filter(Boolean);
  if (!reqs.length || (reqs.length === 1 && reqs[0][0] === '>=' && /^0(?:\.0)*$/.test(reqs[0][1]))) return out('open', { detail: 'any version' });
  if (reqs.length === 1 && reqs[0][0] === '=') return out('exact', { version: reqs[0][1] });
  const text = reqs.map(r => `${r[0]} ${r[1]}`).join(', ');
  if (reqs.some(r => r[0] === '~>' || r[0] === '<' || r[0] === '<=')) return out('range', { detail: text });
  return out('open', { detail: `${text} (no upper bound)` });
}

// ── NuGet ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
export function classifyNuget(v) {
  const s = String(v ?? '').trim();
  if (!s) return out('open', { detail: 'any version' });
  let m = /^\[\s*([^,\]\s]+)\s*\]$/.exec(s);
  if (m) return out('exact', { version: m[1] });
  if (/\*/.test(s)) return out('open', { detail: 'floating version' });
  if (/^[[(]/.test(s)) {
    m = /^[[(]\s*([^,\s]*)\s*,\s*([^,\])\s]*)\s*[\])]$/.exec(s);
    return m && m[2] ? out('range', { detail: s }) : out('open', { detail: 'no upper bound' });
  }
  return /^\d/.test(s) ? out('floor', { version: s, detail: 'NuGet treats a plain version as a minimum (>=); the lowest applicable version is installed' }) : out('unknown', { detail: s });
}

// ── Composer ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
export function classifyComposer(c) {
  const s = String(c ?? '').trim();
  if (!s || s === '*') return out('open', { detail: 'any version' });
  if (/^dev-|-dev$|@dev$/.test(s)) return out('non_registry', { source: 'branch', immutable: /#[0-9a-f]{40}/.test(s), detail: 'development branch (can move)' });
  const m = /^=?\s*v?(\d+\.\d+(?:\.\d+){0,2}(?:-[0-9A-Za-z.]+)?)(?:@\w+)?$/.exec(s);
  if (m && m[1].split('-')[0].split('.').length >= 3) return out('exact', { version: m[1] });
  if (/\^|~|\*|\s-\s|<|\|/.test(s) || m) return /^>=?\s*[\d.]+$/.test(s) ? out('open', { detail: 'no upper bound' }) : out('range', { detail: s });
  if (/^>=?/.test(s)) return out('open', { detail: 'no upper bound' });
  return out('range', { detail: s });
}

// ── pub ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
export function classifyPub(decl) {
  if (decl && typeof decl === 'object') {
    if (decl.git) {
      const ref = typeof decl.git === 'object' ? decl.git.ref : null;
      return out('non_registry', { source: 'git', immutable: Boolean(ref && /^[0-9a-f]{40}$/i.test(ref)), detail: ref ? `git ref ${ref}` : 'git default branch (can move)' });
    }
    if (decl.path) return out('non_registry', { source: 'path', immutable: false, detail: 'local path' });
    if (decl.sdk) return out('non_registry', { source: 'sdk', immutable: true, detail: `SDK (${decl.sdk})` });
    if (decl.hosted) { const r = classifyPub(decl.version ?? 'any'); return { ...r, source: 'alternate-registry', detail: `hosted at ${typeof decl.hosted === 'string' ? decl.hosted : decl.hosted.url || '?'}` }; }
    return classifyPub(decl.version ?? 'any');
  }
  const s = String(decl ?? 'any').trim();
  if (!s || s === 'any') return out('open', { detail: 'any version' });
  if (/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)*$/.test(s)) return out('exact', { version: s });
  if (/^>=?\s*[\d.]+$/.test(s)) return out('open', { detail: 'no upper bound' });
  return out('range', { detail: s });
}

export const PIN_LABEL = { exact: 'pinned', floor: 'minimum (resolver installs this)', range: 'range', open: 'unbounded', non_registry: 'not from the registry', unknown: 'unknown' };
