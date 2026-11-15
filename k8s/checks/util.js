'use strict';
export const rule = (r) => r;
export const T = (v) => v === true || v === 'true';
export const F = (v) => v === false || v === 'false';
export const num = (v) => (v === undefined || v === null || v === '' ? null : Number(v));
export const arr = (v) => (Array.isArray(v) ? v : []);
export const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});

/** Every container of a pod spec with its kind. */
export function containersOf(spec) {
  return [
    ...arr(spec.containers).map((c) => ({ c, type: 'container' })),
    ...arr(spec.initContainers).map((c) => ({ c, type: 'init' })),
    ...arr(spec.ephemeralContainers).map((c) => ({ c, type: 'ephemeral' })),
  ].filter((x) => x.c && typeof x.c === 'object');
}

export const podSc = (spec) => obj(spec.securityContext);
export const ctrSc = (c) => obj(c.securityContext);

/** Violation location for a workload (pod level) or one of its containers. */
export const where = (w, c) => ({ resource: c ? `${w.ref}[${c.name}]` : w.ref, scope: w.namespace });

/**
 * Runs `test(workload, containerOrNull, type)` over every workload (pod-level) or container and collects violations.
 * `test` returns null/false (no finding), a string (the detail) or { detail, severity }.
 */
export function scanWorkloads(inv, level, test) {
  const out = [];
  for (const w of inv.workloads()) {
    if (level === 'pod') {
      const r = test(w, null, null);
      if (r) out.push({ ...where(w), ...(typeof r === 'string' ? { detail: r } : r) });
    } else {
      for (const { c, type } of containersOf(obj(w.spec))) {
        const r = test(w, c, type);
        if (r) out.push({ ...where(w, c), ...(typeof r === 'string' ? { detail: r } : r) });
      }
    }
  }
  return out;
}

/** Splits an image reference into { registry, repo, tag, digest }. */
export function parseImage(image) {
  const s = String(image || '');
  let digest = null, rest = s;
  const at = rest.indexOf('@');
  if (at >= 0) { digest = rest.slice(at + 1); rest = rest.slice(0, at); }
  const slash = rest.indexOf('/');
  let registry = 'docker.io', path = rest;
  if (slash > 0 && (/[.:]/.test(rest.slice(0, slash)) || rest.slice(0, slash) === 'localhost')) { registry = rest.slice(0, slash); path = rest.slice(slash + 1); }
  const colon = path.lastIndexOf(':');
  let tag = null, repo = path;
  if (colon > path.lastIndexOf('/')) { tag = path.slice(colon + 1); repo = path.slice(0, colon); }
  return { registry, repo, tag, digest };
}

export const DEFAULT_SA = (spec) => !spec.serviceAccountName && !spec.serviceAccount ? true : (spec.serviceAccountName || spec.serviceAccount) === 'default';
