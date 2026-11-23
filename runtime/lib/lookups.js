'use strict';
// lookups.js — advisory lookups for the native components a runtime scan finds, through UBEL's own engine (OSV.dev for package URLs, NVD for CPEs):
// the same code and the same fail-closed contract as ubel-binary. A lookup that cannot be completed THROWS, and the
// check that needed it is then "not assessed" — never "clean". Set UBEL_OSV_ENDPOINT / UBEL_NVD_ENDPOINT for internal mirrors.
// The lookup code is loaded lazily, only when a lookup runs.

import { cRecord } from '../../binary/lib/records.js';

/** CPE / PURL component records (from ubel-binary's readers or built here) → advisories. Same shape as ubel-binary's dependency block. */
export async function lookupComponents(records, { log = () => {} } = {}) {
  const { scanBinaryDependencies } = await import('../../binary/lib/deps.js');
  const r = await scanBinaryDependencies(records, { log });
  if (r.lookup_error) throw new Error(`component lookup incomplete: ${r.lookup_error}`);
  return r;
}

/** Component records for the runtime a Node.js process reports about itself (process.versions): the Node.js release and the libraries it bundles. */
export function nodeRuntimeRecords(versions) {
  const v = versions || {};
  const clean = (x) => String(x || '').replace(/-.*$/, '');
  const mk = (name, ver, vendor, product) => (ver ? cRecord({ name, version: ver, vendor, product, evidence: `process.versions: ${name} ${ver}`, source: 'process.versions (live inspection)', sourceType: 'node runtime report', ecosystem: 'Node.js runtime' }) : null);
  return [
    mk('Node.js', clean(v.node), 'nodejs', 'node.js'),
    mk('OpenSSL', clean(v.openssl), 'openssl', 'openssl'),
    mk('zlib', String(v.zlib || '').match(/^\d+(?:\.\d+)+/)?.[0], 'zlib', 'zlib'),
    mk('nghttp2', clean(v.nghttp2), 'nghttp2', 'nghttp2'),
    mk('c-ares', clean(v.ares), 'c-ares_project', 'c-ares'),
  ].filter(Boolean);
}
