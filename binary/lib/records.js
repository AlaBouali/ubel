'use strict';
// records.js — the component record shapes shared by every detector in this folder (banners, Go, Rust, npm bundles, Python bundles).
// Moved out of components.js so each language module can build records without importing the banner table.

export const C_ECOSYSTEM = 'C/C++ library (version banner)';

export const cpeOf = (vendor, product, version) => `cpe:2.3:a:${vendor}:${product}:${version}:*:*:*:*:*:*:*`;
export const specificEnough = v => /^\d+(\.\d+){1,}/.test(String(v || ''));            // same guard as the EASM NVD path: a bare "3" matches every release

/** A component identified by an NVD CPE (looked up through the SCA engine's NVD path). */
export function cRecord({ name, version, vendor, product, evidence, source = 'embedded version string', sourceType = 'binary version string', ecosystem = C_ECOSYSTEM }) {
  const cpe = cpeOf(vendor, product, version);
  return {
    name, version, ecosystem, purl: null, coordinate: cpe, cpe, platform: 'native',
    sources: [source], source_types: [sourceType], confidence: 'medium', identity: null,
    lookup_status: specificEnough(version) ? 'pending' : 'not_queryable',
    lookup_reason: specificEnough(version) ? null : 'The version string is not specific enough for an NVD CPE query.',
    evidence: String(evidence || '').slice(0, 120), vulnerabilities: [], vulnerability_count: 0,
  };
}

/** A component identified by a package URL (looked up through OSV.dev). */
export function purlRecord({ name, version, ecosystem, purl, source, sourceType, confidence = 'high', evidence }) {
  return {
    name, version, ecosystem, purl, coordinate: null, platform: 'native', sources: [source], source_types: [sourceType], confidence, identity: null,
    lookup_status: 'pending', lookup_reason: null, ...(evidence ? { evidence: String(evidence).slice(0, 120) } : {}), vulnerabilities: [], vulnerability_count: 0,
  };
}

/** A package that is visibly in the file but whose version could not be recovered: kept as inventory, never sent to a lookup. */
export function inventoryRecord({ name, ecosystem, source, sourceType, reason, confidence = 'medium', evidence }) {
  return {
    name, version: null, ecosystem, purl: null, coordinate: null, platform: 'native', sources: [source], source_types: [sourceType], confidence, identity: null,
    lookup_status: 'not_queryable', lookup_reason: reason, ...(evidence ? { evidence: String(evidence).slice(0, 120) } : {}), vulnerabilities: [], vulnerability_count: 0,
  };
}

/** npm package URL: a scope is `%40scope`, every other character is percent-encoded. */
export function npmPurl(name, version) {
  const parts = String(name).split('/').map(p => encodeURIComponent(p));
  return `pkg:npm/${parts.join('/')}@${version}`;
}

/** PyPI package URL: names are compared normalised (lower case, runs of - _ . become -). */
export function pypiPurl(name, version) { return `pkg:pypi/${normalisePypi(name)}@${version}`; }
export const normalisePypi = name => String(name).toLowerCase().replace(/[-_.]+/g, '-');
