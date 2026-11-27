'use strict';
// canonical/types.js — the finding-type vocabulary of the canonical report, with no dependencies, so that a rule catalog
// (mobile/lib/rules.js, package/lib/rules.js, mcp/lib/rules.js) can name the type of each of its rules without importing the
// rest of the canonical layer. canonical/common.js re-exports TYPES; every adapter reads it from there.
//
// A finding's `type` says what KIND of thing it is, not which scanner produced it. Each type answers one question: a finding gets
// the type whose question it answers "yes" to. When two types seem to fit, the more specific one wins (mal over vuln, secret over
// vuln, integrity over misconfig).
//
// The app scanners (ubel-mobile, ubel-binary, ubel-package, ubel-mcp-client, ubel-mcp-server) do not guess the type from a rule's
// name: each rule of their catalogs carries its type (the last argument of R(...)), `Findings.add` copies it into the finding as
// `finding_type` (a finding may override it when one rule covers two kinds of thing), and canonical/adapters/appscan.js reads it.
// tests/finding-types.test.js fails when a catalog rule has no valid type, so a new rule cannot be added without picking one.
export const TYPES = {
  VULN: 'vuln', INFECTION: 'infection', SC_VULN: 'sc_vuln', SC_INFECTION: 'sc_infection', SECRET: 'secret', MAL: 'mal', CODE: 'code',
  MISCONFIG: 'misconfig', HARDENING: 'hardening', INTEGRITY: 'integrity',
  BEHAVIOR: 'behavior', EXPOSURE: 'exposure', LICENSE: 'license', COVERAGE: 'coverage',
};

export const TYPE_QUESTIONS = {
  [TYPES.VULN]: 'Is this a weakness in code (source, bytecode, or what a native binary imports) that a developer could fix?',
  [TYPES.MAL]: 'Is this something only hostile code does (reverse shell, miner, credential theft, download-and-run, tool poisoning)?',
  [TYPES.SECRET]: 'Is this a credential or key that ships inside the artifact?',
  [TYPES.BEHAVIOR]: 'Is this a capability the software has that is not a defect in itself (loads code, runs commands, reads identifiers, install hooks)?',
  [TYPES.MISCONFIG]: 'Is this a setting, or a file that should not ship (manifest, configuration, debug build, bundled backup), that should be different?',
  [TYPES.HARDENING]: 'Is this a protection that is missing or present (PIE, RELRO, ASLR, hardened runtime, certificate pinning)?',
  [TYPES.INTEGRITY]: 'Is the artifact or its metadata not what its publisher declared, or a change nobody approved (digest or manifest mismatch, unverifiable archive, changed definitions)?',
  [TYPES.SC_VULN]: 'Is this a known advisory (CVE / OSV) on a third-party component?',
  [TYPES.SC_INFECTION]: 'Is this third-party component itself known to be malicious or compromised?',
  [TYPES.INFECTION]: 'Same as sc_infection; only read from canonical files written earlier.',
  [TYPES.EXPOSURE]: 'Is this reachable network surface (open port, listener, remote host)?',
  [TYPES.LICENSE]: 'Does this component carry a license obligation or risk?',
  [TYPES.COVERAGE]: 'Is this a part of the scan that could not be (fully) assessed?',
  [TYPES.CODE]: 'Retired. Only the fallback for a rule that no catalog knows, and what canonical files written earlier hold; no catalog rule has it.',
};

const ALL = new Set(Object.values(TYPES));
export const isFindingType = (v) => typeof v === 'string' && ALL.has(v);
