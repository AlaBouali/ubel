'use strict';
// compliance_mappings.js — shared compliance-framework mapping engine.
//
// Single source of truth for mapping a finding (SCA vulnerability, SAST
// finding, malicious-code finding, secrets-in-source finding, or cloud
// misconfiguration) onto industry compliance/security frameworks, so the
// SCA, SAST, and cloud modules all attach the same shape of `compliance`
// data to their findings and all three report formats (JSON, HTML, SARIF —
// SARIF only where the module already emits it) stay consistent.
//
// Design: every finding is assigned one or more internal risk CATEGORIES
// (e.g. "injection", "public_exposure"). Each category has a fixed list of
// framework control references in CATEGORY_CONTROLS. This keeps the mapping
// maintainable — a new CWE or cloud check only needs a category assignment,
// not its own hand-written framework list — and keeps every finding of the
// same underlying risk mapped identically across modules.
//
// ACCURACY NOTE: control identifiers below are the stable, widely-published
// ones for each framework (OWASP Top 10 category codes, NIST SP 800-53
// control IDs, CIS Controls v8 numbers, HIPAA/GDPR article & section
// citations, SOC 2 Trust Services Criteria codes, PCI DSS v4.0 requirement
// numbers, ISO/IEC 27001:2022 Annex A control numbers). These are
// best-effort control-family guidance derived from public framework
// documentation, not a substitute for a certified assessor's mapping —
// framework text, versioning, and applicable sub-clauses can change, and
// scope always depends on the organization's own environment. Treat this as
// a starting point for an audit conversation, not a citation to quote
// verbatim in one. See COMPLIANCE_DISCLAIMER below.

const COMPLIANCE_DISCLAIMER =
  'Compliance framework references are best-effort guidance mapped from public framework ' +
  'documentation, not a certified compliance assessment. Verify applicable controls, current ' +
  'framework versions, and scope with your compliance/legal team before relying on this mapping ' +
  'for an audit.';

// ── Framework registry ──────────────────────────────────────────────────────
// Each entry carries the exact version/edition this mapping was written
// against (`name` is just the framework, unversioned) so a report can state
// "mapped against PCI DSS v4.0" without the reader having to go find that
// out for themselves — frameworks get revised, and a mapping silently goes
// stale otherwise. See COMPLIANCE_DISCLAIMER: verify these are still the
// versions your audit needs.
//
// CIS_BENCHMARK entries (cis_aws_foundations / cis_azure_foundations /
// cis_gcp_foundations) are a different kind of thing from CIS Controls v8:
// Controls v8 is the vendor-agnostic 18-control list, "CIS Benchmarks" are
// the per-platform technical hardening guides auditors actually cite for a
// cloud finding (e.g. "CIS AWS Foundations Benchmark 3.1"). Only cloud
// findings with a check-specific benchmark mapping (CIS_BENCHMARK_CONTROLS
// below) get one of these three attached; everything else still gets
// Controls v8 via CATEGORY_CONTROLS like before.
const FRAMEWORKS = {
  owasp_top10_2021:      { name: 'OWASP Top 10',                            version: '2021' },
  pci_dss_4_0:            { name: 'PCI DSS',                                  version: 'v4.0' },
  hipaa_security_rule:    { name: 'HIPAA Security Rule',                      version: null },
  soc2:                   { name: 'SOC 2 (Trust Services Criteria)',         version: '2017' },
  iso_27001_2022:         { name: 'ISO/IEC 27001 (Annex A)',                 version: '2022' },
  nist_800_53_r5:         { name: 'NIST SP 800-53',                          version: 'Rev. 5' },
  gdpr:                   { name: 'GDPR',                                    version: null },
  cis_controls_v8:        { name: 'CIS Controls',                            version: 'v8' },
  cis_aws_foundations:    { name: 'CIS Amazon Web Services Foundations Benchmark', version: 'v1.5.0' },
  cis_azure_foundations:  { name: 'CIS Microsoft Azure Foundations Benchmark',     version: 'v2.0.0' },
  cis_gcp_foundations:    { name: 'CIS Google Cloud Platform Foundation Benchmark', version: 'v1.3.0' },
};

// ── Category → framework control references ────────────────────────────────
// Each entry: { framework: <FRAMEWORKS key>, control: '<id>', title: '<short title>' }
const CATEGORY_CONTROLS = {
  injection: [
    { framework: 'owasp_top10_2021', control: 'A03:2021', title: 'Injection' },
    { framework: 'pci_dss_4_0', control: 'Req. 6.2.4', title: 'Prevent common software attacks (injection, XSS, etc.) via secure coding' },
    { framework: 'nist_800_53_r5', control: 'SI-10', title: 'Information Input Validation' },
    { framework: 'soc2', control: 'CC8.1', title: 'Change management / secure development' },
    { framework: 'iso_27001_2022', control: 'A.8.28', title: 'Secure coding' },
    { framework: 'cis_controls_v8', control: 'CIS 16', title: 'Application Software Security' },
  ],
  broken_access_control: [
    { framework: 'owasp_top10_2021', control: 'A01:2021', title: 'Broken Access Control' },
    { framework: 'pci_dss_4_0', control: 'Req. 7', title: 'Restrict access to system components by business need-to-know' },
    { framework: 'nist_800_53_r5', control: 'AC-3 / AC-6', title: 'Access Enforcement / Least Privilege' },
    { framework: 'soc2', control: 'CC6.1', title: 'Logical access controls' },
    { framework: 'iso_27001_2022', control: 'A.5.15', title: 'Access control' },
    { framework: 'hipaa_security_rule', control: '§164.312(a)(1)', title: 'Access control' },
  ],
  path_traversal: [
    { framework: 'owasp_top10_2021', control: 'A01:2021', title: 'Broken Access Control' },
    { framework: 'pci_dss_4_0', control: 'Req. 6.2.4', title: 'Prevent common software attacks via secure coding' },
    { framework: 'nist_800_53_r5', control: 'SI-10', title: 'Information Input Validation' },
    { framework: 'cis_controls_v8', control: 'CIS 16', title: 'Application Software Security' },
  ],
  insecure_deserialization: [
    { framework: 'owasp_top10_2021', control: 'A08:2021', title: 'Software and Data Integrity Failures' },
    { framework: 'nist_800_53_r5', control: 'SI-10', title: 'Information Input Validation' },
    { framework: 'soc2', control: 'CC8.1', title: 'Change management / secure development' },
    { framework: 'cis_controls_v8', control: 'CIS 16', title: 'Application Software Security' },
  ],
  ssrf: [
    { framework: 'owasp_top10_2021', control: 'A10:2021', title: 'Server-Side Request Forgery (SSRF)' },
    { framework: 'pci_dss_4_0', control: 'Req. 1', title: 'Network security controls' },
    { framework: 'nist_800_53_r5', control: 'SC-7', title: 'Boundary Protection' },
    { framework: 'cis_controls_v8', control: 'CIS 13', title: 'Network Monitoring and Defense' },
  ],
  secrets_management: [
    { framework: 'owasp_top10_2021', control: 'A02:2021', title: 'Cryptographic Failures' },
    { framework: 'pci_dss_4_0', control: 'Req. 3 / Req. 8', title: 'Protect stored account data; identify and authenticate access' },
    { framework: 'nist_800_53_r5', control: 'IA-5', title: 'Authenticator Management' },
    { framework: 'soc2', control: 'CC6.1', title: 'Logical access controls' },
    { framework: 'iso_27001_2022', control: 'A.8.24', title: 'Use of cryptography' },
    { framework: 'hipaa_security_rule', control: '§164.312(a)(2)(iv)', title: 'Encryption and decryption' },
    { framework: 'gdpr', control: 'Art. 32', title: 'Security of processing' },
    { framework: 'cis_controls_v8', control: 'CIS 3', title: 'Data Protection' },
  ],
  cryptography: [
    { framework: 'owasp_top10_2021', control: 'A02:2021', title: 'Cryptographic Failures' },
    { framework: 'pci_dss_4_0', control: 'Req. 3 / Req. 4', title: 'Protect stored account data; protect data in transit with strong cryptography' },
    { framework: 'nist_800_53_r5', control: 'SC-8 / SC-13 / SC-28', title: 'Transmission Confidentiality; Cryptographic Protection; Protection of Information at Rest' },
    { framework: 'soc2', control: 'CC6.7', title: 'Transmission and encryption controls' },
    { framework: 'iso_27001_2022', control: 'A.8.24', title: 'Use of cryptography' },
    { framework: 'hipaa_security_rule', control: '§164.312(a)(2)(iv) / (e)(1)', title: 'Encryption/decryption; transmission security' },
    { framework: 'gdpr', control: 'Art. 32', title: 'Security of processing' },
  ],
  sensitive_data_exposure: [
    { framework: 'owasp_top10_2021', control: 'A02:2021', title: 'Cryptographic Failures (sensitive data exposure)' },
    { framework: 'pci_dss_4_0', control: 'Req. 3', title: 'Protect stored account data' },
    { framework: 'nist_800_53_r5', control: 'SC-28', title: 'Protection of Information at Rest' },
    { framework: 'soc2', control: 'CC6.1', title: 'Logical access controls' },
    { framework: 'hipaa_security_rule', control: '§164.312(c)(1)', title: 'Integrity' },
    { framework: 'gdpr', control: 'Art. 32', title: 'Security of processing' },
    { framework: 'cis_controls_v8', control: 'CIS 3', title: 'Data Protection' },
  ],
  security_misconfiguration: [
    { framework: 'owasp_top10_2021', control: 'A05:2021', title: 'Security Misconfiguration' },
    { framework: 'pci_dss_4_0', control: 'Req. 2', title: 'Apply secure configurations to all system components' },
    { framework: 'nist_800_53_r5', control: 'CM-6 / CM-7', title: 'Configuration Settings; Least Functionality' },
    { framework: 'soc2', control: 'CC8.1', title: 'Change management' },
    { framework: 'iso_27001_2022', control: 'A.8.9', title: 'Configuration management' },
    { framework: 'cis_controls_v8', control: 'CIS 4', title: 'Secure Configuration of Enterprise Assets and Software' },
  ],
  input_validation: [
    { framework: 'owasp_top10_2021', control: 'A03:2021', title: 'Injection (improper input validation)' },
    { framework: 'pci_dss_4_0', control: 'Req. 6.2.4', title: 'Prevent common software attacks via secure coding' },
    { framework: 'nist_800_53_r5', control: 'SI-10', title: 'Information Input Validation' },
    { framework: 'cis_controls_v8', control: 'CIS 16', title: 'Application Software Security' },
  ],
  memory_safety: [
    { framework: 'nist_800_53_r5', control: 'SI-16', title: 'Memory Protection' },
    { framework: 'iso_27001_2022', control: 'A.8.28', title: 'Secure coding' },
    { framework: 'soc2', control: 'CC8.1', title: 'Change management / secure development' },
    { framework: 'cis_controls_v8', control: 'CIS 16', title: 'Application Software Security' },
  ],
  availability_dos: [
    { framework: 'owasp_top10_2021', control: 'A04:2021', title: 'Insecure Design (uncontrolled resource consumption)' },
    { framework: 'nist_800_53_r5', control: 'SC-5', title: 'Denial-of-Service Protection' },
    { framework: 'cis_controls_v8', control: 'CIS 13', title: 'Network Monitoring and Defense' },
  ],
  session_management: [
    { framework: 'owasp_top10_2021', control: 'A07:2021', title: 'Identification and Authentication Failures' },
    { framework: 'pci_dss_4_0', control: 'Req. 8', title: 'Identify and authenticate access to system components' },
    { framework: 'nist_800_53_r5', control: 'AC-12 / IA-2', title: 'Session Termination; Identification and Authentication' },
    { framework: 'soc2', control: 'CC6.1', title: 'Logical access controls' },
    { framework: 'iso_27001_2022', control: 'A.5.15', title: 'Access control' },
  ],
  business_logic: [
    { framework: 'owasp_top10_2021', control: 'A04:2021', title: 'Insecure Design' },
    { framework: 'nist_800_53_r5', control: 'SA-8', title: 'Security and Privacy Engineering Principles' },
    { framework: 'cis_controls_v8', control: 'CIS 16', title: 'Application Software Security' },
  ],
  malicious_code_supply_chain: [
    { framework: 'owasp_top10_2021', control: 'A08:2021', title: 'Software and Data Integrity Failures' },
    { framework: 'pci_dss_4_0', control: 'Req. 6', title: 'Develop and maintain secure systems and software' },
    { framework: 'nist_800_53_r5', control: 'SI-7 / SR-3', title: 'Software & Information Integrity; Supply Chain Controls and Processes' },
    { framework: 'soc2', control: 'CC7.1', title: 'Detection of security events' },
    { framework: 'iso_27001_2022', control: 'A.5.19', title: 'Information security in supplier relationships' },
    { framework: 'cis_controls_v8', control: 'CIS 16', title: 'Application Software Security' },
  ],
  vulnerable_components: [
    { framework: 'owasp_top10_2021', control: 'A06:2021', title: 'Vulnerable and Outdated Components' },
    { framework: 'pci_dss_4_0', control: 'Req. 6.3', title: 'Security vulnerabilities are identified and addressed' },
    { framework: 'nist_800_53_r5', control: 'RA-5 / SI-2', title: 'Vulnerability Monitoring and Scanning; Flaw Remediation' },
    { framework: 'soc2', control: 'CC7.1', title: 'Identification of vulnerabilities' },
    { framework: 'iso_27001_2022', control: 'A.8.8', title: 'Management of technical vulnerabilities' },
    { framework: 'cis_controls_v8', control: 'CIS 7', title: 'Continuous Vulnerability Management' },
  ],
  public_exposure: [
    { framework: 'owasp_top10_2021', control: 'A01:2021 / A05:2021', title: 'Broken Access Control / Security Misconfiguration' },
    { framework: 'pci_dss_4_0', control: 'Req. 1', title: 'Install and maintain network security controls' },
    { framework: 'nist_800_53_r5', control: 'SC-7 / AC-4', title: 'Boundary Protection; Information Flow Enforcement' },
    { framework: 'soc2', control: 'CC6.6', title: 'Logical access — boundary protection against external threats' },
    { framework: 'iso_27001_2022', control: 'A.8.20', title: 'Networks security' },
    { framework: 'gdpr', control: 'Art. 32', title: 'Security of processing' },
    { framework: 'cis_controls_v8', control: 'CIS 13', title: 'Network Monitoring and Defense' },
  ],
  iam_misconfiguration: [
    { framework: 'owasp_top10_2021', control: 'A07:2021', title: 'Identification and Authentication Failures' },
    { framework: 'pci_dss_4_0', control: 'Req. 7 / Req. 8', title: 'Restrict access by need-to-know; identify and authenticate access (incl. MFA)' },
    { framework: 'nist_800_53_r5', control: 'AC-2 / AC-6 / IA-2', title: 'Account Management; Least Privilege; Identification and Authentication' },
    { framework: 'soc2', control: 'CC6.1 / CC6.2', title: 'Logical access controls; user registration and authorization' },
    { framework: 'iso_27001_2022', control: 'A.5.15 / A.8.5', title: 'Access control; Secure authentication' },
    { framework: 'cis_controls_v8', control: 'CIS 5 / CIS 6', title: 'Account Management; Access Control Management' },
  ],
  logging_monitoring: [
    { framework: 'pci_dss_4_0', control: 'Req. 10', title: 'Log and monitor all access to system components and cardholder data' },
    { framework: 'nist_800_53_r5', control: 'AU-2 / AU-6', title: 'Event Logging; Audit Record Review, Analysis, and Reporting' },
    { framework: 'soc2', control: 'CC7.2', title: 'Monitoring of system components for anomalies' },
    { framework: 'iso_27001_2022', control: 'A.8.16', title: 'Monitoring activities' },
    { framework: 'hipaa_security_rule', control: '§164.312(b)', title: 'Audit controls' },
    { framework: 'cis_controls_v8', control: 'CIS 8', title: 'Audit Log Management' },
  ],
  data_protection_resilience: [
    { framework: 'nist_800_53_r5', control: 'CP-9', title: 'System Backup' },
    { framework: 'soc2', control: 'A1.2', title: 'Availability — backup and recovery infrastructure' },
    { framework: 'iso_27001_2022', control: 'A.8.13', title: 'Information backup' },
    { framework: 'gdpr', control: 'Art. 32(1)(c)', title: 'Ability to restore availability and access to data in a timely manner' },
    { framework: 'cis_controls_v8', control: 'CIS 11', title: 'Data Recovery' },
  ],
};

// ── SCA / real-world CVE data: CWE number → category ────────────────────────
// Covers the CWE Top 25 plus the CWEs the SAST catalog below already tracks,
// so common OSV/NVD advisory CWEs resolve to a category. Anything not
// listed falls back to just `vulnerable_components` (still a real, accurate
// mapping — every SCA finding is a known-vulnerable-component finding by
// definition) rather than going unmapped.
const CWE_CATEGORY = {
  20: 'input_validation', 22: 'path_traversal', 59: 'broken_access_control',
  74: 'injection', 77: 'injection', 78: 'injection', 79: 'injection', 80: 'injection',
  89: 'injection', 90: 'injection', 91: 'injection', 94: 'injection', 95: 'injection',
  98: 'path_traversal', 113: 'injection', 117: 'injection', 119: 'memory_safety',
  120: 'memory_safety', 121: 'memory_safety', 122: 'memory_safety', 125: 'memory_safety',
  129: 'input_validation', 134: 'memory_safety', 190: 'memory_safety', 191: 'memory_safety',
  200: 'sensitive_data_exposure', 209: 'sensitive_data_exposure', 250: 'security_misconfiguration',
  269: 'broken_access_control', 276: 'security_misconfiguration', 284: 'broken_access_control',
  285: 'broken_access_control', 287: 'session_management', 295: 'cryptography',
  297: 'cryptography', 306: 'broken_access_control', 307: 'availability_dos',
  311: 'cryptography', 312: 'sensitive_data_exposure', 319: 'cryptography',
  321: 'cryptography', 322: 'cryptography', 326: 'cryptography', 327: 'cryptography',
  330: 'cryptography', 338: 'cryptography', 347: 'session_management', 352: 'session_management',
  362: 'memory_safety', 367: 'memory_safety', 400: 'availability_dos', 415: 'memory_safety',
  416: 'memory_safety', 425: 'broken_access_control', 426: 'security_misconfiguration',
  427: 'security_misconfiguration', 434: 'input_validation', 441: 'ssrf',
  457: 'memory_safety', 476: 'memory_safety', 489: 'security_misconfiguration',
  494: 'security_misconfiguration', 502: 'insecure_deserialization', 506: 'malicious_code_supply_chain',
  521: 'iam_misconfiguration', 532: 'sensitive_data_exposure', 601: 'input_validation',
  611: 'injection', 614: 'session_management', 639: 'broken_access_control',
  643: 'injection', 668: 'sensitive_data_exposure', 693: 'security_misconfiguration',
  697: 'business_logic', 732: 'security_misconfiguration', 759: 'cryptography',
  760: 'cryptography', 770: 'availability_dos', 776: 'injection', 798: 'secrets_management',
  824: 'memory_safety', 840: 'business_logic', 843: 'business_logic', 862: 'broken_access_control',
  863: 'broken_access_control', 909: 'security_misconfiguration', 916: 'cryptography',
  917: 'injection', 918: 'ssrf', 937: 'vulnerable_components', 942: 'security_misconfiguration',
  943: 'injection', 1004: 'session_management', 1104: 'vulnerable_components',
  1236: 'memory_safety', 1321: 'security_misconfiguration', 1333: 'availability_dos',
};

// ── Consistency guard: CWE_CATEGORY vs. SAST_CLASS_COMPLIANCE ──────────────
// These two tables answer two different questions and are allowed to
// disagree on purpose: CWE_CATEGORY says "what's the generic category for
// this bare CWE number, with no other context" (used for SCA/CVE findings
// that only ever carry a CWE number); SAST_CLASS_COMPLIANCE says "what's
// the best category for this specific, already-written-up vuln class"
// (used for SAST findings, which carry a class name from vulnCatalog.js,
// not just a CWE). A SAST class is free to pick a more specific category
// than its CWE's generic default — e.g. "publicly exposed cloud resource"
// (CWE-284) is filed under `public_exposure`, a more specific read than
// CWE-284's own generic `broken_access_control` default — and that's a
// deliberate editorial call, not drift.
//
// What IS drift: a class's category disagreeing with its CWE's generic
// default for no such reason — i.e. nobody actually intended a different
// read, one table just fell out of sync with the other after an edit.
// findCategoryDivergences() below surfaces every disagreement (intentional
// or not) so a test can snapshot the intentional ones; any new, unreviewed
// entry in its output on top of that snapshot is drift to look at, not a
// silent surprise days later in a customer's audit report.
function findCategoryDivergences() {
  const divergences = [];
  for (const [name, info] of Object.entries(SAST_CLASS_COMPLIANCE)) {
    for (const cwe of info.cwes) {
      const defaultCategory = CWE_CATEGORY[cwe];
      if (defaultCategory && defaultCategory !== info.category) {
        divergences.push({ sastClass: name, cwe, sastCategory: info.category, cweDefaultCategory: defaultCategory });
      }
    }
  }
  return divergences;
}

// ── SAST catalog: canonical vuln_class name (lowercased) → { cwes, category } ──
// Mirrors the `name`/`cwe` pairs in sast/src/analyzer/vulnCatalog.js. Kept as
// data here (rather than re-deriving categories from CWE_CATEGORY above) so
// each SAST class gets the category that best matches how it's actually
// written up, not a generic CWE-number guess.
const SAST_CLASS_COMPLIANCE = {
  'hardcoded secret or credential':                      { cwes: [798],      category: 'secrets_management' },
  'sql injection':                                        { cwes: [89],       category: 'injection' },
  'command injection':                                    { cwes: [78],       category: 'injection' },
  'path traversal':                                       { cwes: [22],       category: 'path_traversal' },
  'unsafe deserialization':                               { cwes: [502],      category: 'insecure_deserialization' },
  'xss / template injection':                             { cwes: [79, 94],   category: 'injection' },
  'open redirect':                                        { cwes: [601],      category: 'input_validation' },
  'xxe injection':                                        { cwes: [611],      category: 'injection' },
  'ssrf':                                                  { cwes: [918],      category: 'ssrf' },
  'missing authentication check':                         { cwes: [306],      category: 'broken_access_control' },
  'broken access control / privilege escalation':         { cwes: [269],      category: 'broken_access_control' },
  'prototype pollution':                                  { cwes: [1321],     category: 'security_misconfiguration' },
  'code injection / dangerous eval':                      { cwes: [95],       category: 'injection' },
  'unsafe file upload':                                   { cwes: [434],      category: 'input_validation' },
  'sensitive data exposure / information disclosure':     { cwes: [200],      category: 'sensitive_data_exposure' },
  'cryptographic weakness':                                { cwes: [327],      category: 'cryptography' },
  'integer overflow / underflow':                          { cwes: [190],      category: 'memory_safety' },
  'null / nil dereference':                                { cwes: [476],      category: 'memory_safety' },
  'use after free / memory safety':                        { cwes: [416],      category: 'memory_safety' },
  'buffer overflow / out-of-bounds access':                { cwes: [120],      category: 'memory_safety' },
  'format string vulnerability':                           { cwes: [134],      category: 'memory_safety' },
  'race condition / toctou':                               { cwes: [362],      category: 'memory_safety' },
  'insecure direct object reference (idor)':               { cwes: [639],      category: 'broken_access_control' },
  'http header injection / response splitting':            { cwes: [113],      category: 'injection' },
  'regex denial of service (redos)':                        { cwes: [1333],     category: 'availability_dos' },
  'cross-site request forgery (csrf)':                      { cwes: [352],      category: 'session_management' },
  'nosql injection':                                        { cwes: [943],      category: 'injection' },
  'ldap / xpath injection':                                 { cwes: [90, 643],  category: 'injection' },
  'insecure session cookie attributes':                     { cwes: [614, 1004],category: 'session_management' },
  'missing / misconfigured security headers':               { cwes: [693],      category: 'security_misconfiguration' },
  'insecure cors policy':                                   { cwes: [942],      category: 'security_misconfiguration' },
  'host header injection / cache poisoning':                { cwes: [20],       category: 'input_validation' },
  'log injection / forged log entries':                     { cwes: [117],      category: 'logging_monitoring' },
  'debug / verbose error mode enabled in production':       { cwes: [489],      category: 'security_misconfiguration' },
  'insecure file permissions (world‑writable or executable)': { cwes: [276],    category: 'security_misconfiguration' },
  'graphql injection / query abuse':                        { cwes: [943, 770], category: 'injection' },
  'jwt / token validation weakness':                        { cwes: [347],      category: 'session_management' },
  'missing rate limiting / brute force exposure':           { cwes: [307],      category: 'availability_dos' },
  'expression language (el) / spel / ognl injection':       { cwes: [917],      category: 'injection' },
  'double free':                                            { cwes: [415],      category: 'memory_safety' },
  'uninitialized variable / memory read':                   { cwes: [457],      category: 'memory_safety' },
  'local / remote file inclusion (lfi/rfi)':                { cwes: [98],       category: 'path_traversal' },
  'php type juggling / loose comparison':                   { cwes: [697, 843], category: 'business_logic' },
  'unsafe rust block without safety justification':         { cwes: [1236],     category: 'memory_safety' },
  'business logic flaw':                                    { cwes: [840],      category: 'business_logic' },
  'container running as root':                              { cwes: [250],      category: 'security_misconfiguration' },
  'privileged container / excessive docker capabilities':   { cwes: [250],      category: 'security_misconfiguration' },
  'hardcoded secret in docker image or compose file':       { cwes: [798],      category: 'secrets_management' },
  'unpinned or unsafe base image':                          { cwes: [1104],     category: 'vulnerable_components' },
  'insecure add / untrusted remote content':                { cwes: [494],      category: 'security_misconfiguration' },
  'sensitive docker volume or bind mount exposure':         { cwes: [732],      category: 'security_misconfiguration' },
  'publicly exposed cloud resource':                        { cwes: [284],      category: 'public_exposure' },
  'hardcoded secret in iac template or variable':           { cwes: [798],      category: 'secrets_management' },
  'disabled encryption at rest or in transit (iac)':        { cwes: [311],      category: 'cryptography' },
  'overly permissive iam policy or rbac':                   { cwes: [269],      category: 'iam_misconfiguration' },
  'insecure kubernetes pod security context':               { cwes: [250],      category: 'security_misconfiguration' },
  'missing kubernetes network segmentation':                { cwes: [284],      category: 'public_exposure' },
  'insecure kubernetes workload supply-chain hygiene':      { cwes: [1104],     category: 'vulnerable_components' },
  'insecure network exposure or unencrypted state (terraform)': { cwes: [200], category: 'public_exposure' },
};

// ── Malware/backdoor catalog: every class maps to the same category ────────
// (see sast/src/analyzer/malwareCatalog.js) — intentional malicious code is
// a supply-chain integrity concern regardless of its specific mechanism.
const MALWARE_CLASS_CWE = {
  'reverse shell / remote command execution backdoor': [506],
  'hardcoded command-and-control (c2) endpoint':        [506],
  'obfuscated or dynamically decoded payload execution':[506],
  'unauthorized data exfiltration':                     [200],
  'hidden backdoor authentication bypass':              [798],
  'malicious persistence mechanism':                    [506],
  'supply-chain implant in build/install scripts':      [506],
  'cryptomining payload':                               [506],
  'anti-analysis / sandbox and debugger evasion':       [506],
  'logic bomb / time bomb':                             [506],
  'disabling or tampering with security controls':      [506],
  'credential or keystroke harvesting':                 [506],
  'dns tunneling / covert channel':                     [506],
  'self-modifying or self-propagating code':            [506],
  'unauthorized remote dynamic code loading':           [494],
};

// ── Cloud checks: check id → one or more categories ─────────────────────────
const CHECK_CATEGORY = {
  // AWS
  'cloudtrail-log-validation-disabled': ['logging_monitoring'],
  'cloudtrail-logging-stopped':         ['logging_monitoring'],
  'cloudtrail-no-multiregion-trail':    ['logging_monitoring'],
  'cloudtrail-not-kms-encrypted':       ['logging_monitoring', 'cryptography'],
  'ebs-default-encryption-disabled':    ['cryptography'],
  'ebs-volume-not-encrypted':           ['cryptography'],
  'ebs-volume-unattached':              ['security_misconfiguration'],
  'ec2-instance-public-ip':             ['public_exposure'],
  'guardduty-detector-disabled':        ['logging_monitoring'],
  'guardduty-not-enabled':              ['logging_monitoring'],
  'iam-access-key-not-rotated':         ['iam_misconfiguration'],
  'iam-console-user-no-mfa':            ['iam_misconfiguration'],
  'iam-no-password-policy':             ['iam_misconfiguration'],
  'iam-policy-full-admin':              ['iam_misconfiguration'],
  'iam-role-public-trust-policy':       ['public_exposure', 'iam_misconfiguration'],
  'rds-publicly-accessible':            ['public_exposure'],
  'rds-snapshot-not-encrypted':         ['cryptography'],
  'rds-snapshot-public':                ['public_exposure'],
  'rds-storage-not-encrypted':          ['cryptography'],
  's3-acl-authenticated-users':         ['public_exposure'],
  's3-acl-public':                      ['public_exposure'],
  's3-encryption-disabled':             ['cryptography'],
  's3-logging-disabled':                ['logging_monitoring'],
  's3-object-acl-public-sample':        ['public_exposure'],
  's3-policy-public':                   ['public_exposure'],
  's3-public-access-block':             ['public_exposure'],
  's3-versioning-disabled':             ['data_protection_resilience'],
  'sg-open-all-ports':                  ['public_exposure'],
  'sg-open-ingress':                    ['public_exposure'],
  'sg-open-sensitive-port':             ['public_exposure'],
  'sns-topic-policy-public':            ['public_exposure'],
  'sqs-queue-policy-public':            ['public_exposure'],
  'vpc-flow-logs-disabled':             ['logging_monitoring'],

  // Azure
  'azure-acr-admin-user-enabled':            ['iam_misconfiguration'],
  'azure-acr-public-network-access':         ['public_exposure'],
  'azure-aks-local-accounts-enabled':        ['iam_misconfiguration'],
  'azure-aks-public-api-no-authorized-ranges': ['public_exposure'],
  'azure-aks-rbac-disabled':                 ['iam_misconfiguration'],
  'azure-appservice-https-only-disabled':    ['cryptography'],
  'azure-keyvault-public-network-access':    ['public_exposure'],
  'azure-keyvault-purge-protection-disabled':['data_protection_resilience'],
  'azure-nsg-open-all-ports':                ['public_exposure'],
  'azure-nsg-open-ingress':                  ['public_exposure'],
  'azure-nsg-open-sensitive-port':           ['public_exposure'],
  'azure-nsg-unassociated-with-open-rule':   ['public_exposure'],
  'azure-sql-firewall-allow-all':            ['public_exposure'],
  'azure-sql-firewall-broad-range':          ['public_exposure'],
  'azure-storage-container-public-access':   ['public_exposure'],
  'azure-storage-http-allowed':              ['cryptography'],
  'azure-storage-outdated-tls':              ['cryptography'],
  'azure-storage-public-blob-access':        ['public_exposure'],

  // GCP
  'bigquery-dataset-public':                          ['public_exposure'],
  'cloudfunctions-public-iam':                        ['public_exposure'],
  'cloudrun-service-public-iam':                       ['public_exposure'],
  'cloudsql-authorized-network-open':                 ['public_exposure'],
  'cloudsql-public-ip-enabled':                       ['public_exposure'],
  'cloudsql-ssl-not-required':                        ['cryptography'],
  'gcp-fw-open-all':                                  ['public_exposure'],
  'gcp-fw-open-all-ports-protocol':                   ['public_exposure'],
  'gcp-fw-open-ingress':                              ['public_exposure'],
  'gcp-fw-open-sensitive-port':                       ['public_exposure'],
  'gcp-instance-default-sa-full-access':              ['iam_misconfiguration'],
  'gcp-project-iam-public':                           ['public_exposure', 'iam_misconfiguration'],
  'gcs-bucket-fine-grained-acl':                      ['security_misconfiguration'],
  'gcs-bucket-public-access-prevention-not-enforced': ['public_exposure'],
  'gcs-bucket-public-iam':                            ['public_exposure'],
  'gke-basic-auth-configured':                        ['iam_misconfiguration'],
  'gke-legacy-abac-enabled':                          ['iam_misconfiguration'],
  'gke-public-control-plane-no-authorized-networks':  ['public_exposure'],
};

// ── Cloud checks: check id → CIS Benchmark control ──────────────────────────
// CIS *Controls* (v8, above) are the vendor-agnostic 18-control list; CIS
// *Benchmarks* are the per-platform technical hardening guides (AWS/Azure/
// GCP) that a cloud audit actually cites for a specific finding — e.g. "CIS
// AWS Foundations Benchmark 3.1", not just "CIS 8". Unlike CATEGORY_CONTROLS
// (one mapping per internal risk category, shared across every check in
// that category), a Benchmark control is specific to one exact check, so
// this table is keyed by check id, not category.
//
// Each control number below was verified against the named benchmark
// version (not just recalled/guessed) — see FRAMEWORKS above for the
// pinned version. This is intentionally NOT a mapping for every check in
// CHECK_CATEGORY: a check with no entry here still gets its normal
// category-based frameworks (including CIS Controls v8) from
// getComplianceForCloudCheck, it just doesn't get an extra Benchmark
// control until one is verified and added. Treat a missing entry as "not
// yet mapped", not "this check has no Benchmark equivalent" — most of
// these do; this table just doesn't claim numbers nobody has checked.
const CIS_BENCHMARK_CONTROLS = {
  // AWS — CIS Amazon Web Services Foundations Benchmark v1.5.0
  'iam-no-password-policy':          { framework: 'cis_aws_foundations', control: '1.8',   title: 'Ensure IAM password policy requires minimum length of 14 or greater' },
  'iam-console-user-no-mfa':         { framework: 'cis_aws_foundations', control: '1.10',  title: 'Ensure MFA is enabled for all IAM users that have a console password' },
  'iam-access-key-not-rotated':      { framework: 'cis_aws_foundations', control: '1.14',  title: 'Ensure access keys are rotated every 90 days or less' },
  'iam-policy-full-admin':           { framework: 'cis_aws_foundations', control: '1.16',  title: 'Ensure IAM policies that allow full "*:*" administrative privileges are not attached' },
  's3-encryption-disabled':          { framework: 'cis_aws_foundations', control: '2.1.1', title: 'Ensure all S3 buckets employ encryption-at-rest' },
  's3-acl-public':                   { framework: 'cis_aws_foundations', control: '2.1.5', title: "Ensure that S3 Buckets are configured with 'Block public access (bucket settings)'" },
  's3-acl-authenticated-users':      { framework: 'cis_aws_foundations', control: '2.1.5', title: "Ensure that S3 Buckets are configured with 'Block public access (bucket settings)'" },
  's3-policy-public':                { framework: 'cis_aws_foundations', control: '2.1.5', title: "Ensure that S3 Buckets are configured with 'Block public access (bucket settings)'" },
  's3-public-access-block':          { framework: 'cis_aws_foundations', control: '2.1.5', title: "Ensure that S3 Buckets are configured with 'Block public access (bucket settings)'" },
  's3-object-acl-public-sample':     { framework: 'cis_aws_foundations', control: '2.1.5', title: "Ensure that S3 Buckets are configured with 'Block public access (bucket settings)'" },
  'ebs-default-encryption-disabled': { framework: 'cis_aws_foundations', control: '2.2.1', title: 'Ensure EBS Volume Encryption is Enabled in all Regions' },
  'ebs-volume-not-encrypted':        { framework: 'cis_aws_foundations', control: '2.2.1', title: 'Ensure EBS Volume Encryption is Enabled in all Regions' },
  'rds-publicly-accessible':         { framework: 'cis_aws_foundations', control: '2.3.3', title: 'Ensure that public access is not given to RDS Instance' },
  'cloudtrail-no-multiregion-trail': { framework: 'cis_aws_foundations', control: '3.1',   title: 'Ensure CloudTrail is enabled in all regions' },
  'cloudtrail-logging-stopped':      { framework: 'cis_aws_foundations', control: '3.1',   title: 'Ensure CloudTrail is enabled in all regions' },
  'cloudtrail-log-validation-disabled': { framework: 'cis_aws_foundations', control: '3.2', title: 'Ensure CloudTrail log file validation is enabled' },
  'cloudtrail-not-kms-encrypted':    { framework: 'cis_aws_foundations', control: '3.7',   title: 'Ensure CloudTrail logs are encrypted at rest using KMS CMKs' },
  'vpc-flow-logs-disabled':          { framework: 'cis_aws_foundations', control: '3.9',   title: 'Ensure VPC flow logging is enabled in all VPCs' },
  'sg-open-sensitive-port':          { framework: 'cis_aws_foundations', control: '5.2',   title: 'Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports' },

  // Azure — CIS Microsoft Azure Foundations Benchmark v2.0.0
  'azure-storage-outdated-tls':          { framework: 'cis_azure_foundations', control: '3.15', title: "Ensure the 'Minimum TLS version' for storage accounts is set to 'Version 1.2'" },
  'azure-storage-container-public-access': { framework: 'cis_azure_foundations', control: '3.7', title: "Ensure that 'Public access level' is disabled for storage accounts with blob containers" },
  'azure-storage-public-blob-access':    { framework: 'cis_azure_foundations', control: '3.7',  title: "Ensure that 'Public access level' is disabled for storage accounts with blob containers" },
  'azure-keyvault-purge-protection-disabled': { framework: 'cis_azure_foundations', control: '8.5', title: 'Ensure the Key Vault is Recoverable' },
  'azure-keyvault-public-network-access': { framework: 'cis_azure_foundations', control: '8.7', title: 'Ensure that Private Endpoints are used for Azure Key Vault' },

  // GCP — CIS Google Cloud Platform Foundation Benchmark v1.3.0
  'cloudsql-ssl-not-required':          { framework: 'cis_gcp_foundations', control: '6.4', title: 'Ensure that the Cloud SQL database instance requires all incoming connections to use SSL' },
  'cloudsql-authorized-network-open':   { framework: 'cis_gcp_foundations', control: '6.5', title: 'Ensure that Cloud SQL database instances do not implicitly whitelist all public IP addresses' },
  'cloudsql-public-ip-enabled':         { framework: 'cis_gcp_foundations', control: '6.6', title: 'Ensure that Cloud SQL database instances do not have public IPs' },
  'gcp-fw-open-sensitive-port':         { framework: 'cis_gcp_foundations', control: '3.6 / 3.7', title: 'Ensure that SSH / RDP access is restricted from the Internet (most directly applicable to the port-22/3389 case; other sensitive ports in this finding are covered only by analogy)' },
};

// ── Core builder ─────────────────────────────────────────────────────────────

/**
 * Given a list of category keys, build the { categories, frameworks } shape
 * attached to a finding as `finding.compliance`. Frameworks are deduplicated
 * and merged across categories; controls are deduplicated within a
 * framework.
 */
function buildCompliance(categories) {
  const cats = [...new Set((categories || []).filter(c => CATEGORY_CONTROLS[c]))];
  if (!cats.length) return null;

  const byFramework = new Map(); // frameworkId -> Map(controlId -> title)
  for (const cat of cats) {
    for (const entry of CATEGORY_CONTROLS[cat]) {
      if (!byFramework.has(entry.framework)) byFramework.set(entry.framework, new Map());
      const controls = byFramework.get(entry.framework);
      // Keyed by framework:control (the nesting above already scopes this
      // Map to one framework, so `entry.control` alone is the composite
      // key). First title wins and is never silently overwritten by a
      // later category that happens to reference the same control — two
      // categories citing the same control with differently-worded titles
      // would otherwise flip which title shows depending on category
      // iteration order, which is exactly the kind of footgun that isn't
      // wrong today but would be an invisible, order-dependent bug the
      // first time it happened.
      if (!controls.has(entry.control)) controls.set(entry.control, entry.title);
    }
  }

  const frameworks = [...byFramework.entries()].map(([id, controls]) => ({
    id,
    name: FRAMEWORKS[id]?.name || id,
    version: FRAMEWORKS[id]?.version ?? null,
    controls: [...controls.entries()].map(([id2, title]) => ({ id: id2, title })),
  }));

  return { categories: cats, frameworks };
}

/**
 * Attach one extra framework/control to an already-built compliance object
 * — used for CIS Benchmark controls, which are looked up per check id
 * (CIS_BENCHMARK_CONTROLS) rather than per category (CATEGORY_CONTROLS),
 * so they can't just be folded into buildCompliance's category loop above.
 * `compliance` may be null (a finding with no category-based mapping at
 * all); this still attaches the benchmark control in that case rather than
 * silently dropping it. Never mutates its input.
 */
function addBenchmarkControl(compliance, entry) {
  const base = compliance || { categories: [], frameworks: [] };
  const frameworks = base.frameworks.map(fw => ({ ...fw, controls: [...fw.controls] }));
  const controlObj = { id: entry.control, title: entry.title };

  const idx = frameworks.findIndex(fw => fw.id === entry.framework);
  if (idx === -1) {
    frameworks.push({
      id: entry.framework,
      name: FRAMEWORKS[entry.framework]?.name || entry.framework,
      version: FRAMEWORKS[entry.framework]?.version ?? null,
      controls: [controlObj],
    });
  } else if (!frameworks[idx].controls.some(c => c.id === controlObj.id)) {
    frameworks[idx].controls.push(controlObj);
  }

  return { categories: base.categories, frameworks };
}

/** Normalize a CWE array (ints or "CWE-89" strings) to plain ints. */
function normalizeCwes(cwes) {
  return (Array.isArray(cwes) ? cwes : [])
    .map(c => (typeof c === 'number' ? c : parseInt(String(c).replace(/^CWE-/i, ''), 10)))
    .filter(n => Number.isInteger(n));
}

// ── Public API: SCA ──────────────────────────────────────────────────────────

/**
 * Compliance mapping for an SCA dependency finding (known-vulnerable
 * component from OSV/NVD, or a supply-chain infection). Every such finding
 * is at minimum a `vulnerable_components` risk; `is_infection` findings are
 * additionally `malicious_code_supply_chain`, and any CWE the advisory
 * carries adds its own more specific category on top.
 */
function getComplianceForVulnerability(cwes, isInfection) {
  const categories = new Set(isInfection ? ['malicious_code_supply_chain'] : ['vulnerable_components']);
  for (const cwe of normalizeCwes(cwes)) {
    const cat = CWE_CATEGORY[cwe];
    if (cat) categories.add(cat);
  }
  return buildCompliance([...categories]);
}

/** Compliance mapping for a secrets-in-source finding — always secrets_management. */
function getComplianceForSecret() {
  return buildCompliance(['secrets_management']);
}

// ── Public API: SAST ─────────────────────────────────────────────────────────

/**
 * Compliance mapping for a ubel-sast finding, looked up by the finding's
 * (already-normalized, CWE-suffix-stripped) `vuln_class` string.
 *
 * If the class name isn't in the catalog (e.g. an older report, or a
 * custom/LLM vuln class outside vulnCatalog.js) and the caller separately
 * has CWE numbers for the finding, those are used as a fallback instead.
 * The SAST analyzer doesn't emit CWEs independently of `vuln_class` today
 * (see vulnCatalog.js: "cwe — primary CWE for reference, not emitted in
 * output"), so `cwes` will typically be omitted and this falls through to
 * null — which is the honest answer, not a guess.
 *
 * (This replaces a previous fallback that searched every known SAST class's
 * CWE numbers for a substring match against `key`. `key` is a prose class
 * name, never a bare CWE number, so that search could never match anything
 * a real finding would produce — it looked defensive but was dead code.)
 */
function getComplianceForSastFinding(vulnClass, cwes) {
  const key = String(vulnClass || '').toLowerCase().trim();
  const entry = SAST_CLASS_COMPLIANCE[key];
  if (entry) return buildCompliance([entry.category]);

  if (cwes && cwes.length) {
    const categories = new Set();
    for (const cwe of normalizeCwes(cwes)) {
      const cat = CWE_CATEGORY[cwe];
      if (cat) categories.add(cat);
    }
    if (categories.size) return buildCompliance([...categories]);
  }
  return null;
}

/** CWE array for a SAST vuln_class — replaces the old partial per-file tables. */
function getCwesForSastClass(vulnClass) {
  const key = String(vulnClass || '').toLowerCase().trim();
  return (SAST_CLASS_COMPLIANCE[key] || {}).cwes || [];
}

/** Compliance mapping for a ubel-mal (malicious-code) finding — always malicious_code_supply_chain. */
function getComplianceForMalwareFinding() {
  return buildCompliance(['malicious_code_supply_chain']);
}

/** CWE array for a malware vuln_class, mirroring getCwesForSastClass. */
function getCwesForMalwareClass(vulnClass) {
  const key = String(vulnClass || '').toLowerCase().trim();
  return MALWARE_CLASS_CWE[key] || [506];
}

// ── Public API: cloud ────────────────────────────────────────────────────────

/** Compliance mapping for a cloud-scanner finding, looked up by its `check` id. */
function getComplianceForCloudCheck(checkId) {
  const categories = CHECK_CATEGORY[checkId];
  const compliance = buildCompliance(categories || ['security_misconfiguration']);
  const benchmarkEntry = CIS_BENCHMARK_CONTROLS[checkId];
  return benchmarkEntry ? addBenchmarkControl(compliance, benchmarkEntry) : compliance;
}

// ── Public API: report-level summaries ───────────────────────────────────────

/**
 * Aggregate a list of `compliance` objects (as attached to individual
 * findings — one entry per finding, `null` for an unmapped finding, in
 * both cases) into a report-level summary: per-framework finding counts +
 * per-control finding counts, a per-category breakdown, an OWASP-Top-10
 * rollup, and overall mapping coverage.
 *
 * `complianceList` is expected to have one entry per finding the report
 * covers (including `null` for findings that didn't map to anything) —
 * every call site in this codebase already builds it that way — so its
 * length doubles as the report's total finding count for the coverage
 * stat below.
 */
function summarizeCompliance(complianceList) {
  const frameworkAgg = new Map(); // id -> { name, version, findings_count, controls: Map(controlId -> {title, count}) }
  const byCategory = {};
  // OWASP Top 10 is the rollup auditors ask for first, and it's also the
  // one place two of our internal categories can legitimately land on the
  // same headline risk: `cryptography` and `secrets_management` are
  // different CATEGORY_CONTROLS entries (so they read as unrelated in
  // by_category), but OWASP files both under A02:2021 "Cryptographic
  // Failures". Grouping by the *OWASP control* instead of the internal
  // category surfaces that overlap instead of splitting it across two
  // rows that don't obviously belong together.
  const byOwaspAgg = new Map(); // controlId -> { title, findings_count, categories: Set }
  let mappedFindings = 0;

  for (const c of complianceList) {
    if (!c) continue;
    mappedFindings++;
    for (const cat of c.categories || []) {
      byCategory[cat] = (byCategory[cat] || 0) + 1;
    }
    for (const fw of c.frameworks || []) {
      if (!frameworkAgg.has(fw.id)) {
        frameworkAgg.set(fw.id, { name: fw.name, version: fw.version ?? null, findings_count: 0, controls: new Map() });
      }
      const agg = frameworkAgg.get(fw.id);
      agg.findings_count++;
      for (const ctrl of fw.controls || []) {
        if (!agg.controls.has(ctrl.id)) agg.controls.set(ctrl.id, { title: ctrl.title, findings_count: 0 });
        agg.controls.get(ctrl.id).findings_count++;
      }

      if (fw.id === 'owasp_top10_2021') {
        for (const ctrl of fw.controls || []) {
          if (!byOwaspAgg.has(ctrl.id)) {
            byOwaspAgg.set(ctrl.id, { title: ctrl.title, findings_count: 0, categories: new Set() });
          }
          const o = byOwaspAgg.get(ctrl.id);
          o.findings_count++;
          for (const cat of c.categories || []) {
            const ownsThisControl = (CATEGORY_CONTROLS[cat] || [])
              .some(entry => entry.framework === 'owasp_top10_2021' && entry.control === ctrl.id);
            if (ownsThisControl) o.categories.add(cat);
          }
        }
      }
    }
  }

  const frameworks = [...frameworkAgg.entries()]
    .map(([id, agg]) => ({
      id,
      name: agg.name,
      version: agg.version,
      findings_count: agg.findings_count,
      controls: [...agg.controls.entries()]
        .map(([id2, v]) => ({ id: id2, title: v.title, findings_count: v.findings_count }))
        .sort((a, b) => b.findings_count - a.findings_count),
    }))
    .sort((a, b) => b.findings_count - a.findings_count);

  const byOwaspCategory = [...byOwaspAgg.entries()]
    .map(([id, v]) => ({ id, title: v.title, findings_count: v.findings_count, categories: [...v.categories] }))
    .sort((a, b) => b.findings_count - a.findings_count);

  const totalFindings = complianceList.length;
  return {
    disclaimer: COMPLIANCE_DISCLAIMER,
    frameworks,
    by_category: byCategory,
    by_owasp_category: byOwaspCategory,
    coverage: {
      mapped_findings: mappedFindings,
      total_findings: totalFindings,
      coverage_pct: totalFindings ? Math.round((mappedFindings / totalFindings) * 1000) / 10 : null,
    },
  };
}

export {
  FRAMEWORKS,
  COMPLIANCE_DISCLAIMER,
  getComplianceForVulnerability,
  getComplianceForSecret,
  getComplianceForSastFinding,
  getCwesForSastClass,
  getComplianceForMalwareFinding,
  getCwesForMalwareClass,
  getComplianceForCloudCheck,
  summarizeCompliance,
  findCategoryDivergences,
  CIS_BENCHMARK_CONTROLS,
};
