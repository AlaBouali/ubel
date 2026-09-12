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
const FRAMEWORKS = {
  owasp_top10_2021:    'OWASP Top 10 (2021)',
  pci_dss_4_0:          'PCI DSS v4.0',
  hipaa_security_rule:  'HIPAA Security Rule',
  soc2:                 'SOC 2 (Trust Services Criteria)',
  iso_27001_2022:       'ISO/IEC 27001:2022 (Annex A)',
  nist_800_53_r5:       'NIST SP 800-53 Rev. 5',
  gdpr:                 'GDPR',
  cis_controls_v8:      'CIS Controls v8',
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
  943: 'injection', 1004: 'session_management', 1104: 'security_misconfiguration',
  1236: 'memory_safety', 1321: 'security_misconfiguration', 1333: 'availability_dos',
};

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
      byFramework.get(entry.framework).set(entry.control, entry.title);
    }
  }

  const frameworks = [...byFramework.entries()].map(([id, controls]) => ({
    id,
    name: FRAMEWORKS[id] || id,
    controls: [...controls.entries()].map(([id2, title]) => ({ id: id2, title })),
  }));

  return { categories: cats, frameworks };
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
 * (already-normalized, CWE-suffix-stripped) `vuln_class` string. Falls back
 * to a CWE-only lookup if the class name isn't in the catalog (e.g. an
 * older report, or a custom vuln class), then to null if nothing matches.
 */
function getComplianceForSastFinding(vulnClass) {
  const key = String(vulnClass || '').toLowerCase().trim();
  const entry = SAST_CLASS_COMPLIANCE[key];
  if (entry) return buildCompliance([entry.category]);

  // Fallback: try each known CWE for a coarse category match.
  for (const [, info] of Object.entries(SAST_CLASS_COMPLIANCE)) {
    if (info.cwes.some(c => key.includes(String(c)))) return buildCompliance([info.category]);
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
  return buildCompliance(categories || ['security_misconfiguration']);
}

// ── Public API: report-level summaries ───────────────────────────────────────

/**
 * Aggregate a list of `compliance` objects (as attached to individual
 * findings, `null`s allowed and skipped) into a report-level summary:
 * per-framework finding counts + per-control finding counts, plus a
 * per-category breakdown.
 */
function summarizeCompliance(complianceList) {
  const frameworkAgg = new Map(); // id -> { name, findings_count, controls: Map(controlId -> {title, count}) }
  const byCategory = {};

  for (const c of complianceList) {
    if (!c) continue;
    for (const cat of c.categories || []) {
      byCategory[cat] = (byCategory[cat] || 0) + 1;
    }
    for (const fw of c.frameworks || []) {
      if (!frameworkAgg.has(fw.id)) {
        frameworkAgg.set(fw.id, { name: fw.name, findings_count: 0, controls: new Map() });
      }
      const agg = frameworkAgg.get(fw.id);
      agg.findings_count++;
      for (const ctrl of fw.controls || []) {
        if (!agg.controls.has(ctrl.id)) agg.controls.set(ctrl.id, { title: ctrl.title, findings_count: 0 });
        agg.controls.get(ctrl.id).findings_count++;
      }
    }
  }

  const frameworks = [...frameworkAgg.entries()]
    .map(([id, agg]) => ({
      id,
      name: agg.name,
      findings_count: agg.findings_count,
      controls: [...agg.controls.entries()]
        .map(([id2, v]) => ({ id: id2, title: v.title, findings_count: v.findings_count }))
        .sort((a, b) => b.findings_count - a.findings_count),
    }))
    .sort((a, b) => b.findings_count - a.findings_count);

  return {
    disclaimer: COMPLIANCE_DISCLAIMER,
    frameworks,
    by_category: byCategory,
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
};
