'use strict';
// rules.js — the rule catalog of ubel-package, registered into the shared mobile rule table (mobile/lib/rules.js) so that Findings, the report,
// the gate and the diff treat package findings like every other UBEL finding. Importing this module is what registers them.
//
// masvs = the AREA the finding is filed under in the report (there is no MASVS control for a dependency package):
//   PKG-INSTALL    code that runs on the consumer's machine because the package was installed, built against or imported
//   PKG-CODE       what the package's source does (static analysis findings: vulnerabilities and malicious code)
//   PKG-DEPS       dependencies: pinning, source, advisories, bundled copies
//   PKG-INTEGRITY  was the archive the registry's archive, is the metadata the archive's metadata, is the archive safe to unpack
//   PKG-CONTENT    files that do not belong in a package; build / tool configuration

import { RULES } from '../../mobile/lib/rules.js';
import { TYPES } from '../../canonical/types.js';

// The last argument is the rule's canonical finding type (canonical/types.js). The install-time signals follow one rule: hostile ones
// (download-and-run, credential access, reverse shell, miner, persistence, destructive, encoded payload, exfiltration) are `mal`; what an
// ordinary package may legitimately do at install (a hook, a native build, a download, an install, an inline shell) is `behavior`.
const R = (severity, title, area, cwe, remediation, type) => ({ severity, title, masvs: area, cwe, remediation, type });
const I = 'PKG-INSTALL', C = 'PKG-CODE', D = 'PKG-DEPS', G = 'PKG-INTEGRITY', F = 'PKG-CONTENT';
const REVIEW = 'Do not install this release until the code has been reviewed. If it is already installed, treat the machine as exposed: rotate the credentials reachable from it, and pin an earlier, reviewed version.';
const IGNORE = 'Install with the package manager\'s "ignore scripts" mode (npm: --ignore-scripts; pip: --only-binary :all:; cargo: vendor and review build.rs; gem: --no-document and review extensions) unless the hook is required, and review the hook.';

export const PACKAGE_RULES = {
  // ── install-time and build-time hooks ─────────────────────────────────────────────────────────────────────────────────────────
  'package.install.hook':               R('low',      'Package runs code when it is installed or built', I, 506, IGNORE, TYPES.BEHAVIOR),
  'package.install.native_build':       R('info',     'Package compiles native code on the consumer machine', I, 506, 'Prefer a prebuilt binary from the registry where one exists, and make sure the build toolchain and its configuration are trusted.', TYPES.BEHAVIOR),
  'package.install.download_exec':      R('critical', 'Install-time code downloads and runs a program', I, 494, REVIEW, TYPES.MAL),
  'package.install.remote_fetch':       R('medium',   'Install-time code contacts a remote host', I, 829, 'An install should not need the network beyond the registry. If a download is required, it must be pinned to a digest and fetched over HTTPS; otherwise remove it.', TYPES.BEHAVIOR),
  'package.install.runtime_install':    R('high',     'Install-time code installs further packages', I, 829, 'Packages installed by an install script are outside the lockfile, the advisory check and the pin review. Declare them as dependencies instead.', TYPES.BEHAVIOR),
  'package.install.shell_exec':         R('medium',   'Install-time code runs an inline shell or interpreter command', I, 78, 'Move the logic into a reviewed script file, or remove it.', TYPES.BEHAVIOR),
  'package.install.credential_access':  R('critical', 'Install-time code reads credentials or the environment', I, 522, REVIEW, TYPES.MAL),
  'package.install.persistence':        R('critical', 'Install-time code sets up something that survives the install', I, 506, REVIEW, TYPES.MAL),
  'package.install.destructive':        R('critical', 'Install-time code deletes or overwrites files broadly', I, 912, REVIEW, TYPES.MAL),
  'package.install.privilege':          R('high',     'Install-time code changes privileges or permissions', I, 269, 'An install must not need sudo, setuid or world-writable files. Review and remove.', TYPES.BEHAVIOR),
  'package.install.obfuscated':         R('critical', 'Install-time code contains an encoded or obfuscated payload', I, 506, REVIEW, TYPES.MAL),
  'package.install.reverse_shell':      R('critical', 'Install-time code opens a reverse shell', I, 506, REVIEW, TYPES.MAL),
  'package.install.crypto_mining':      R('critical', 'Install-time code refers to a cryptocurrency miner', I, 506, REVIEW, TYPES.MAL),
  'package.install.exfiltration':       R('critical', 'Install-time code collects secrets and has network access', I, 200, REVIEW, TYPES.MAL),
  'package.install.insecure_tls':       R('high',     'Install-time code switches TLS certificate verification off', I, 295, 'Never disable certificate verification in an installer; fix the trust problem instead.', TYPES.VULN),
  'package.install.pth_file':           R('high',     'Python .pth / sitecustomize file runs code at every interpreter start', I, 506, 'Only a path list belongs in a .pth file. Remove `import` lines and sitecustomize modules, or avoid this package.', TYPES.BEHAVIOR),

  // ── source behaviour ──────────────────────────────────────────────────────────────────────────────────────────────────────────
  // What the package's source does is judged by the static engines (package.sast.* and package.mal.*, registered below as they fire), not by
  // rules of this catalog. Only the remote-host finding stays here: it comes from the hosts the files name, not from a source pattern.
  'package.code.exfiltration':          R('high',     'Source collects secrets and has network access in the same file', C, 200, 'Review the file: it can read credentials and send data out. Treat as malicious until shown otherwise.', TYPES.MAL),

  // ── dependencies ──────────────────────────────────────────────────────────────────────────────────────────────────────────────
  'package.dep.unpinned':               R('low',      'Dependencies are not bounded to a version', D, 1357, 'Declare a bounded range or an exact version; pin the resolved versions in a lockfile that is checked in.', TYPES.MISCONFIG),
  'package.dep.range':                  R('info',     'Dependencies are declared as version ranges', D, 1357, 'A range lets a new release change what is installed. Use a lockfile and review upgrades.', TYPES.MISCONFIG),
  'package.dep.non_registry':           R('medium',   'Dependencies come from outside the registry', D, 829, 'Publish the dependency to the registry, or pin the git revision / URL to an immutable commit or digest.', TYPES.MISCONFIG),
  'package.dep.vulnerable':             R('medium',   'Dependency has a known vulnerability', D, 1395, 'Update the dependency to a fixed version.', TYPES.SC_VULN),
  'package.dep.malicious':              R('critical', 'Dependency is a known malicious package', D, 506, 'Remove the dependency. Treat every machine that installed it as compromised: rotate credentials, and review what it ran.', TYPES.SC_INFECTION),
  'package.dep.bundled':                R('info',     'Package ships bundled copies of other packages', D, 1104, 'Bundled copies are not updated when the registry copy is fixed; check them against advisories.', TYPES.MISCONFIG),
  'package.vulnerable':                 R('medium',   'This package version has a known vulnerability', D, 1395, 'Upgrade to a fixed version.', TYPES.SC_VULN),
  'package.malicious':                  R('critical', 'This package version is a known malicious package', D, 506, 'Do not install it. If it is installed, treat the machine as compromised: rotate credentials, and review what it ran.', TYPES.SC_INFECTION),

  // ── integrity, metadata, archive ──────────────────────────────────────────────────────────────────────────────────────────────
  'package.integrity.mismatch':         R('critical', 'Downloaded archive does not match the registry\'s digest', G, 354, 'Do not use the archive. Re-download over a trusted network and compare; a persistent mismatch means the registry, a proxy or the cache serves different bytes than it published.', TYPES.INTEGRITY),
  'package.integrity.unverified':       R('low',      'Downloaded archive could not be verified against a published digest', G, 353, 'Verify it with another source (the lockfile digest, a second mirror) before relying on it.', TYPES.INTEGRITY),
  'package.manifest_confusion':         R('high',     'Registry manifest differs from the manifest inside the tarball', G, 345, 'The registry shows one set of scripts and dependencies, the tarball runs another. Do not install it: this is how install-time code is hidden from dependency tools.', TYPES.INTEGRITY),
  'package.metadata.yanked':            R('medium',   'Release has been yanked / retracted', G, 1104, 'The publisher withdrew this release. Move to a supported version.', TYPES.MISCONFIG),
  'package.metadata.deprecated':        R('low',      'Release or package is deprecated', G, 1104, 'Move to the replacement named in the deprecation message.', TYPES.MISCONFIG),
  'package.metadata.name_mismatch':     R('medium',   'Archive metadata does not match the requested package', G, 345, 'The name, version or manifest inside the archive is not what the registry served. Investigate before installing.', TYPES.INTEGRITY),
  'package.archive.path_traversal':     R('high',     'Archive entry writes outside the install directory', G, 22, 'Do not extract this archive with a tool that does not sanitise paths.', TYPES.MISCONFIG),
  'package.archive.symlink_escape':     R('high',     'Archive contains a link that points outside the package', G, 59, 'Do not extract this archive with a tool that follows links.', TYPES.MISCONFIG),
  'package.archive.special_file':       R('medium',   'Archive contains a device node or FIFO', G, 749, 'A package has no reason to carry device files.', TYPES.MISCONFIG),
  'package.archive.setuid':             R('high',     'Archive contains a setuid / setgid file', G, 269, 'A package must not ship setuid files.', TYPES.MISCONFIG),
  'package.archive.world_writable':     R('low',      'Archive contains world-writable files or directories', G, 732, 'Ship files with ordinary permissions.', TYPES.MISCONFIG),
  'package.archive.duplicate_entry':    R('low',      'Archive lists the same path more than once', G, 694, 'Which copy an extractor keeps differs between tools; the archive may show a different file to a scanner than to an installer.', TYPES.INTEGRITY),

  // ── content and tool configuration ────────────────────────────────────────────────────────────────────────────────────────────
  'package.files.disguised_binary':     R('high',     'Native executable hidden under a non-binary file name', F, 434, 'A compiled program named like text, an image or a script is not an accident. Review it.', TYPES.MISCONFIG),
  'package.files.native_binary':        R('info',     'Package ships native binaries', F, 1104, 'Prebuilt binaries cannot be reviewed as source; prefer packages that build from source or publish provenance.', TYPES.MISCONFIG),
  'package.files.sensitive':            R('medium',   'Package ships a file that normally holds secrets or private keys', F, 540, 'Remove the file from the package and rotate anything it contained.', TYPES.MISCONFIG),
  'package.files.nested_archive':       R('low',      'Package contains an archive inside the archive', F, 1104, 'Nested archives are not unpacked by dependency tools and hide content from review.', TYPES.MISCONFIG),
  'package.files.compiled_code':        R('low',      'Package ships compiled bytecode that no source in the package explains', F, 656, 'Bytecode (.pyc, .class) without its source cannot be reviewed.', TYPES.MISCONFIG),
  'package.config.insecure_registry':   R('medium',   'Package metadata refers to an unencrypted HTTP source', F, 319, 'Use HTTPS for every registry, repository and download URL.', TYPES.MISCONFIG),
  'package.config.tool_config':         R('low',      'Package ships package-manager or build-tool configuration', F, 15, 'Configuration files of the package manager do not belong in a published package; remove them.', TYPES.MISCONFIG),
};

Object.assign(RULES, PACKAGE_RULES);
export const PACKAGE_RULE_IDS = Object.keys(PACKAGE_RULES);

// ── static source analysis (always on: the SAST and the malware engines, both without a model) ───────────────────────────────────
// The engines of `ubel-sast --no-llm` and `ubel-mal --no-llm` have hundreds of rules of their own (and the user's, with --rules-dir, for the SAST
// engine), so they are not listed here: each rule that fires is registered on first use as `package.sast.<engine rule id>` (a vulnerability;
// custom rules: `package.sast.custom.<id>`) or `package.mal.<engine rule id>` (malicious code), filed under PKG-CODE. The severity and title
// are the engine's; the CWE of a vulnerability comes from its class.
export const SAST_RULE_PREFIX = 'package.sast.';
export const MAL_RULE_PREFIX = 'package.mal.';
const SAST_REMEDIATION = 'Review the flagged line: fix the weakness in the package, or avoid the code path that reaches it. A finding here is a lead from static analysis, not proof that the package is exploitable in your use of it.';
export function registerSastRule(id, { severity, title, cwe }) {
  if (!RULES[id]) RULES[id] = R(severity, title, C, cwe ?? null, SAST_REMEDIATION, TYPES.VULN);
  return RULES[id];
}
export function registerMalRule(id, { severity, title, cwe }) {
  if (!RULES[id]) RULES[id] = R(severity, title, C, cwe ?? 506, REVIEW, TYPES.MAL);
  return RULES[id];
}
