'use strict';
// rules.js — the rule catalog of ubel-package, registered into the shared mobile rule table (mobile/lib/rules.js) so that Findings, the report,
// the gate and the diff treat package findings like every other UBEL finding. Importing this module is what registers them.
//
// masvs = the AREA the finding is filed under in the report (there is no MASVS control for a dependency package):
//   PKG-INSTALL    code that runs on the consumer's machine because the package was installed, built against or imported
//   PKG-CODE       what the package's source does (malware patterns)
//   PKG-DEPS       dependencies: pinning, source, advisories, bundled copies
//   PKG-INTEGRITY  was the archive the registry's archive, is the metadata the archive's metadata, is the archive safe to unpack
//   PKG-CONTENT    files that do not belong in a package; build / tool configuration

import { RULES } from '../../mobile/lib/rules.js';

const R = (severity, title, area, cwe, remediation) => ({ severity, title, masvs: area, cwe, remediation });
const I = 'PKG-INSTALL', C = 'PKG-CODE', D = 'PKG-DEPS', G = 'PKG-INTEGRITY', F = 'PKG-CONTENT';
const REVIEW = 'Do not install this release until the code has been reviewed. If it is already installed, treat the machine as exposed: rotate the credentials reachable from it, and pin an earlier, reviewed version.';
const IGNORE = 'Install with the package manager\'s "ignore scripts" mode (npm: --ignore-scripts; pip: --only-binary :all:; cargo: vendor and review build.rs; gem: --no-document and review extensions) unless the hook is required, and review the hook.';

export const PACKAGE_RULES = {
  // ── install-time and build-time hooks ─────────────────────────────────────────────────────────────────────────────────────────
  'package.install.hook':               R('low',      'Package runs code when it is installed or built', I, 506, IGNORE),
  'package.install.native_build':       R('info',     'Package compiles native code on the consumer machine', I, 506, 'Prefer a prebuilt binary from the registry where one exists, and make sure the build toolchain and its configuration are trusted.'),
  'package.install.download_exec':      R('critical', 'Install-time code downloads and runs a program', I, 494, REVIEW),
  'package.install.remote_fetch':       R('medium',   'Install-time code contacts a remote host', I, 829, 'An install should not need the network beyond the registry. If a download is required, it must be pinned to a digest and fetched over HTTPS; otherwise remove it.'),
  'package.install.runtime_install':    R('high',     'Install-time code installs further packages', I, 829, 'Packages installed by an install script are outside the lockfile, the advisory check and the pin review. Declare them as dependencies instead.'),
  'package.install.shell_exec':         R('medium',   'Install-time code runs an inline shell or interpreter command', I, 78, 'Move the logic into a reviewed script file, or remove it.'),
  'package.install.credential_access':  R('critical', 'Install-time code reads credentials or the environment', I, 522, REVIEW),
  'package.install.persistence':        R('critical', 'Install-time code sets up something that survives the install', I, 506, REVIEW),
  'package.install.destructive':        R('critical', 'Install-time code deletes or overwrites files broadly', I, 912, REVIEW),
  'package.install.privilege':          R('high',     'Install-time code changes privileges or permissions', I, 269, 'An install must not need sudo, setuid or world-writable files. Review and remove.'),
  'package.install.obfuscated':         R('critical', 'Install-time code contains an encoded or obfuscated payload', I, 506, REVIEW),
  'package.install.reverse_shell':      R('critical', 'Install-time code opens a reverse shell', I, 506, REVIEW),
  'package.install.crypto_mining':      R('critical', 'Install-time code refers to a cryptocurrency miner', I, 506, REVIEW),
  'package.install.exfiltration':       R('critical', 'Install-time code collects secrets and has network access', I, 200, REVIEW),
  'package.install.insecure_tls':       R('high',     'Install-time code switches TLS certificate verification off', I, 295, 'Never disable certificate verification in an installer; fix the trust problem instead.'),
  'package.install.pth_file':           R('high',     'Python .pth / sitecustomize file runs code at every interpreter start', I, 506, 'Only a path list belongs in a .pth file. Remove `import` lines and sitecustomize modules, or avoid this package.'),

  // ── source behaviour (outside install-time code) ──────────────────────────────────────────────────────────────────────────────
  'package.code.obfuscated':            R('medium',   'Source contains encoded, packed or obfuscated code', C, 506, 'Ask for readable source or build the package from its repository; obfuscation in a dependency hides what it does.'),
  'package.code.reverse_shell':         R('critical', 'Source contains a reverse-shell construct', C, 506, REVIEW),
  'package.code.credential_access':     R('high',     'Source reads credential stores or the whole environment', C, 522, 'A library has no reason to read SSH keys, cloud tokens, browser profiles or every environment variable. Review where the data goes.'),
  'package.code.exfiltration':          R('high',     'Source collects secrets and has network access in the same file', C, 200, 'Review the file: it can read credentials and send data out. Treat as malicious until shown otherwise.'),
  'package.code.persistence':           R('medium',   'Source refers to autostart, scheduler or shell-profile locations', C, 506, 'A library should not write to startup locations. Review the code that does.'),
  'package.code.download_exec':         R('high',     'Source downloads and runs a program', C, 494, 'Remove run-time download-and-execute, or pin the download to a digest.'),
  'package.code.insecure_tls':          R('medium',   'Source switches TLS certificate verification off', C, 295, 'Enable certificate verification.'),
  'package.code.crypto_mining':         R('high',     'Source refers to a cryptocurrency miner', C, 506, REVIEW),
  'package.code.destructive':           R('medium',   'Source contains a destructive command', C, 912, 'Review the command and the path it can reach.'),

  // ── dependencies ──────────────────────────────────────────────────────────────────────────────────────────────────────────────
  'package.dep.unpinned':               R('low',      'Dependencies are not bounded to a version', D, 1357, 'Declare a bounded range or an exact version; pin the resolved versions in a lockfile that is checked in.'),
  'package.dep.range':                  R('info',     'Dependencies are declared as version ranges', D, 1357, 'A range lets a new release change what is installed. Use a lockfile and review upgrades.'),
  'package.dep.non_registry':           R('medium',   'Dependencies come from outside the registry', D, 829, 'Publish the dependency to the registry, or pin the git revision / URL to an immutable commit or digest.'),
  'package.dep.vulnerable':             R('medium',   'Dependency has a known vulnerability', D, 1395, 'Update the dependency to a fixed version.'),
  'package.dep.malicious':              R('critical', 'Dependency is a known malicious package', D, 506, 'Remove the dependency. Treat every machine that installed it as compromised: rotate credentials, and review what it ran.'),
  'package.dep.bundled':                R('info',     'Package ships bundled copies of other packages', D, 1104, 'Bundled copies are not updated when the registry copy is fixed; check them against advisories.'),
  'package.vulnerable':                 R('medium',   'This package version has a known vulnerability', D, 1395, 'Upgrade to a fixed version.'),
  'package.malicious':                  R('critical', 'This package version is a known malicious package', D, 506, 'Do not install it. If it is installed, treat the machine as compromised: rotate credentials, and review what it ran.'),

  // ── integrity, metadata, archive ──────────────────────────────────────────────────────────────────────────────────────────────
  'package.integrity.mismatch':         R('critical', 'Downloaded archive does not match the registry\'s digest', G, 354, 'Do not use the archive. Re-download over a trusted network and compare; a persistent mismatch means the registry, a proxy or the cache serves different bytes than it published.'),
  'package.integrity.unverified':       R('low',      'Downloaded archive could not be verified against a published digest', G, 353, 'Verify it with another source (the lockfile digest, a second mirror) before relying on it.'),
  'package.manifest_confusion':         R('high',     'Registry manifest differs from the manifest inside the tarball', G, 345, 'The registry shows one set of scripts and dependencies, the tarball runs another. Do not install it: this is how install-time code is hidden from dependency tools.'),
  'package.metadata.yanked':            R('medium',   'Release has been yanked / retracted', G, 1104, 'The publisher withdrew this release. Move to a supported version.'),
  'package.metadata.deprecated':        R('low',      'Release or package is deprecated', G, 1104, 'Move to the replacement named in the deprecation message.'),
  'package.metadata.name_mismatch':     R('medium',   'Archive metadata does not match the requested package', G, 345, 'The name, version or manifest inside the archive is not what the registry served. Investigate before installing.'),
  'package.archive.path_traversal':     R('high',     'Archive entry writes outside the install directory', G, 22, 'Do not extract this archive with a tool that does not sanitise paths.'),
  'package.archive.symlink_escape':     R('high',     'Archive contains a link that points outside the package', G, 59, 'Do not extract this archive with a tool that follows links.'),
  'package.archive.special_file':       R('medium',   'Archive contains a device node or FIFO', G, 749, 'A package has no reason to carry device files.'),
  'package.archive.setuid':             R('high',     'Archive contains a setuid / setgid file', G, 269, 'A package must not ship setuid files.'),
  'package.archive.world_writable':     R('low',      'Archive contains world-writable files or directories', G, 732, 'Ship files with ordinary permissions.'),
  'package.archive.duplicate_entry':    R('low',      'Archive lists the same path more than once', G, 694, 'Which copy an extractor keeps differs between tools; the archive may show a different file to a scanner than to an installer.'),

  // ── content and tool configuration ────────────────────────────────────────────────────────────────────────────────────────────
  'package.files.disguised_binary':     R('high',     'Native executable hidden under a non-binary file name', F, 434, 'A compiled program named like text, an image or a script is not an accident. Review it.'),
  'package.files.native_binary':        R('info',     'Package ships native binaries', F, 1104, 'Prebuilt binaries cannot be reviewed as source; prefer packages that build from source or publish provenance.'),
  'package.files.sensitive':            R('medium',   'Package ships a file that normally holds secrets or private keys', F, 540, 'Remove the file from the package and rotate anything it contained.'),
  'package.files.nested_archive':       R('low',      'Package contains an archive inside the archive', F, 1104, 'Nested archives are not unpacked by dependency tools and hide content from review.'),
  'package.files.compiled_code':        R('low',      'Package ships compiled bytecode that no source in the package explains', F, 656, 'Bytecode (.pyc, .class) without its source cannot be reviewed.'),
  'package.config.insecure_registry':   R('medium',   'Package metadata refers to an unencrypted HTTP source', F, 319, 'Use HTTPS for every registry, repository and download URL.'),
  'package.config.tool_config':         R('low',      'Package ships package-manager or build-tool configuration', F, 15, 'Configuration files of the package manager do not belong in a published package; remove them.'),
};

Object.assign(RULES, PACKAGE_RULES);
export const PACKAGE_RULE_IDS = Object.keys(PACKAGE_RULES);
