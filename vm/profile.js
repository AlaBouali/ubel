'use strict';
// profile.js — labels and area descriptions of ubel-vm, embedded in every report (see lib/html_report.js).

export const VM_PROFILE = {
  key: 'vm',
  tool: 'vm-scanner',
  title: 'VM Hardening Report',
  exec_title: 'Virtual Machine Security Posture — Executive Summary',
  logo: 'V',
  subject_noun: 'machine',
  scope_label: 'Scope',
  scopes_label: 'Scopes',
  statement: 'Produced by a read-only review of the machine\'s own configuration files, kernel settings and listening sockets, by a process running on (or pointed at the disk image of) that machine. It reflects the state of the machine at the time of the scan.',
  scope_description: 'ubel-vm audits a Linux virtual machine or server against a hardening baseline: SSH, accounts and authentication, file permissions, kernel parameters, network exposure, services, logging and credentials stored on disk — and, when the machine is a Kubernetes node, the node-level Kubernetes hardening checks (control-plane and kubelet files, etcd data directory, kubelet configuration). It reads files and /proc and /sys only; it does not run any command, install anything or change the machine.',
  discovery: 'The machine is either the host the tool runs on, or a mounted disk image / extracted root filesystem passed with --root. Checks that need a running kernel (live sysctl values, listening sockets, CPU mitigations) are marked not applicable for an offline root.',
  method_steps: [
    { step: 'Read the configuration', detail: 'Operating-system release, SSH, PAM, sudo, account databases, systemd units, cron, mounts and sysctl settings are read directly from files. On a live host the running kernel parameters, listening sockets and CPU-vulnerability status are read from /proc and /sys.' },
    { step: 'Evaluate each check', detail: 'Every check in the baseline reports one of four outcomes: passed, failed, not applicable (the feature is not installed or needs a live host) or not assessed (it applies but could not be evaluated, for example permission denied).' },
    { step: 'Look up installed packages (SCA engine)', detail: 'The SCA engine scans the machine: its platform mode reads the package database (dpkg, apk, rpm) from disk and checks every operating-system package against OSV.dev for its release, its full-stack scan reads the application packages (npm, Python, Composer, Bundler, Cargo, Go, …) under the application directories, and for a mounted root its docker mode does both, as ubel-docker does for an image. Advisories for other releases or already fixed in the installed build are dropped, and CISA KEV / FIRST EPSS data is attached. Findings are SCA vulnerabilities (sc_vuln / sc_infection) and open in the SCA vulnerability view. A scan that cannot be completed is reported as not assessed.' },
    { step: 'Walk the filesystem once', detail: 'A single pass over the filesystem collects world-writable files and directories and set-uid / set-gid programs. Virtual and network filesystems are skipped.' },
    { step: 'Map to compliance frameworks', detail: 'Each check is mapped to controls of NIST SP 800-53, PCI DSS, ISO/IEC 27001, SOC 2, CIS Controls and others; findings inherit the mapping of their check.' },
    { step: 'Compare with the previous scan', detail: 'The Diffs tab lists findings that are new, still present or fixed since the previous report of the same machine, ignoring checks that were not evaluated both times.' },
  ],
  limitations: [
    'Only Linux machines are audited. Windows and macOS guests are not covered; a Linux image can be audited from any operating system with --root.',
    'The tool reads configuration and matches installed packages against OSV.dev advisories; it does not test whether a service is exploitable, and software that is neither in the package database nor in a scanned application directory (a statically linked binary, a vendored copy) is not seen by the package checks.',
    'Without root privileges some files (/etc/shadow, /etc/sudoers, other users\' homes) cannot be read; the checks that need them are reported as not assessed.',
    'Listening-port findings describe the host\'s own sockets; whether a port is reachable from the internet also depends on firewalls and security groups outside the machine.',
  ],
  glossary: [
    { term: 'Hardening', meaning: 'Changing a system\'s configuration to remove unnecessary risk, without adding new software.' },
    { term: 'Set-uid program', meaning: 'A program that runs with its owner\'s privileges (often root) whoever starts it; a classic privilege-escalation route.' },
    { term: 'sysctl', meaning: 'Run-time settings of the Linux kernel, for example whether memory addresses are randomised.' },
  ],
  areas: {
    os: { label: 'Operating system', plain: 'Whether the operating-system release is still supported and updates and package signatures are handled safely.', owner: 'Infrastructure / platform team' },
    ssh: { label: 'SSH remote access', plain: 'How administrators log in remotely: root login, passwords, algorithms and key files.', owner: 'Infrastructure / platform team' },
    accounts: { label: 'Accounts & authentication', plain: 'User accounts, passwords, sudo rights and login (PAM) policy.', owner: 'Infrastructure / identity team' },
    filesystem: { label: 'Files & permissions', plain: 'Who can read or change sensitive files, scheduled jobs and privileged programs.', owner: 'Infrastructure / platform team' },
    kernel: { label: 'Kernel & hardening', plain: 'Kernel protections against memory-corruption and network attacks, CPU mitigations and mandatory access control.', owner: 'Infrastructure / platform team' },
    network: { label: 'Network exposure', plain: 'Which services listen on the network and whether a host firewall is in place.', owner: 'Network / infrastructure team' },
    services: { label: 'Services & software', plain: 'Obsolete or unnecessary services and the exposure of the container runtime.', owner: 'Infrastructure / platform team' },
    logging: { label: 'Logging & time', plain: 'Whether security-relevant events are recorded and clocks are synchronised.', owner: 'Security operations' },
    secrets: { label: 'Stored credentials', plain: 'Private keys and access tokens left in plain text on disk.', owner: 'Application owners / security team' },
    kubernetes: { label: 'Kubernetes node', plain: 'When the machine is a Kubernetes node: permissions of the cluster\'s files and keys, the etcd data directory and the kubelet\'s own configuration (node-level Kubernetes hardening).', owner: 'Platform / cluster operators' },
    packages: { label: 'Installed packages', plain: 'Known vulnerabilities (OSV.dev, through the SCA engine) in the operating-system packages and the application packages (npm, Python, Composer, …) installed on the machine.', owner: 'Infrastructure / platform team' },
    boot: { label: 'Boot loader', plain: 'Protection of the boot process against tampering from the console.', owner: 'Infrastructure / platform team' },
  },
};
