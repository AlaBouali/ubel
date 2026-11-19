'use strict';
// profile.js — labels and area descriptions of ubel-runtime, embedded in every report (see lib/html_report.js).

export const RUNTIME_PROFILE = {
  key: 'runtime',
  tool: 'runtime-scanner',
  title: 'Runtime Scan Report',
  exec_title: 'Running Applications — Executive Summary',
  logo: 'R',
  subject_noun: 'host',
  scope_label: 'Where',
  scopes_label: 'Where',
  statement: 'Produced by a read-only inspection of the processes running on the machine at the time of the scan — /proc, the applications\' files on disk, and only when requested the container engine socket, a loopback HTTP probe and the Node.js inspector. It describes what was running then, not what was installed or configured.',
  scope_description: 'ubel-runtime assesses the software that is actually running on a Linux machine: how each process is confined (capabilities, seccomp, root, debug interfaces), what it exposes on the network, which libraries it has mapped (stale, injected, vulnerable), which npm packages and which Node.js release it is made of — and, with live inspection, which of those packages it has really loaded — credentials left in process environments and command lines, and the configuration of the running containers. It uses only Node.js built-ins: no third-party library and no external program.',
  discovery: 'Processes are discovered from /proc. By default every user-space process visible to the scanner is assessed; --pid, --name and --node-only narrow the scope. Containers are discovered through the engine\'s unix socket when it is present and readable.',
  method_steps: [
    { step: 'Take a snapshot of the processes', detail: 'Every process is read from /proc: command line, executable (and whether it was deleted or runs from memory), capabilities, seccomp, parent, namespaces, mapped files, open sockets. What cannot be read (other users\' processes without root) is counted and reported as not assessed, never as clean.' },
    { step: 'Evaluate each check', detail: 'Every check reports one of four outcomes: passed, failed, not applicable (for example no container engine on the machine, or --inspect not requested) or not assessed (it applies but could not be evaluated).' },
    { step: 'Resolve the software each process is made of', detail: 'For Node.js processes the application\'s package.json and node_modules (or package-lock.json) are read from disk; executables and the libraries outside the distribution\'s directories are read for embedded version banners, Go modules, Rust crates and bundled npm / Python packages. All lookups go through OSV.dev and NVD; a lookup that cannot be completed is reported as not assessed.' },
    { step: 'Optionally look inside Node.js processes (--inspect)', detail: 'With explicit consent, the V8 inspector of each Node.js process is opened (SIGUSR1, only when the process handles it), V8 replays the list of scripts it has compiled — ES modules included — and one read-only expression returns process.versions. That tells which installed packages are really loaded and which Node.js release and bundled libraries really run. The inspector is closed again afterwards.' },
    { step: 'Map to compliance frameworks', detail: 'Each check is mapped to controls of NIST SP 800-53, PCI DSS, ISO/IEC 27001, SOC 2, CIS Controls and others; findings inherit the mapping of their check.' },
    { step: 'Compare with the previous scan', detail: 'The Diffs tab lists findings that are new, still present or fixed since the previous report of the same machine. Findings are identified by program, not by process id, so restarting a service does not make its findings look new.' },
  ],
  limitations: [
    'Only Linux hosts are assessed; /proc is required. On any other platform every check is reported as not applicable.',
    'It is a snapshot: processes that start and finish between scans are not seen, and a finding describes the moment of the scan.',
    'Without root only the scanner user\'s own processes are fully readable; the rest are reported as not assessed. A kernel-level rootkit that hides processes from /proc cannot be detected from /proc.',
    'Package and library versions are read from files on disk. Where files changed after a process started, memory may differ (the stale-code and stale-library checks flag it).',
    'Live inspection runs one read-only expression inside the target process and makes it print a "Debugger listening" line to its standard error. It is limited to Node.js, and to processes that handle SIGUSR1.',
    'Whether a port is reachable from the internet also depends on firewalls and security groups outside the machine.',
  ],
  glossary: [
    { term: 'Runtime scan', meaning: 'An assessment of software while it is running, as opposed to a scan of its source code or its installation files.' },
    { term: 'Capability', meaning: 'One of the fine-grained privileges of the Linux root user (for example loading kernel modules); processes can hold some without being root.' },
    { term: 'seccomp', meaning: 'A Linux filter that limits which system calls a process may make, reducing what an attacker can do after taking it over.' },
    { term: 'Loaded package', meaning: 'A package whose code the running process has actually read into memory, as opposed to one that merely sits in node_modules.' },
    { term: 'Inspector', meaning: 'The debugging interface of Node.js (V8). It has no authentication, which is why it must never be reachable by untrusted users.' },
  ],
  areas: {
    processes: { label: 'Process hardening', plain: 'How the running processes are confined: root, capabilities, tracing, debug interfaces, programs run from deleted files, memory or temporary directories.', owner: 'Infrastructure / platform team' },
    exposure: { label: 'Network exposure', plain: 'What the running applications accept connections on, and which sensitive endpoints they answer on.', owner: 'Network / infrastructure team' },
    libraries: { label: 'Libraries in use', plain: 'The native code the processes have loaded: outdated copies still in memory, code from temporary directories, injected libraries, vulnerable embedded components.', owner: 'Infrastructure / platform team' },
    components: { label: 'Application components', plain: 'The npm packages and the Node.js runtime the applications are built on, checked against known vulnerabilities and support status.', owner: 'Application owners / development team' },
    secrets: { label: 'Credentials in processes', plain: 'Passwords, tokens and keys visible in process environments and command lines.', owner: 'Application owners / security team' },
    containers: { label: 'Running containers', plain: 'How the running containers are configured: privileges, mounted host paths, exposed ports, limits, image pinning, and packages inside them.', owner: 'Platform / container team' },
    inspection: { label: 'Live inspection', plain: 'What the Node.js processes have really loaded into memory, and whether memory still matches the files on disk.', owner: 'Application owners / security team' },
  },
};
