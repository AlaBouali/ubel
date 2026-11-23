# ubel-vm — Linux VM / server hardening audit

`ubel-vm` audits a Linux virtual machine or server against a hardening baseline and writes a JSON and an HTML report with
**diffs against the previous scan, compliance mapping and detailed stats** — the same report model as `ubel-cloud`.

- **Zero third-party dependencies, no subprocesses.** Node.js built-ins only. It reads configuration files, `/proc` and `/sys`;
  it never runs `systemctl`, `ss`, `sshd -T`, `dpkg`, `iptables` or any other program, and never changes anything on the machine.
- **Live or offline.** By default it audits the host it runs on. `--root <dir>` audits a **mounted disk image / extracted root
  filesystem** instead (works from any operating system; symlinks are resolved *inside* the root and can never escape to the
  scanner's own filesystem). Checks that need a running kernel are then reported as *not applicable*.
- **Honest coverage.** Every check ends as **passed**, **failed**, **not applicable** or **not assessed** (it applies but could not be
  evaluated — typically *permission denied*). A check that could not run is never counted as a pass: the run exits `3` unless you
  pass `--allow-partial`. Run it as **root** for a complete result.

```bash
sudo ubel-vm                                   # audit this machine
ubel-vm --root /mnt/vm-disk                    # audit a mounted image (any OS)
sudo ubel-vm --fail-on high --min-severity medium
sudo ubel-vm --only ssh,accounts --skip vm-ssh-no-access-restriction
ubel-vm --list-checks                          # print the catalogue
```

## Options

| Option | Meaning |
|---|---|
| `--root <dir>` | Audit a mounted image / extracted root filesystem instead of the running host |
| `--host-proc` | With `--root`: the root is a **host filesystem mounted into this process** (a pod with `hostPID` / `hostNetwork`), so `/proc` and `/sys` are read from the process's own view — the host's kernel — and the live checks (sysctl, listening ports, kubelet flags) work. See *Auditing every node from inside the cluster* |
| `--skip-fs-walk` | Skip the one-pass filesystem walk (world-writable files / dirs, set-uid programs) |
| `--fs-max-entries <n>` | Stop the filesystem walk after `n` entries (default 3,000,000) |
| `--fs-timeout <seconds>` | Stop the filesystem walk after this long (default 90); a truncated walk is noted in the report |
| `--only <a,b>` / `--skip <a,b>` | Run / skip checks by id, area name or prefix ending in `*` (`ssh`, `vm-sysctl-*`) |
| `--min-severity <sev>` | Hide findings below this severity (default `info`) |
| `--fail-on <sev\|none\|N:sev>` | Exit `2` when a finding at or above `sev` exists (default `critical`; `5:high` tolerates five) |
| `--allow-partial` | Accept an incomplete assessment (otherwise exit `3`) |
| `--working-dir <path>` | Where `.ubel/` and the `latest.*` reports go (default: current directory) |
| `--verbose` / `--quiet` | Per-check progress / no console findings list |

Exit codes: `0` ok · `2` a `--fail-on` finding exists or bad arguments · `3` incomplete assessment · `1` fatal error.
Asset commands (`asset-id`, `set-asset-id`, `version`, `--asset-id`) work as in every UBEL CLI.

## Reports

Each run writes `report.vm.json` and `report.vm.html` into a timestamped zip under `~/.ubel/history/<asset_id>/` and refreshes
`.ubel/reports/latest.vm.json` / `latest.vm.html`. The HTML is one self-contained file (no network access when viewing) with
the same tabs as the cloud report:

- **Dashboard** — severity, check results and findings per area.
- **Executive Summary** — plain-language overview (rating, top risks, what to fix first, coverage per area, methodology).
- **Findings** — searchable / filterable table with detail view and per-finding compliance controls.
- **Compliance** — findings per framework and control, plus the **check posture per framework** (of the evaluated checks that map to a
  framework, how many pass).
- **Diffs** — findings and areas that are new, still present or fixed since the previous report **of the same host**. Checks that
  were not evaluated in both runs are never read as "fixed", and a note says when the scan mode, host or filter changed.
- **Stats** — SCA-style cards: check coverage, finding severity, area distribution, compliance posture, outcomes per area, most
  common checks, busiest resources.
- **Scan Info** — target (OS, kernel, hypervisor / cloud provider, mode), options, coverage caveats and the full check catalogue
  with each outcome.

The JSON is the exact object the HTML renders from: `findings[]`, `checks[]` (one entry per check with its outcome),
`coverage`, `stats`, `compliance_summary`, `compliance_posture`, `diffs`, `executive_summary`, `target`, `scan_options`.

## Installed packages are not scanned

`ubel-vm` reads configuration, `/proc` and `/sys`. It does not read the package databases to look the installed operating-system or application packages up in a vulnerability database, and it makes no network request. Which packages are installed is read only where a configuration check needs it (for example whether a legacy network-service package is present).

The report's **Inventory** tab lists the host and the objects the findings are about.

## Auditing a Kubernetes node

Run `ubel-vm` **on the node** (as root): its *Kubernetes node* area then covers the node-level hardening that the API cannot show (control-plane and kubelet file permissions, the etcd data directory, the effective kubelet configuration), together with everything else in this report.

`--host-proc` is for the case where the node's filesystem is mounted into the process that runs the scan (for example `ubel-vm --root /host --host-proc`): files are then read from the mounted root, while `/proc` and `/sys` are read from the process's own view, which must be the node's kernel (the process has to share the node's PID and network namespaces). A note in the coverage section appears when it is not. How you start `ubel-vm` on the nodes is up to you; nothing in this repository deploys it.

## Compliance mapping

Every check maps to controls of OWASP Top 10, PCI DSS 4.0, NIST SP 800-53 r5, ISO/IEC 27001:2022, SOC 2, CIS Controls v8 and others
(`sca/compliance_mappings.js`, `VM_CHECK_CATEGORY`). Best-effort guidance, not a compliance assessment. Benchmark-specific control numbers (the CIS Benchmarks) are deliberately not mapped: their numbering differs per distribution and version.

## What it checks

The checks below run on any Linux machine. The **Kubernetes node** area is the node-level hardening of a cluster node: permissions and ownership of the control-plane manifests, kubeconfigs and PKI, the etcd data directory, CNI files and the kubelet's service / kubeconfig / configuration files, plus the **effective kubelet configuration** (command-line flags override the config file; an unset authentication / authorization section is judged by the kubelet's own insecure defaults). Run `ubel-vm` on each node (as root) for that view — `ubel-k8s` sees the cluster through the API but not a node's disk. On a machine that is not a Kubernetes node every one of these checks is reported as *not applicable*.

### Operating system (`os`)

Whether the operating-system release is still supported and updates and package signatures are handled safely.

| Check | Severity | What it detects |
|---|---|---|
| `vm-pkg-repo-integrity` | high | Package signature verification is disabled |
| `vm-os-auto-updates` | low | Automatic security updates are not configured |
| `vm-os-reboot-required` | low | A reboot is pending to apply updates |

### SSH remote access (`ssh`)

How administrators log in remotely: root login, passwords, algorithms and key files.

| Check | Severity | What it detects |
|---|---|---|
| `vm-ssh-root-login` | high | SSH permits direct root login |
| `vm-ssh-empty-passwords` | critical | SSH permits empty passwords |
| `vm-ssh-protocol-1` | critical | SSH protocol version 1 is enabled |
| `vm-ssh-password-auth` | medium | SSH accepts password authentication |
| `vm-ssh-x11-forwarding` | low | SSH X11 forwarding is enabled |
| `vm-ssh-max-auth-tries` | low | SSH allows many authentication attempts per connection |
| `vm-ssh-permit-user-environment` | medium | SSH lets users set environment variables |
| `vm-ssh-hostbased-auth` | medium | SSH host-based authentication is enabled |
| `vm-ssh-ignore-rhosts` | medium | SSH honours .rhosts files |
| `vm-ssh-gateway-ports` | medium | SSH allows remote hosts to use forwarded ports |
| `vm-ssh-no-idle-timeout` | low | SSH sessions have no idle timeout |
| `vm-ssh-no-access-restriction` | low | SSH is not limited to named users or groups |
| `vm-ssh-loglevel` | low | SSH logging is turned down too far |
| `vm-ssh-weak-crypto` | medium | SSH is configured with weak cryptographic algorithms |
| `vm-ssh-config-permissions` | medium | sshd_config is writable by someone other than root |
| `vm-ssh-host-key-permissions` | high | SSH host private key is readable by other users |
| `vm-ssh-dsa-host-key` | medium | SSH offers a DSA host key |
| `vm-ssh-root-authorized-keys` | low | root has SSH authorized keys without a forced command |
| `vm-ssh-authorized-keys-permissions` | medium | A user's SSH directory or authorized_keys can be modified by others |

### Accounts & authentication (`accounts`)

User accounts, passwords, sudo rights and login (PAM) policy.

| Check | Severity | What it detects |
|---|---|---|
| `vm-account-empty-password` | critical | Account has an empty password |
| `vm-account-uid0-nonroot` | critical | A non-root account has UID 0 |
| `vm-account-passwd-hash` | high | Password hash stored in /etc/passwd |
| `vm-account-weak-hash` | medium | Account password uses a weak hash algorithm |
| `vm-account-system-shell` | medium | System account has an interactive login shell |
| `vm-account-duplicate-uid` | low | Two accounts share the same UID |
| `vm-account-password-aging` | low | Password ageing is not configured |
| `vm-account-encrypt-method` | medium | login.defs hashes new passwords with a weak algorithm |
| `vm-account-umask` | low | Default umask is more permissive than 027 |
| `vm-account-home-permissions` | medium | A home directory is writable by other users |
| `vm-account-trust-files` | high | Legacy remote-trust files (.rhosts / hosts.equiv) exist |
| `vm-sudo-nopasswd` | medium | sudo allows commands without a password |
| `vm-pam-nullok` | high | PAM allows logins with empty passwords (nullok) |
| `vm-pam-password-quality` | low | No password-quality enforcement in PAM |
| `vm-pam-lockout` | low | No failed-login lockout in PAM |

### Files & permissions (`filesystem`)

Who can read or change sensitive files, scheduled jobs and privileged programs.

| Check | Severity | What it detects |
|---|---|---|
| `vm-fs-critical-permissions` | high | Critical system file has overly permissive access |
| `vm-fs-world-writable-files` | high | World-writable file in a system or application directory |
| `vm-fs-world-writable-dirs` | medium | World-writable directory without the sticky bit |
| `vm-fs-suid-risky` | high | Set-uid/set-gid bit on a general-purpose program |
| `vm-fs-suid-unexpected` | low | Set-uid/set-gid program that is not a well-known system binary |
| `vm-fs-tmp-mount-options` | low | Temporary directories are not hardened with mount options |
| `vm-fs-ld-so-preload` | medium | /etc/ld.so.preload is in use |
| `vm-cron-writable` | high | Scheduled job can be modified by non-root users |
| `vm-systemd-unit-writable` | high | systemd unit or the program it runs is writable by non-root users |

### Kernel & hardening (`kernel`)

Kernel protections against memory-corruption and network attacks, CPU mitigations and mandatory access control.

| Check | Severity | What it detects |
|---|---|---|
| `vm-sysctl-kernel-randomize-va-space` | medium | Address-space layout randomisation (ASLR) is not fully enabled |
| `vm-sysctl-kernel-kptr-restrict` | low | Kernel pointers are exposed to unprivileged users |
| `vm-sysctl-kernel-dmesg-restrict` | low | Unprivileged users can read the kernel log |
| `vm-sysctl-kernel-yama-ptrace-scope` | low | Any process may ptrace its siblings |
| `vm-sysctl-kernel-sysrq` | low | All magic SysRq functions are enabled |
| `vm-sysctl-kernel-unprivileged-bpf` | low | Unprivileged users can load eBPF programs |
| `vm-sysctl-kernel-kexec-load` | low | kexec can load a replacement kernel at runtime |
| `vm-sysctl-kernel-perf-event-paranoid` | low | Unprivileged users can use perf events broadly |
| `vm-sysctl-fs-protected-links` | medium | Hard-link / symlink protections are off |
| `vm-sysctl-fs-protected-fifos-regular` | low | FIFO / regular-file creation protections are off |
| `vm-sysctl-fs-suid-dumpable` | medium | Set-uid programs may write core dumps |
| `vm-sysctl-vm-mmap-min-addr` | low | Low memory addresses can be mapped by users |
| `vm-sysctl-net-ipv4-source-route` | medium | IPv4 source-routed packets are accepted |
| `vm-sysctl-net-ipv4-accept-redirects` | medium | ICMP redirects are accepted |
| `vm-sysctl-net-ipv4-secure-redirects` | low | Redirects from gateways are accepted |
| `vm-sysctl-net-ipv4-send-redirects` | medium | The host sends ICMP redirects |
| `vm-sysctl-net-ipv4-log-martians` | low | Packets with impossible source addresses are not logged |
| `vm-sysctl-net-ipv4-rp-filter` | low | Reverse-path filtering is off |
| `vm-sysctl-net-ipv4-icmp-broadcast` | low | The host answers broadcast pings |
| `vm-sysctl-net-ipv4-icmp-bogus` | low | Bogus ICMP error responses are not ignored |
| `vm-sysctl-net-ipv4-tcp-syncookies` | medium | TCP SYN cookies are disabled |
| `vm-sysctl-net-ipv6-redirects-source-route` | medium | IPv6 redirects or source routing are accepted |
| `vm-sysctl-net-ip-forward` | medium | IP forwarding is enabled |
| `vm-cpu-vulnerabilities` | medium | CPU vulnerability is not mitigated |
| `vm-kernel-unneeded-modules` | low | Rarely needed kernel modules are loaded |
| `vm-mac-not-enforcing` | low | No mandatory access control (SELinux / AppArmor) is enforcing |

### Network exposure (`network`)

Which services listen on the network and whether a host firewall is in place.

| Check | Severity | What it detects |
|---|---|---|
| `vm-net-risky-listeners` | medium | Sensitive or clear-text service listens on a non-loopback address |
| `vm-net-no-firewall` | low | No host firewall configuration was found |
| `vm-net-promiscuous-interface` | medium | A network interface is in promiscuous mode |

### Services & software (`services`)

Obsolete or unnecessary services and the exposure of the container runtime.

| Check | Severity | What it detects |
|---|---|---|
| `vm-svc-legacy-enabled` | medium | Legacy or unnecessary network service is enabled |
| `vm-pkg-legacy-installed` | medium | Legacy network-service package is installed |
| `vm-docker-exposure` | high | Docker daemon is exposed beyond local root |

### Logging & time (`logging`)

Whether security-relevant events are recorded and clocks are synchronised.

| Check | Severity | What it detects |
|---|---|---|
| `vm-log-auditd` | medium | The Linux audit daemon is not installed or not enabled |
| `vm-log-audit-rules` | low | The audit daemon has no rules loaded from configuration |
| `vm-log-syslog` | medium | No persistent system logging is configured |
| `vm-time-sync` | low | No time-synchronisation service is enabled |

### Stored credentials (`secrets`)

Private keys and access tokens left in plain text on disk.

| Check | Severity | What it detects |
|---|---|---|
| `vm-secrets-ssh-private-keys` | medium | SSH private key stored without a passphrase, or readable by others |
| `vm-secrets-credential-files` | medium | Credentials are stored in plain text in a user's home directory |

### Kubernetes node (`kubernetes`)

When the machine is a Kubernetes node: permissions of the cluster's files and keys, the etcd data directory and the kubelet's own configuration (node-level Kubernetes hardening).

| Check | Severity | What it detects |
|---|---|---|
| `vm-k8s-controlplane-manifests` | high | Control-plane static-pod manifest is accessible by other users |
| `vm-k8s-controlplane-kubeconfigs` | high | Control-plane kubeconfig is accessible by other users |
| `vm-k8s-pki-permissions` | high | Kubernetes PKI directory or file is accessible by other users |
| `vm-k8s-kubelet-service-file` | high | Kubelet service file is accessible by other users |
| `vm-k8s-kubelet-kubeconfig` | high | Kubelet kubeconfig is accessible by other users |
| `vm-k8s-kube-proxy-kubeconfig` | high | kube-proxy kubeconfig is accessible by other users |
| `vm-k8s-client-ca-file` | high | Kubelet client CA file is accessible by other users |
| `vm-k8s-kubelet-config-file` | high | Kubelet configuration file is accessible by other users |
| `vm-k8s-etcd-data-dir` | high | etcd data directory is not locked down |
| `vm-k8s-cni-file-permissions` | high | CNI configuration file is accessible by other users |
| `vm-k8s-kubelet-config` | high | Kubelet is configured insecurely |

### Boot loader (`boot`)

Protection of the boot process against tampering from the console.

| Check | Severity | What it detects |
|---|---|---|
| `vm-boot-grub-password` | low | Boot loader is not password-protected |

## Limits worth knowing

- **Linux only.** Windows and macOS guests are not audited (a Linux image can be audited from any OS with `--root`).
- **Configuration, not exploitation, not vulnerable software.** It does not test whether a service is exploitable and it does not match the installed packages against any vulnerability database.
- **Kubernetes nodes:** the node checks read the kubelet's flags from the running process (live) or the service files (offline root) and its configuration from the usual paths (`/var/lib/kubelet/config.yaml`, `/etc/kubernetes/kubelet/kubelet-config.json`, …); a node whose kubelet configuration lives elsewhere is reported as *not applicable* for that check.
- **No root, no full picture.** `/etc/shadow`, `/etc/sudoers*` and other users' homes need root; the affected checks are *not assessed*.
- **Reachability is not tested.** A listening port is a fact about the host; whether it is reachable from the internet also depends on
  firewalls / security groups outside the machine.
- **sshd is read, not run.** The effective `sshd_config` is reconstructed (first value wins, `Include` expanded, global section only); it does not
  evaluate `Match` blocks and cannot know the compiled-in defaults of your OpenSSH version, so only explicit settings (and defaults that were
  never safe) are judged.
- The shared HTML engine used by both `ubel-vm` and `ubel-k8s` lives in `vm/lib/` (`html_report.js`, `executive_summary.js`, `runner.js`, `engine.js`).
