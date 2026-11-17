'use strict';
// Kubernetes node checks — the node-level hardening that kube-bench-style audits perform: permissions and ownership of the
// cluster's files and keys, the etcd data directory and the kubelet's own configuration, evaluated on the node itself by reading files and /proc. They complement `ubel-k8s`, which sees
// the cluster through the API but not a node's disk. Every rule is "not applicable" on a machine that is not a Kubernetes node.

import { rule, fmtMode, octal } from './util.js';
import { na } from '../lib/engine.js';
import { parseYaml } from '../../package/lib/yaml.js';

const isK8sNode = (ctx) => ['/etc/kubernetes', '/var/lib/kubelet', '/usr/bin/kubelet', '/usr/local/bin/kubelet', '/etc/kubernetes/kubelet'].some((p) => ctx.fs.exists(p))
  || ctx.serviceState('kubelet').installed;
const NOT_NODE = 'this machine is not a Kubernetes node (no /etc/kubernetes, /var/lib/kubelet or kubelet)';

/** Finding severity for a file's access: not root-owned or writable by group/others is serious, a credential readable by others too; merely looser than the benchmark's maximum is low. */
function ladder(st, max, secret) {
  if (st.uid !== 0 || (st.mode & 0o022)) return 'high';
  if (secret && (st.mode & 0o044)) return 'high';
  return (st.mode & ~max & 0o7777) !== 0 ? 'low' : null;
}

/** Inspects `items` = [path, maxMode, {secret?}] and returns violations; `present` counts the files that exist. */
function inspect(ctx, items) {
  const out = []; let present = 0;
  for (const [p, max, opt = {}] of items) {
    const st = ctx.fs.stat(p);
    if (!st || (!st.isFile && !st.isDir)) continue;
    present++;
    const sev = ladder(st, max, !!opt.secret);
    if (sev) out.push({ resource: p, severity: sev, detail: `${fmtMode(st)}; expected: owned by root, mode ${octal(max)} or more restrictive.` });
  }
  return { out, present };
}

const CP_MANIFESTS = ['kube-apiserver', 'kube-controller-manager', 'kube-scheduler', 'etcd'].map((n) => `/etc/kubernetes/manifests/${n}.yaml`);
const CP_CONFS = ['admin.conf', 'super-admin.conf', 'scheduler.conf', 'controller-manager.conf'].map((n) => `/etc/kubernetes/${n}`);

function pkiItems(ctx) {
  const items = [];
  const walk = (dir, depth) => {
    for (const n of ctx.fs.readdir(dir) || []) {
      const p = `${dir}/${n}`;
      const st = ctx.fs.lstat(p);
      if (!st || st.isSymlink) continue;
      if (st.isDir) { if (depth < 2) walk(p, depth + 1); continue; }
      if (/\.key$/.test(n)) items.push([p, 0o600, { secret: true }]);
      else if (/\.(crt|pem|cert)$/.test(n)) items.push([p, 0o644]);
    }
  };
  if (ctx.fs.exists('/etc/kubernetes/pki')) { items.push(['/etc/kubernetes/pki', 0o755]); walk('/etc/kubernetes/pki', 0); }
  return items;
}

// ── kubelet effective configuration ───────────────────────────────────────────

const flagMap = (text) => {
  const m = new Map();
  for (const t of String(text || '').match(/--[A-Za-z0-9-]+(?:=(?:"[^"]*"|'[^']*'|\S+))?/g) || []) {
    const eq = t.indexOf('=');
    m.set(eq > 0 ? t.slice(2, eq) : t.slice(2), eq > 0 ? t.slice(eq + 1).replace(/^["']|["']$/g, '') : 'true');
  }
  return m;
};

/** Kubelet flags (process command line on a live host, else the environment files / systemd drop-ins) and its config file. */
function kubeletSettings(ctx) {
  return ctx._memo('kubelet-settings', () => {
    let flags = new Map();
    let source = null;
    const proc = ctx.live ? ctx.processes().find((p) => p.comm === 'kubelet') : null;
    if (proc) { flags = flagMap(proc.cmdline); source = 'the running kubelet'; }
    else {
      const files = ['/var/lib/kubelet/kubeadm-flags.env', '/etc/default/kubelet', '/etc/sysconfig/kubelet', ...ctx.fs.glob('/etc/systemd/system/kubelet.service.d/*.conf'), '/usr/lib/systemd/system/kubelet.service', '/lib/systemd/system/kubelet.service'];
      for (const f of files) { const t = ctx.fs.read(f); if (t) for (const [k, v] of flagMap(t)) if (!flags.has(k)) flags.set(k, v); }
      source = 'the kubelet service files';
    }
    const candidates = [flags.get('config'), '/var/lib/kubelet/config.yaml', '/etc/kubernetes/kubelet/kubelet-config.json', '/etc/kubernetes/kubelet-config.yaml', '/etc/kubernetes/kubelet.yaml'].filter(Boolean);
    let cfg = null, cfgPath = null;
    for (const p of candidates) {
      const t = ctx.fs.read(p);
      if (t === null) continue;
      try { cfg = /\.json$/i.test(p) || /^\s*\{/.test(t) ? JSON.parse(t) : parseYaml(t); cfgPath = p; break; } catch { /* unparsable: try the next one */ }
    }
    return { flags, cfg: cfg || {}, cfgPath, source, haveConfig: !!cfg, haveFlags: flags.size > 0 };
  });
}

const get = (o, pathStr) => pathStr.split('.').reduce((a, k) => (a && typeof a === 'object' ? a[k] : undefined), o);
const asBool = (v) => (v === true || v === 'true' ? true : v === false || v === 'false' ? false : undefined);
const durationZero = (v) => v === 0 || v === '0' || /^0+(\.0+)?(ns|us|µs|ms|s|m|h)?$/.test(String(v));

/** Effective boolean/value of a kubelet setting: command-line flag first, then the config file; `undefined` when unset. */
function eff(ks, flag, cfgPath) {
  if (flag && ks.flags.has(flag)) return ks.flags.get(flag);
  return get(ks.cfg, cfgPath);
}


/** One rule per group of files, so each finding concerns one kind of file. */
function fileRule(id, title, description, remediation, items, naReason) {
  return rule({
    id, area: 'kubernetes', severity: 'high', title, description, remediation, cap: 100,
    evaluate(ctx) {
      if (!isK8sNode(ctx)) return na(NOT_NODE);
      const seen = new Set();
      const r = inspect(ctx, items(ctx).filter(([p]) => (seen.has(p) ? false : seen.add(p))));
      return r.present ? r.out : na(naReason);
    },
  });
}

const FIX600 = 'chown root:root <file> and chmod 600 <file>.';
const fileRules = [
  fileRule('vm-k8s-controlplane-manifests', 'Control-plane static-pod manifest is accessible by other users',
    'The kube-apiserver, kube-controller-manager, kube-scheduler and etcd manifests define how the control plane runs; anyone able to edit one controls the cluster.', FIX600,
    () => CP_MANIFESTS.map((p) => [p, 0o600]), 'no control-plane manifests on this node (worker node)'),
  fileRule('vm-k8s-controlplane-kubeconfigs', 'Control-plane kubeconfig is accessible by other users',
    'admin.conf, scheduler.conf and controller-manager.conf hold credentials of the cluster\'s most privileged identities.', FIX600,
    () => CP_CONFS.map((p) => [p, 0o600, { secret: true }]), 'no control-plane kubeconfig files on this node (worker node)'),
  fileRule('vm-k8s-pki-permissions', 'Kubernetes PKI directory or file is accessible by other users',
    'The cluster CA and component private keys must be owned by root, with keys readable by root only (certificates may be world-readable at 644).',
    'chown -R root:root /etc/kubernetes/pki; chmod 600 on *.key and 644 on *.crt.', (ctx) => pkiItems(ctx), 'no /etc/kubernetes/pki on this node'),
  fileRule('vm-k8s-kubelet-service-file', 'Kubelet service file is accessible by other users',
    'The kubelet unit file and its systemd drop-ins decide how the kubelet starts; whoever can edit them controls the node.', FIX600,
    (ctx) => [['/usr/lib/systemd/system/kubelet.service', 0o600], ['/lib/systemd/system/kubelet.service', 0o600], ['/etc/systemd/system/kubelet.service', 0o600], ...ctx.fs.glob('/etc/systemd/system/kubelet.service.d/*').map((p) => [p, 0o600])],
    'no kubelet service file found'),
  fileRule('vm-k8s-kubelet-kubeconfig', 'Kubelet kubeconfig is accessible by other users',
    'The kubelet kubeconfig contains the node\'s credential to the API server.', FIX600,
    (ctx) => [['/etc/kubernetes/kubelet.conf', 0o600, { secret: true }], ['/etc/kubernetes/bootstrap-kubelet.conf', 0o600, { secret: true }], ['/var/lib/kubelet/kubeconfig', 0o600, { secret: true }],
      ...(kubeletSettings(ctx).flags.get('kubeconfig') ? [[kubeletSettings(ctx).flags.get('kubeconfig'), 0o600, { secret: true }]] : [])], 'no kubelet kubeconfig found'),
  fileRule('vm-k8s-kube-proxy-kubeconfig', 'kube-proxy kubeconfig is accessible by other users',
    'The kube-proxy kubeconfig contains its credential to the API server.', FIX600,
    () => [['/var/lib/kube-proxy/kubeconfig.conf', 0o600, { secret: true }], ['/etc/kubernetes/kube-proxy-kubeconfig', 0o600, { secret: true }], ['/var/lib/kube-proxy/kubeconfig', 0o600, { secret: true }]], 'no kube-proxy kubeconfig on this node'),
  fileRule('vm-k8s-client-ca-file', 'Kubelet client CA file is accessible by other users',
    'The certificate authority file the kubelet uses to verify clients must not be modifiable by anyone but root; replacing it lets an attacker add a trusted CA.',
    'chown root:root <file> and chmod 644 (or stricter).',
    (ctx) => { const ks = kubeletSettings(ctx); return [[get(ks.cfg, 'authentication.x509.clientCAFile') || ks.flags.get('client-ca-file') || '/etc/kubernetes/pki/ca.crt', 0o644]]; }, 'no client CA file found'),
  fileRule('vm-k8s-kubelet-config-file', 'Kubelet configuration file is accessible by other users',
    'The kubelet configuration file controls its authentication and authorization; whoever can edit it can open the kubelet API.', FIX600,
    (ctx) => [['/var/lib/kubelet/config.yaml', 0o600], ['/etc/kubernetes/kubelet/kubelet-config.json', 0o600], ['/etc/kubernetes/kubelet-config.yaml', 0o600], ...(kubeletSettings(ctx).cfgPath ? [[kubeletSettings(ctx).cfgPath, 0o600]] : [])],
    'no kubelet configuration file found'),
];

export default [
  ...fileRules,
  rule({
    id: 'vm-k8s-etcd-data-dir', area: 'kubernetes', severity: 'high', title: 'etcd data directory is not locked down',
    description: 'The etcd data directory contains every Kubernetes object including Secrets. It should be accessible only to the etcd user (mode 700).',
    remediation: 'chmod 700 /var/lib/etcd and chown etcd:etcd /var/lib/etcd (create a dedicated etcd user for the etcd process).',
    evaluate(ctx) {
      if (!isK8sNode(ctx)) return na(NOT_NODE);
      const manifest = ctx.fs.read('/etc/kubernetes/manifests/etcd.yaml');
      const dir = (manifest && (manifest.match(/--data-dir=([^\s"',\]]+)/) || [])[1]) || '/var/lib/etcd';
      const st = ctx.fs.stat(dir);
      if (!st || !st.isDir) return na('no etcd data directory on this node');
      const out = [];
      if (st.mode & 0o077) out.push({ resource: `${dir}:permissions`, severity: 'high', detail: `${fmtMode(st)}; expected 700 or more restrictive.` });
      const etcdUser = (ctx.passwd() || []).find((u) => u.name === 'etcd');
      if (etcdUser ? st.uid !== etcdUser.uid : st.uid === 0) {
        out.push({ resource: `${dir}:ownership`, severity: 'low', detail: etcdUser ? `Owned by uid ${st.uid}, expected the etcd user (uid ${etcdUser.uid}).` : 'Owned by root; the benchmark expects a dedicated etcd owner (no "etcd" user exists on this node).' });
      }
      return out;
    },
  }),
  rule({
    id: 'vm-k8s-cni-file-permissions', area: 'kubernetes', severity: 'high', title: 'CNI configuration file is accessible by other users',
    description: 'CNI configuration files define pod networking; anyone able to edit them can redirect or intercept pod traffic on the node.',
    remediation: 'chown root:root /etc/cni/net.d/* and chmod 600 /etc/cni/net.d/*',
    evaluate(ctx) {
      if (!isK8sNode(ctx)) return na(NOT_NODE);
      const files = ctx.fs.glob('/etc/cni/net.d/*').filter((p) => ctx.fs.stat(p)?.isFile);
      if (!files.length) return na('no CNI configuration files on this node');
      return inspect(ctx, files.map((p) => [p, 0o600])).out;
    },
  }),
  rule({
    id: 'vm-k8s-kubelet-config', area: 'kubernetes', severity: 'high', title: 'Kubelet is configured insecurely',
    description: 'The kubelet API controls every pod on the node. Anonymous access, AlwaysAllow authorization, an open read-only port, missing client-CA verification or weak TLS settings let anyone who can reach port 10250 read or run workloads. Command-line flags override the configuration file, and an unset authentication / authorization section uses the kubelet\'s own insecure defaults.',
    remediation: 'In the kubelet configuration file set authentication.anonymous.enabled=false, authentication.webhook.enabled=true, authentication.x509.clientCAFile, authorization.mode=Webhook, readOnlyPort=0, protectKernelDefaults=true, rotateCertificates=true and a strong tlsCipherSuites list; remove conflicting flags.',
    evaluate(ctx) {
      if (!isK8sNode(ctx)) return na(NOT_NODE);
      const ks = kubeletSettings(ctx);
      if (!ks.haveConfig && !ks.haveFlags) return na('the kubelet configuration could not be found on this node');
      const where = ks.cfgPath ? `${ks.cfgPath} and ${ks.source}` : ks.source;
      const d = [];
      const add = (res, severity, detail) => d.push({ resource: `kubelet:${res}`, severity, detail: `${detail} (read from ${where}).` });
      const anon = asBool(eff(ks, 'anonymous-auth', 'authentication.anonymous.enabled'));
      if (anon !== false) add('authentication.anonymous', 'high', anon === true ? 'Anonymous requests are enabled.' : 'Anonymous authentication is not disabled, and the kubelet default is enabled');
      const mode = String(eff(ks, 'authorization-mode', 'authorization.mode') || '');
      if (!mode || /AlwaysAllow/i.test(mode)) add('authorization.mode', 'critical', mode ? 'Authorization mode is AlwaysAllow.' : 'No authorization mode is configured, and the kubelet default is AlwaysAllow');
      if (!eff(ks, 'client-ca-file', 'authentication.x509.clientCAFile')) add('authentication.x509.clientCAFile', 'medium', 'No client CA file is set, so client certificates are not verified');
      const ro = Number(eff(ks, 'read-only-port', 'readOnlyPort'));
      if (ro > 0) add('readOnlyPort', 'medium', `The unauthenticated read-only port ${ro} is enabled.`);
      const idle = eff(ks, 'streaming-connection-idle-timeout', 'streamingConnectionIdleTimeout');
      if (idle !== undefined && durationZero(idle)) add('streamingConnectionIdleTimeout', 'low', 'Streaming connections never time out (0).');
      if (asBool(eff(ks, 'protect-kernel-defaults', 'protectKernelDefaults')) !== true) add('protectKernelDefaults', 'low', 'protectKernelDefaults is not true, so the kubelet does not verify kernel parameters');
      if (asBool(eff(ks, 'make-iptables-util-chains', 'makeIPTablesUtilChains')) === false) add('makeIPTablesUtilChains', 'low', 'makeIPTablesUtilChains is false');
      if (asBool(eff(ks, 'rotate-certificates', 'rotateCertificates')) !== true) add('rotateCertificates', 'low', 'Client certificate rotation is not enabled');
      const ciphers = [].concat(ks.flags.get('tls-cipher-suites') ? String(ks.flags.get('tls-cipher-suites')).split(',') : (ks.cfg.tlsCipherSuites || []));
      const weak = ciphers.filter((c) => /_CBC_|3DES|RC4|_RSA_WITH_|NULL/i.test(String(c)));
      if (weak.length) add('tlsCipherSuites', 'medium', `Weak TLS cipher suites allowed: ${weak.join(', ')}`);
      return d;
    },
  }),
];
