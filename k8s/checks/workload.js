'use strict';
import { rule, T, F, num, arr, obj, containersOf, podSc, ctrSc, scanWorkloads, parseImage, DEFAULT_SA } from './util.js';
import { na } from '../../vm/lib/engine.js';

const BASELINE_CAPS = new Set(['AUDIT_WRITE', 'CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'FSETID', 'KILL', 'MKNOD', 'NET_BIND_SERVICE', 'SETFCAP', 'SETGID', 'SETPCAP', 'SETUID', 'SYS_CHROOT']);
const DANGEROUS_CAPS = new Set(['ALL', 'SYS_ADMIN', 'NET_ADMIN', 'SYS_PTRACE', 'SYS_MODULE', 'DAC_READ_SEARCH', 'SYS_RAWIO', 'SYS_BOOT', 'BPF', 'PERFMON', 'SYS_TIME', 'MAC_ADMIN', 'MAC_OVERRIDE', 'LINUX_IMMUTABLE', 'SYSLOG']);
const SAFE_SYSCTLS = new Set(['kernel.shm_rmid_forced', 'net.ipv4.ip_local_port_range', 'net.ipv4.ip_unprivileged_port_start', 'net.ipv4.tcp_syncookies', 'net.ipv4.ping_group_range', 'net.ipv4.ip_local_reserved_ports', 'net.ipv4.tcp_keepalive_time', 'net.ipv4.tcp_fin_timeout', 'net.ipv4.tcp_keepalive_intvl', 'net.ipv4.tcp_keepalive_probes']);
const SENSITIVE_HOST = [/^\/$/, /^\/etc(\/|$)/, /^\/proc(\/|$)/, /^\/sys(\/|$)/, /^\/var\/run\/docker\.sock$/, /^\/run\/docker\.sock$/, /^\/(var\/)?run\/containerd(\/|$)/, /^\/run\/crio(\/|$)/, /^\/var\/lib\/kubelet(\/|$)/, /^\/var\/lib\/docker(\/|$)/, /^\/root(\/|$)/, /^\/home(\/|$)/, /^\/boot(\/|$)/, /^\/dev(\/|$)/];
const SECRET_NAME = /(PASSWORD|PASSWD|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|CREDENTIAL|AUTH[_-]?KEY)/i;
const SECRET_VALUE = [/AKIA[0-9A-Z]{16}/, /-----BEGIN [A-Z ]*PRIVATE KEY-----/, /\bgh[pousr]_[A-Za-z0-9]{30,}/, /\bxox[abprs]-[A-Za-z0-9-]{10,}/, /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/, /\bsk_live_[A-Za-z0-9]{16,}/, /AIza[0-9A-Za-z_-]{35}/];

const capName = (x) => String(x).toUpperCase().replace(/^CAP_/, '');
const seccompOf = (w, c) => {
  const t = obj(ctrSc(c).seccompProfile).type || obj(podSc(obj(w.spec))).seccompProfile?.type;
  if (t) return t;
  const ann = w.annotations || {};
  if (/unconfined/i.test(ann['seccomp.security.alpha.kubernetes.io/pod'] || '') || /unconfined/i.test(ann[`container.seccomp.security.alpha.kubernetes.io/${c.name}`] || '')) return 'Unconfined';
  return null;
};

export default [
  rule({
    id: 'k8s-workload-privileged', area: 'workload', severity: 'critical', title: 'Privileged container',
    description: 'A privileged container has all Linux capabilities, access to every host device and no seccomp / AppArmor confinement; anyone who gets code execution in it effectively owns the node.',
    remediation: 'Remove securityContext.privileged (or set it to false) and add only the specific capabilities or devices the workload really needs.',
    evaluate: (inv) => scanWorkloads(inv, 'container', (w, c) => (T(ctrSc(c).privileged) ? 'securityContext.privileged is true.' : null)),
  }),
  rule({
    id: 'k8s-workload-host-pid', area: 'workload', severity: 'high', title: 'Workload shares the host PID namespace',
    description: 'With hostPID the pod can see and signal every process on the node, and read their environment and memory if combined with other capabilities.',
    remediation: 'Remove spec.hostPID (or set it to false).',
    evaluate: (inv) => scanWorkloads(inv, 'pod', (w) => (T(obj(w.spec).hostPID) ? 'spec.hostPID is true.' : null)),
  }),
  rule({
    id: 'k8s-workload-host-ipc', area: 'workload', severity: 'high', title: 'Workload shares the host IPC namespace',
    description: 'With hostIPC the pod can read and write the node\'s shared memory and message queues, which other host processes may rely on.',
    remediation: 'Remove spec.hostIPC (or set it to false).',
    evaluate: (inv) => scanWorkloads(inv, 'pod', (w) => (T(obj(w.spec).hostIPC) ? 'spec.hostIPC is true.' : null)),
  }),
  rule({
    id: 'k8s-workload-host-network', area: 'workload', severity: 'high', title: 'Workload uses the host network',
    description: 'With hostNetwork the pod binds to the node\'s network interfaces, can reach node-local services (kubelet, metadata endpoint) and bypasses NetworkPolicy.',
    remediation: 'Remove spec.hostNetwork (or set it to false); expose the service through a Service or Ingress instead.',
    evaluate: (inv) => scanWorkloads(inv, 'pod', (w) => (T(obj(w.spec).hostNetwork) ? 'spec.hostNetwork is true.' : null)),
  }),
  rule({
    id: 'k8s-workload-host-path', area: 'workload', severity: 'medium', title: 'Workload mounts a host path',
    description: 'hostPath volumes expose the node\'s filesystem to the pod. Mounting the container runtime socket, /etc, /proc or the kubelet directory is equivalent to root on the node.',
    remediation: 'Use emptyDir, a PersistentVolume or a ConfigMap/Secret volume instead; where a hostPath is unavoidable, restrict it to a specific subdirectory and mount it read-only.',
    evaluate: (inv) => scanWorkloads(inv, 'pod', (w) => {
      const hits = arr(obj(w.spec).volumes).filter((v) => v && v.hostPath && v.hostPath.path);
      if (!hits.length) return null;
      const paths = hits.map((v) => v.hostPath.path);
      const sensitive = paths.filter((p) => SENSITIVE_HOST.some((re) => re.test(String(p).replace(/\/+$/, '') || '/')));
      return { severity: sensitive.length ? 'critical' : 'medium', detail: `hostPath volume(s): ${paths.join(', ')}${sensitive.length ? ` — sensitive: ${sensitive.join(', ')}` : ''}.` };
    }),
  }),
  rule({
    id: 'k8s-workload-host-port', area: 'workload', severity: 'medium', title: 'Container uses a host port',
    description: 'hostPort binds the container to a port on the node, bypassing Services and NetworkPolicy and limiting scheduling.',
    remediation: 'Remove hostPort and publish the port through a Service (NodePort / LoadBalancer) or Ingress.',
    evaluate: (inv) => scanWorkloads(inv, 'container', (w, c) => {
      const p = arr(c.ports).filter((x) => x && num(x.hostPort) > 0);
      return p.length ? `hostPort ${p.map((x) => x.hostPort).join(', ')}.` : null;
    }),
  }),
  rule({
    id: 'k8s-workload-privilege-escalation', area: 'workload', severity: 'low', title: 'Container allows privilege escalation',
    description: 'Unless allowPrivilegeEscalation is false, a process can gain more privileges than its parent (set-uid binaries, file capabilities).',
    remediation: 'Set securityContext.allowPrivilegeEscalation: false on the container.',
    evaluate: (inv) => scanWorkloads(inv, 'container', (w, c) => {
      const sc = ctrSc(c);
      if (T(sc.privileged) || F(sc.allowPrivilegeEscalation)) return null;
      return T(sc.allowPrivilegeEscalation) ? { severity: 'medium', detail: 'allowPrivilegeEscalation is explicitly true.' } : 'allowPrivilegeEscalation is not set to false (the default is true).';
    }),
  }),
  rule({
    id: 'k8s-workload-run-as-root', area: 'workload', severity: 'low', title: 'Container runs, or may run, as root',
    description: 'A process running as UID 0 inside the container is far more dangerous if it escapes or if a volume is shared; images should run as an unprivileged user.',
    remediation: 'Set securityContext.runAsNonRoot: true and a non-zero runAsUser (pod or container level), and build the image to run as a non-root user.',
    evaluate: (inv) => scanWorkloads(inv, 'container', (w, c) => {
      const sc = ctrSc(c), pod = podSc(obj(w.spec));
      const user = num(sc.runAsUser ?? pod.runAsUser);
      const nonRoot = T(sc.runAsNonRoot ?? pod.runAsNonRoot);
      if (user === 0) return { severity: 'medium', detail: 'runAsUser is 0 (root).' };
      if (nonRoot || (user !== null && user > 0)) return null;
      return 'Neither runAsNonRoot nor a non-zero runAsUser is set, so the container runs as whatever user the image defines (often root).';
    }),
  }),
  rule({
    id: 'k8s-workload-capabilities', area: 'workload', severity: 'medium', title: 'Container adds Linux capabilities beyond the baseline',
    description: 'Capabilities such as SYS_ADMIN, NET_ADMIN, SYS_PTRACE or ALL allow container escape or host manipulation. The Kubernetes baseline profile only permits a short list.',
    remediation: 'Remove the capability from securityContext.capabilities.add; drop ALL and add back only what is required.',
    evaluate: (inv) => scanWorkloads(inv, 'container', (w, c) => {
      if (T(ctrSc(c).privileged)) return null;
      const added = arr(obj(ctrSc(c).capabilities).add).map(capName);
      const extra = added.filter((x) => !BASELINE_CAPS.has(x));
      if (!extra.length) return null;
      const danger = extra.filter((x) => DANGEROUS_CAPS.has(x));
      return { severity: danger.length ? 'high' : 'medium', detail: `Adds ${extra.join(', ')}${danger.length ? ` (dangerous: ${danger.join(', ')})` : ''}.` };
    }),
  }),
  rule({
    id: 'k8s-workload-net-raw', area: 'workload', severity: 'low', title: 'Container keeps the NET_RAW capability',
    description: 'By default containers can craft raw packets (NET_RAW), enabling ARP/DNS spoofing against neighbouring pods. The restricted profile drops ALL capabilities.',
    remediation: 'Set securityContext.capabilities.drop: ["ALL"] (or at least ["NET_RAW"]).',
    evaluate: (inv) => scanWorkloads(inv, 'container', (w, c, type) => {
      if (type !== 'container') return null;
      const drop = arr(obj(ctrSc(c).capabilities).drop).map(capName);
      return drop.includes('ALL') || drop.includes('NET_RAW') ? null : 'capabilities.drop does not include ALL or NET_RAW.';
    }),
  }),
  rule({
    id: 'k8s-workload-readonly-rootfs', area: 'workload', severity: 'low', title: 'Container root filesystem is writable',
    description: 'A writable root filesystem lets an attacker who gets code execution drop tools or modify the application inside the container.',
    remediation: 'Set securityContext.readOnlyRootFilesystem: true and mount emptyDir volumes for paths that must be writable.',
    evaluate: (inv) => scanWorkloads(inv, 'container', (w, c, type) => (type === 'container' && !T(ctrSc(c).readOnlyRootFilesystem) ? 'readOnlyRootFilesystem is not true.' : null)),
  }),
  rule({
    id: 'k8s-workload-seccomp', area: 'workload', severity: 'low', title: 'Container has no seccomp profile',
    description: 'Without a seccomp profile the container can use the full system-call surface of the node kernel. The runtime default profile blocks the most dangerous calls.',
    remediation: 'Set securityContext.seccompProfile.type: RuntimeDefault at pod or container level.',
    evaluate: (inv) => scanWorkloads(inv, 'container', (w, c, type) => {
      if (type !== 'container' || T(ctrSc(c).privileged)) return null;
      const t = seccompOf(w, c);
      if (t === 'Unconfined' || (t && /unconfined/i.test(t))) return { severity: 'medium', detail: 'seccomp profile is Unconfined.' };
      return t ? null : 'No seccompProfile is set (the default is Unconfined unless the cluster enforces RuntimeDefault).';
    }),
  }),
  rule({
    id: 'k8s-workload-baseline-settings', area: 'workload', severity: 'medium', title: 'Workload uses a setting forbidden by the Pod Security baseline',
    description: 'The Kubernetes Pod Security Standards baseline profile forbids unmasked /proc, unconfined AppArmor, custom SELinux types, unsafe sysctls and Windows HostProcess containers because they weaken isolation.',
    remediation: 'Remove the setting or run the workload in a namespace that is intentionally exempt, with compensating controls.',
    evaluate: (inv) => scanWorkloads(inv, 'pod', (w) => {
      const spec = obj(w.spec), d = [];
      let sev = 'medium';
      for (const s of arr(obj(spec.securityContext).sysctls)) if (s && !SAFE_SYSCTLS.has(s.name)) d.push(`unsafe sysctl ${s.name}`);
      if (T(obj(obj(spec.securityContext).windowsOptions).hostProcess)) { d.push('Windows hostProcess'); sev = 'high'; }
      const se = obj(obj(spec.securityContext).seLinuxOptions);
      if (se.user || se.role || (se.type && !['container_t', 'container_init_t', 'container_kvm_t', 'container_engine_t'].includes(se.type))) d.push('custom SELinux options');
      if (obj(obj(spec.securityContext).appArmorProfile).type === 'Unconfined') d.push('AppArmor Unconfined (pod)');
      for (const [k, v] of Object.entries(w.annotations || {})) if (/^container\.apparmor\.security\.beta\.kubernetes\.io\//.test(k) && /unconfined/i.test(v)) d.push(`AppArmor unconfined for ${k.split('/')[1]}`);
      for (const { c } of containersOf(spec)) {
        const sc = ctrSc(c);
        if (sc.procMount === 'Unmasked') { d.push(`procMount Unmasked (${c.name})`); sev = 'high'; }
        if (obj(sc.appArmorProfile).type === 'Unconfined') d.push(`AppArmor Unconfined (${c.name})`);
        if (T(obj(sc.windowsOptions).hostProcess)) { d.push(`Windows hostProcess (${c.name})`); sev = 'high'; }
      }
      return d.length ? { severity: sev, detail: `${d.join('; ')}.` } : null;
    }),
  }),
  rule({
    id: 'k8s-workload-resource-limits', area: 'workload', severity: 'low', title: 'Container has no CPU / memory limits',
    description: 'Without limits a single container can exhaust the node (noisy neighbour or denial of service) and is first to be evicted unpredictably.',
    remediation: 'Set resources.limits.cpu and resources.limits.memory (and matching requests); enforce defaults with a LimitRange.',
    evaluate: (inv) => scanWorkloads(inv, 'container', (w, c, type) => {
      if (type !== 'container') return null;
      const l = obj(obj(c.resources).limits);
      const miss = ['cpu', 'memory'].filter((k) => !l[k]);
      return miss.length ? `No ${miss.join(' / ')} limit.` : null;
    }),
  }),
  rule({
    id: 'k8s-workload-image-tag', area: 'workload', severity: 'medium', title: 'Container image uses a mutable tag',
    description: 'An image without a tag, or tagged :latest, can change underneath the workload at any time, which breaks reproducibility and lets a compromised registry push code into production.',
    remediation: 'Pin the image to a specific version tag, ideally by digest (image@sha256:…).',
    evaluate: (inv) => scanWorkloads(inv, 'container', (w, c) => {
      const im = parseImage(c.image);
      if (!c.image || im.digest) return null;
      return !im.tag || im.tag === 'latest' ? `Image ${c.image} ${im.tag ? 'uses the :latest tag' : 'has no tag (defaults to :latest)'}.` : null;
    }),
  }),
  rule({
    id: 'k8s-workload-image-registry', area: 'workload', severity: 'medium', title: 'Container image comes from a registry outside the allow-list',
    description: 'Only images from registries your organisation controls or trusts should run in the cluster.',
    remediation: 'Mirror the image into an approved registry, or add the registry to --allowed-registries if it is trusted.',
    evaluate(inv) {
      const allowed = (inv.options.allowedRegistries || []).map((x) => x.toLowerCase());
      if (!allowed.length) return na('no --allowed-registries list was given');
      return scanWorkloads(inv, 'container', (w, c) => {
        const im = parseImage(c.image);
        const r = im.registry.toLowerCase();
        return c.image && !allowed.some((a) => r === a || r.endsWith('.' + a)) ? `Image ${c.image} is from ${im.registry}.` : null;
      });
    },
  }),
  rule({
    id: 'k8s-workload-secret-in-env', area: 'workload', severity: 'high', title: 'Secret value written in plain text in the pod spec',
    description: 'A credential defined as a literal env value is stored in the manifest, in etcd, in GitOps repositories and in every `kubectl describe`. The value itself is not shown in this report.',
    remediation: 'Move it to a Secret (ideally from an external secret manager) and reference it with valueFrom.secretKeyRef or a mounted file; rotate the exposed credential.',
    evaluate: (inv) => scanWorkloads(inv, 'container', (w, c) => {
      const hits = [];
      for (const e of arr(c.env)) {
        if (!e || e.value === undefined || e.value === null || e.valueFrom) continue;
        const v = String(e.value);
        const byValue = SECRET_VALUE.some((re) => re.test(v));
        const byName = SECRET_NAME.test(String(e.name)) && v.length >= 4 && !/^(true|false|none|null|\/|\$\(|\{\{)/i.test(v) && !/^[A-Za-z0-9_.\/-]*(file|path|dir|url|name|enabled)$/i.test(String(e.name));
        if (byValue || byName) hits.push(e.name);
      }
      return hits.length ? `Literal value in env var(s): ${hits.join(', ')}.` : null;
    }),
  }),
  rule({
    id: 'k8s-workload-secret-env-ref', area: 'workload', severity: 'info', title: 'Secret exposed to the container as an environment variable',
    description: 'Environment variables leak easily (process listings, crash dumps, child processes). Mounting secrets as files is the safer option.',
    remediation: 'Mount the Secret as a volume (or use a CSI secrets driver) instead of secretKeyRef / secretRef.',
    evaluate: (inv) => scanWorkloads(inv, 'container', (w, c) => {
      const names = [...arr(c.env).filter((e) => e && e.valueFrom && e.valueFrom.secretKeyRef).map((e) => e.name), ...arr(c.envFrom).filter((e) => e && e.secretRef).map((e) => `envFrom:${e.secretRef.name}`)];
      return names.length ? `Secret-backed environment: ${names.join(', ')}.` : null;
    }),
  }),
  rule({
    id: 'k8s-workload-default-service-account', area: 'workload', severity: 'low', title: 'Workload runs as the default service account with its token mounted',
    description: 'Pods that do not name a ServiceAccount share the namespace\'s default one, and its API token is mounted into every container. Any permission later granted to "default" is inherited by all of them.',
    remediation: 'Create a dedicated ServiceAccount per workload, or set automountServiceAccountToken: false on pods that do not call the Kubernetes API.',
    evaluate: (inv) => scanWorkloads(inv, 'pod', (w) => {
      const spec = obj(w.spec);
      if (!DEFAULT_SA(spec) || F(spec.automountServiceAccountToken)) return null;
      return 'Uses the "default" ServiceAccount and automountServiceAccountToken is not false.';
    }),
  }),
  rule({
    id: 'k8s-workload-default-namespace', area: 'workload', severity: 'low', title: 'Workload is deployed in the default namespace',
    description: 'The default namespace has no isolation boundary of its own and tends to collect unrelated workloads, making RBAC, quotas and network policy harder to apply.',
    remediation: 'Deploy workloads into dedicated namespaces.',
    evaluate: (inv) => scanWorkloads(inv, 'pod', (w) => (w.namespace === 'default' ? 'metadata.namespace is "default".' : null)),
  }),
];
