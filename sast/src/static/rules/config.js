'use strict';

import { custom } from './helpers.js';
import { parseYamlDocs, parseHclBlocks, isMap, asArray, lineOfKey, truthy, falsy } from '../structured.js';

// ═══ plumbing ════════════════════════════════════════════════════════════════
const cfg = (d) => custom({ conf: 'medium', ...d });

function rawLines(flow) { return (flow._raw ||= flow.chunk.code.split('\n')); }
function litLines(flow) { return (flow._lit ||= flow.ctx.literal.split('\n')); }
const SECRETISH = /(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|apikey|private[_-]?key|access[_-]?key|secret[_-]?key|client[_-]?secret|credential|auth[_-]?token|connection[_-]?string|master[_-]?password|admin[_-]?password)/i;
const PLACEHOLDER = /^(?:|\$\{?[\w:.\-]*\}?|\{\{.*\}\}|%\(.*\)s|<.*>|your[_-].*|changeme|change[_-]?me|xxx+|\*+|todo|null|none|example|dummy|placeholder|secret|password|test|\.\.\.|var\.\w+.*|local\.\w+.*|data\.\w+.*|module\..*|aws_\w+\..*|random_\w+\..*|!(?:Ref|GetAtt|Sub|ImportValue|If)\b.*|\{"?(?:Ref|Fn::[A-Za-z]+)"?:.*|!vault.*)$/i;
const isPlaceholder = (v) => PLACEHOLDER.test(String(v ?? '').trim().replace(/^["']|["']$/g, ''));

// redact the value part of a `key: value` / `key = value` line so reports never carry the secret
function redactLine(line) {
  return line.replace(/((?:["']?[\w.\-]*(?:pass(?:word|wd)?|secret|token|key|credential|pwd)[\w.\-]*["']?)\s*[:=]\s*)(["']?)([^"'\s#,}]+)\2/ig, '$1$2****$2')
             .replace(/(-p\s*|--password[= ]\s*|:\/\/[^:\s\/]+:)([^@\s"']+)/g, '$1****').trim().slice(0, 300);
}
function emitAt(flow, emit, line, extra = {}) {
  const raw = (rawLines(flow)[line - 1] ?? '').trim();
  emit(0, { relLine: line, snippet: (extra.redact ? redactLine(raw) : raw).slice(0, 300), lineNeedle: raw, ...extra });
}
const kindOf = (flow) => flow.chunk.type;

// ═══ Dockerfile / Compose ════════════════════════════════════════════════════
function dockerInstr(flow) {
  if (flow._di) return flow._di;
  const L = litLines(flow); const out = []; let cur = null;
  for (let i = 0; i < L.length; i++) {
    const t = L[i];
    if (cur) { cur.args += ' ' + t.trim().replace(/\\\s*$/, ''); if (!/\\\s*$/.test(t)) cur = null; continue; }
    const mm = /^\s*([A-Za-z]+)(?:\s+(.*))?$/.exec(t);
    if (!mm || !/^(?:FROM|RUN|CMD|LABEL|MAINTAINER|EXPOSE|ENV|ADD|COPY|ENTRYPOINT|VOLUME|USER|WORKDIR|ARG|ONBUILD|STOPSIGNAL|HEALTHCHECK|SHELL)$/i.test(mm[1])) continue;
    const ins = { op: mm[1].toUpperCase(), args: (mm[2] || '').replace(/\\\s*$/, '').trim(), line: i + 1 };
    out.push(ins);
    if (/\\\s*$/.test(t)) cur = ins;
  }
  return (flow._di = out);
}
function composeServices(flow) {
  if (flow._cs) return flow._cs;
  const res = [];
  for (const { doc } of parseYamlDocs(flow.ctx.literal)) {
    if (!isMap(doc) || !isMap(doc.services)) continue;
    for (const [name, svc] of Object.entries(doc.services)) if (isMap(svc)) res.push({ name, svc, line: lineOfKey(doc.services, name) });
  }
  return (flow._cs = res);
}
const FAM_DOCKER = ['docker'];

const DOCKER_RULES = [
  cfg({ id: 'docker-root', cls: 'container running as root', langs: FAM_DOCKER, sev: 'medium', conf: 'high', group: 'docker', title: 'Container runs as root',
    fix: 'Create an unprivileged user and switch to it before the entrypoint (RUN adduser … && USER app); in Compose/Kubernetes also set user / runAsNonRoot.',
    run(flow, emit) {
      if (kindOf(flow) === 'compose') {
        for (const { name, svc } of composeServices(flow)) {
          const u = String(svc.user ?? '').trim();
          if (/^(?:root|0|0:0|root:root)$/.test(u)) emitAt(flow, emit, lineOfKey(svc, 'user'), { desc: `Compose service "${name}" is configured to run as root.` });
        }
        return;
      }
      const ins = dockerInstr(flow);
      const froms = ins.filter(i => i.op === 'FROM'); if (!froms.length) return;
      const last = froms[froms.length - 1];
      if (/nonroot|unprivileged|rootless|chainguard|wolfi/i.test(last.args)) return;
      const users = ins.filter(i => i.op === 'USER' && i.line > last.line);
      const lastUser = users[users.length - 1];
      if (!lastUser) emitAt(flow, emit, last.line, { desc: 'The final image stage never sets a USER, so the container process runs as root. A compromise of the application then has root inside the container.', conf: 'high' });
      else if (/^["']?(?:root|0)(?::\S*)?["']?$/i.test(lastUser.args.trim())) emitAt(flow, emit, lastUser.line, { desc: 'The final stage explicitly switches to root (USER root).' });
    } }),

  cfg({ id: 'docker-privileged', cls: 'privileged container / excessive Docker capabilities', langs: FAM_DOCKER, sev: 'high', conf: 'high', group: 'docker', title: 'Privileged container or dangerous capabilities',
    fix: 'Remove privileged mode and host namespaces; drop all capabilities (cap_drop: [ALL]) and add back only the specific ones required; do not disable seccomp/AppArmor.',
    run(flow, emit) {
      if (kindOf(flow) !== 'compose') {
        for (const i of dockerInstr(flow)) if (i.op === 'RUN' && /--privileged|--cap-add[= ](?:ALL|SYS_ADMIN)|setcap\s+\S*\+ep|chmod\s+(?:u\+s|[24]7\d\d)\s/.test(i.args)) emitAt(flow, emit, i.line, { desc: 'A build step grants elevated privileges (privileged flag, dangerous capability, or setuid bit).', sev: 'medium' });
        return;
      }
      const DANGEROUS_CAPS = /^(?:ALL|SYS_ADMIN|NET_ADMIN|SYS_PTRACE|SYS_MODULE|DAC_READ_SEARCH|SYS_RAWIO|SYS_BOOT|SYS_CHROOT|MAC_ADMIN|BPF|PERFMON|SYS_TIME)$/i;
      for (const { name, svc } of composeServices(flow)) {
        if (truthy(svc.privileged)) emitAt(flow, emit, lineOfKey(svc, 'privileged'), { desc: `Compose service "${name}" runs with privileged: true, which gives it nearly all host capabilities and device access.`, sev: 'critical' });
        for (const cap of asArray(svc.cap_add)) if (DANGEROUS_CAPS.test(String(cap))) emitAt(flow, emit, lineOfKey(svc, 'cap_add'), { desc: `Service "${name}" adds the dangerous capability ${cap}.`, sev: String(cap).toUpperCase() === 'ALL' || /SYS_ADMIN/i.test(cap) ? 'high' : 'medium' });
        for (const k of ['network_mode', 'pid', 'ipc', 'userns_mode', 'uts']) if (/^host$/i.test(String(svc[k] ?? '').trim())) emitAt(flow, emit, lineOfKey(svc, k), { desc: `Service "${name}" shares the host ${k.replace('_mode', '')} namespace (${k}: host).`, sev: 'high' });
        for (const o of asArray(svc.security_opt)) if (/(?:seccomp|apparmor)\s*[:=]\s*unconfined|label\s*[:=]\s*disable|no-new-privileges\s*[:=]\s*false/i.test(String(o))) emitAt(flow, emit, lineOfKey(svc, 'security_opt'), { desc: `Service "${name}" disables a container confinement layer (${o}).`, sev: 'high' });
        for (const d of asArray(svc.devices)) if (/^\/dev(?::\/dev)?(?::|$)/.test(String(d))) emitAt(flow, emit, lineOfKey(svc, 'devices'), { desc: `Service "${name}" exposes host devices (${d}).`, sev: 'high' });
      }
    } }),

  cfg({ id: 'docker-secret', cls: 'hardcoded secret in Docker image or Compose file', langs: FAM_DOCKER, sev: 'high', conf: 'high', group: 'secret', title: 'Hardcoded secret in Docker configuration',
    fix: 'Do not bake credentials into images or compose files: use BuildKit secrets (RUN --mount=type=secret), runtime environment injection, Docker/Compose secrets or an external secret manager; rotate any value that was committed.',
    run(flow, emit) {
      if (kindOf(flow) === 'compose') {
        for (const { name, svc } of composeServices(flow)) {
          const env = svc.environment;
          const entries = Array.isArray(env) ? env.map((e, i) => { const s = String(e); const k = s.indexOf('='); return k > 0 ? [s.slice(0, k), s.slice(k + 1), env.$lines?.[i] || lineOfKey(svc, 'environment')] : null; }).filter(Boolean)
            : isMap(env) ? Object.entries(env).map(([k, v]) => [k, v, lineOfKey(env, k)]) : [];
          for (const [k, v, line] of entries) if (SECRETISH.test(k) && !/_FILE$/i.test(k) && typeof v === 'string' && !isPlaceholder(v) && v.length >= 3) emitAt(flow, emit, line, { redact: true, desc: `Compose service "${name}" sets ${k} to a literal value in the file.` });
        }
        return;
      }
      for (const i of dockerInstr(flow)) {
        if (i.op === 'ENV' || i.op === 'ARG') {
          const pairs = [...i.args.matchAll(/([A-Za-z_][\w.]*)(?:=|\s+)(?:"([^"]*)"|'([^']*)'|(\S+))/g)];
          for (const p of pairs) { const k = p[1], v = p[2] ?? p[3] ?? p[4] ?? ''; if (SECRETISH.test(k) && !isPlaceholder(v) && v.length >= 3 && !/^\$/.test(v)) emitAt(flow, emit, i.line, { redact: true, desc: `${i.op} ${k} is set to a literal value; it is stored in the image layers and visible with "docker history".` }); }
        } else if (i.op === 'RUN') {
          if (/(?:curl|wget)\b[^|;&]*(?:-u|--user)[ =]\s*\S+:\S+|--password[= ]\s*[^\s$]+|docker\s+login\b[^|;&]*-p\s+\S+|\bmysql\b[^|;&]*\s-p[^\s$]\S+|echo\s+["']?[^|;&]*(?:password|secret|token)[^|;&]*["']?\s*>\s*\S*(?:\.netrc|\.npmrc|credentials|id_rsa)|-----BEGIN [A-Z ]*PRIVATE KEY/i.test(i.args)) emitAt(flow, emit, i.line, { redact: true, desc: 'A build step embeds a credential on the command line or writes one into the image.' });
        }
      }
    } }),

  cfg({ id: 'docker-base-image', cls: 'unpinned or unsafe base image', langs: FAM_DOCKER, sev: 'medium', conf: 'high', group: 'docker', title: 'Unpinned base image',
    fix: 'Pin base images to a specific version tag and, for production, to an immutable digest (image:1.2.3@sha256:…); rebuild regularly to pick up patches.',
    run(flow, emit) {
      const check = (img, line, ctxName) => {
        if (!img || /^(?:scratch|\$|\{\{)/.test(img) || /\$\{?\w+\}?/.test(img)) return;
        if (/@sha256:[0-9a-f]{16,}/i.test(img)) return;
        const tag = /:([^/@:]+)$/.exec(img.replace(/^[^/]*\/(?=.*[:])/, m => m));
        const hasTag = /:[^/]+$/.test(img.split('/').pop());
        if (!hasTag) emitAt(flow, emit, line, { desc: `${ctxName} "${img}" has no tag, so it resolves to :latest and changes without notice.`, sev: 'medium' });
        else if (/:latest$/i.test(img)) emitAt(flow, emit, line, { desc: `${ctxName} "${img}" uses the mutable :latest tag.`, sev: 'medium' });
      };
      if (kindOf(flow) === 'compose') {
        for (const { name, svc } of composeServices(flow)) if (typeof svc.image === 'string') check(svc.image.trim(), lineOfKey(svc, 'image'), `Service "${name}" image`);
        return;
      }
      const stages = new Set();
      for (const i of dockerInstr(flow)) if (i.op === 'FROM') {
        const mm = /^(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?/i.exec(i.args); if (!mm) continue;
        if (!stages.has(mm[1].toLowerCase())) check(mm[1], i.line, 'Base image');
        if (mm[2]) stages.add(mm[2].toLowerCase());
      }
    } }),

  cfg({ id: 'docker-add-remote', cls: 'insecure ADD / untrusted remote content', langs: FAM_DOCKER, sev: 'high', conf: 'high', group: 'docker', title: 'Untrusted remote content in image build',
    fix: 'Download artefacts over HTTPS with a pinned version and verify a checksum/signature before use; prefer COPY over ADD; never pipe a download into a shell.',
    run(flow, emit) {
      if (kindOf(flow) === 'compose') return;
      for (const i of dockerInstr(flow)) {
        if (i.op === 'ADD' && /^(?:--\S+\s+)*https?:\/\//i.test(i.args)) emitAt(flow, emit, i.line, { desc: 'ADD downloads a remote URL at build time with no integrity check; the content can change or be tampered with.', sev: /^(?:--\S+\s+)*http:\/\//i.test(i.args) ? 'high' : 'medium' });
        if (i.op === 'RUN') {
          if (/(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:python[\d.]*|perl|ruby|node)\b|bash\s+<\(\s*(?:curl|wget)|sh\s+-c\s+["']\$\(\s*(?:curl|wget)/i.test(i.args)) emitAt(flow, emit, i.line, { desc: 'A build step pipes a downloaded script straight into an interpreter, executing unverified remote code as part of the image build.', sev: 'high' });
          else if (/\bcurl\b[^|;&]*(?:\s-k\b|--insecure)|\bwget\b[^|;&]*--no-check-certificate|--trusted-host\b|--allow-unauthenticated|--force-yes|\s--nogpgcheck|rpm\b[^|;&]*--nosignature|npm\s+config\s+set\s+strict-ssl\s+false|git\s+config\s+(?:--global\s+)?http\.sslVerify\s+false|\bgit\s+clone\s+http:\/\/|pip3?\s+install\b[^|;&]*(?:--index-url|-i)\s+http:\/\/|apt(?:-get)?\b[^|;&]*\bAcquire::https::Verify-Peer\s*=\s*false|NODE_TLS_REJECT_UNAUTHORIZED=0/i.test(i.args)) emitAt(flow, emit, i.line, { desc: 'A build step disables TLS or signature verification when fetching packages or files.', sev: 'high' });
        }
      }
    } }),

  cfg({ id: 'docker-volume', cls: 'sensitive Docker volume or bind mount exposure', langs: FAM_DOCKER, sev: 'high', conf: 'high', group: 'docker', title: 'Sensitive host path mounted into container',
    fix: 'Do not mount the Docker socket or sensitive host directories. If access is unavoidable, mount a narrowly scoped path read-only (":ro") and use a socket proxy with restricted API access.',
    run(flow, emit) {
      if (kindOf(flow) !== 'compose') return;
      const SENS = /^(?:\/|\/etc|\/root|\/proc|\/sys|\/dev|\/boot|\/home|\/var\/run\/docker\.sock|\/run\/docker\.sock|\/var\/lib\/docker|\/var\/lib\/kubelet|\/usr|\/bin|\/sbin|~\/\.ssh|~\/\.aws|~\/\.kube|~\/\.docker|\$\{?HOME\}?\/\.(?:ssh|aws|kube|docker)|\.\/\.ssh)(?:\/)?$/;
      for (const { name, svc } of composeServices(flow)) {
        const vols = asArray(svc.volumes);
        vols.forEach((v, i) => {
          let host = null, ro = false;
          if (typeof v === 'string') { const parts = v.split(':'); host = parts[0]; ro = /(?:^|,)ro$/.test(parts[parts.length - 1]); }
          else if (isMap(v)) { host = v.source; ro = truthy(v.read_only); }
          if (!host) return;
          const line = svc.volumes.$lines?.[i] || lineOfKey(svc, 'volumes');
          if (/docker\.sock$/.test(host)) emitAt(flow, emit, line, { desc: `Service "${name}" mounts the Docker socket, which is equivalent to root on the host.`, sev: 'critical' });
          else if (SENS.test(host.replace(/\/+$/, '') || '/')) emitAt(flow, emit, line, { desc: `Service "${name}" bind-mounts the sensitive host path ${host}${ro ? ' (read-only)' : ' read-write'}.`, sev: ro ? 'medium' : 'high' });
        });
      }
    } }),
];

// ═══ Kubernetes ══════════════════════════════════════════════════════════════
const K8S = ['k8s'];
const WORKLOADS = new Set(['Pod', 'Deployment', 'StatefulSet', 'DaemonSet', 'Job', 'CronJob', 'ReplicaSet', 'ReplicationController', 'DeploymentConfig']);
function k8sDocs(flow) {
  if (flow._k8s) return flow._k8s;
  const docs = [];
  const parse = (tree, offset = 0) => {
    for (const { doc } of tree) {
      if (isMap(doc) && doc.kind && Array.isArray(doc.items) && /List$/.test(String(doc.kind))) doc.items.forEach(it => { if (isMap(it)) docs.push(it); });
      else if (isMap(doc) && doc.kind) docs.push(doc);
    }
  };
  if (/\.json$/i.test(flow.chunk.file || '')) {
    try { const o = JSON.parse(flow.chunk.code); if (o && o.kind) docs.push(o); } catch { /* ignore */ }
  } else parse(parseYamlDocs(flow.ctx.literal));
  return (flow._k8s = docs);
}
function podSpecOf(doc) {
  const k = doc.kind; const s = doc.spec; if (!isMap(s)) return null;
  if (k === 'Pod') return s;
  if (k === 'CronJob') return s.jobTemplate?.spec?.template?.spec || null;
  return s.template?.spec || null;
}
const containersOf = (spec) => ['initContainers', 'containers', 'ephemeralContainers'].flatMap(k => asArray(spec[k]).map((c, i) => ({ c, line: spec[k].$lines?.[i] || lineOfKey(spec, k), kind: k })).filter(x => isMap(x.c)));
const nameOf = (doc) => doc.metadata?.name || doc.kind;
const DANGER_CAPS = /^(?:ALL|SYS_ADMIN|NET_ADMIN|SYS_PTRACE|SYS_MODULE|DAC_READ_SEARCH|DAC_OVERRIDE|SYS_RAWIO|SYS_BOOT|BPF|PERFMON|NET_RAW|SYS_CHROOT|MAC_ADMIN)$/i;
const SENS_HOSTPATH = /^(?:\/|\/etc|\/root|\/proc|\/sys|\/dev|\/boot|\/var\/run\/docker\.sock|\/run\/docker\.sock|\/var\/lib\/docker|\/var\/lib\/kubelet|\/var\/log|\/home|\/usr|\/lib|\/bin|\/sbin|\/run|\/var\/run)(?:\/.*)?$/;

const K8S_RULES = [
  cfg({ id: 'k8s-pod-security', cls: 'insecure Kubernetes pod security context', langs: K8S, sev: 'high', conf: 'high', group: 'k8s', title: 'Insecure pod security context',
    fix: 'Set securityContext: runAsNonRoot: true, allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities.drop: ["ALL"], seccompProfile.type: RuntimeDefault; never use privileged, hostNetwork/hostPID/hostIPC or sensitive hostPath mounts.',
    run(flow, emit) {
      for (const doc of k8sDocs(flow)) {
        if (!WORKLOADS.has(doc.kind)) continue;
        const spec = podSpecOf(doc); if (!spec) continue;
        const wl = `${doc.kind}/${nameOf(doc)}`;
        for (const k of ['hostNetwork', 'hostPID', 'hostIPC']) if (truthy(spec[k])) emitAt(flow, emit, lineOfKey(spec, k), { desc: `${wl} sets ${k}: true, sharing the node's ${k.replace('host', '').toLowerCase() || 'network'} namespace with the pod.`, sev: 'high' });
        asArray(spec.volumes).forEach((v, i) => {
          const hp = v?.hostPath?.path; if (!hp) return;
          emitAt(flow, emit, v.hostPath.$lines?.path || spec.volumes.$lines?.[i] || lineOfKey(spec, 'volumes'), { desc: `${wl} mounts the host path ${hp}${/docker\.sock/.test(hp) ? ' (the container runtime socket: root on the node)' : ''}.`, sev: SENS_HOSTPATH.test(hp) ? 'high' : 'medium' });
        });
        const podSC = isMap(spec.securityContext) ? spec.securityContext : {};
        for (const { c, line } of containersOf(spec)) {
          const sc = isMap(c.securityContext) ? c.securityContext : null; const cname = c.name || 'container';
          const L = (k) => (sc ? lineOfKey(sc, k) : line);
          if (sc && truthy(sc.privileged)) emitAt(flow, emit, L('privileged'), { desc: `Container "${cname}" in ${wl} runs privileged: true, which disables almost all isolation from the node.`, sev: 'critical' });
          if (sc && truthy(sc.allowPrivilegeEscalation)) emitAt(flow, emit, L('allowPrivilegeEscalation'), { desc: `Container "${cname}" in ${wl} explicitly allows privilege escalation.`, sev: 'high' });
          const uid = sc?.runAsUser ?? podSC.runAsUser;
          if (uid !== undefined && String(uid).trim() === '0') emitAt(flow, emit, sc && sc.runAsUser !== undefined ? L('runAsUser') : lineOfKey(podSC, 'runAsUser'), { desc: `Container "${cname}" in ${wl} runs as UID 0 (root).`, sev: 'high' });
          if ((sc && falsy(sc.runAsNonRoot) && sc.runAsNonRoot !== undefined)) emitAt(flow, emit, L('runAsNonRoot'), { desc: `Container "${cname}" in ${wl} sets runAsNonRoot: false.`, sev: 'high' });
          for (const cap of asArray(sc?.capabilities?.add)) if (DANGER_CAPS.test(String(cap))) emitAt(flow, emit, lineOfKey(sc.capabilities, 'add'), { desc: `Container "${cname}" in ${wl} adds the capability ${cap}.`, sev: /^(?:ALL|SYS_ADMIN)$/i.test(cap) ? 'high' : 'medium' });
          const prof = (sc?.seccompProfile?.type ?? podSC.seccompProfile?.type);
          if (/^Unconfined$/i.test(String(prof || ''))) emitAt(flow, emit, L('seccompProfile'), { desc: `Container "${cname}" in ${wl} runs with the Unconfined seccomp profile.`, sev: 'high' });
          // baseline hardening that is simply missing
          const missing = [];
          const nonRoot = sc?.runAsNonRoot ?? podSC.runAsNonRoot; const effUid = sc?.runAsUser ?? podSC.runAsUser;
          if (!truthy(nonRoot) && !(effUid !== undefined && String(effUid) !== '0')) missing.push('runAsNonRoot');
          if (!sc || sc.allowPrivilegeEscalation === undefined) missing.push('allowPrivilegeEscalation: false');
          if (!sc || !truthy(sc.readOnlyRootFilesystem)) missing.push('readOnlyRootFilesystem');
          if (!asArray(sc?.capabilities?.drop).some(d => /^ALL$/i.test(String(d)))) missing.push('capabilities.drop: [ALL]');
          if (missing.length >= 3) emitAt(flow, emit, line, { desc: `Container "${cname}" in ${wl} lacks baseline hardening: ${missing.join(', ')}.`, sev: 'medium', conf: 'medium' });
        }
      }
    } }),

  cfg({ id: 'k8s-exposure', cls: 'publicly exposed cloud resource', langs: ['k8s'], sev: 'medium', conf: 'medium', group: 'k8s', title: 'Workload exposed outside the cluster',
    fix: 'Expose services through an authenticated, TLS-terminating ingress; restrict LoadBalancer sources (loadBalancerSourceRanges) or make the load balancer internal; avoid NodePort, hostPort and externalIPs.',
    run(flow, emit) {
      for (const doc of k8sDocs(flow)) {
        const s = isMap(doc.spec) ? doc.spec : {};
        if (doc.kind === 'Service') {
          const t = String(s.type || '');
          const annos = JSON.stringify(doc.metadata?.annotations || {});
          const internal = /internal|load-balancer-scheme.*internal|azure-load-balancer-internal.*true|cloud\.google\.com\/load-balancer-type.*Internal/i.test(annos);
          if (t === 'LoadBalancer' && !internal && !asArray(s.loadBalancerSourceRanges).length) emitAt(flow, emit, lineOfKey(s, 'type'), { desc: `Service ${nameOf(doc)} is a public LoadBalancer with no loadBalancerSourceRanges, reachable from the whole internet.`, sev: 'medium' });
          else if (t === 'NodePort') emitAt(flow, emit, lineOfKey(s, 'type'), { desc: `Service ${nameOf(doc)} is a NodePort, opening a port on every node.`, sev: 'low', conf: 'low' });
          if (asArray(s.externalIPs).length) emitAt(flow, emit, lineOfKey(s, 'externalIPs'), { desc: `Service ${nameOf(doc)} sets externalIPs, which can be used to hijack traffic to arbitrary addresses.`, sev: 'medium' });
        } else if (doc.kind === 'Ingress') {
          if (!asArray(s.tls).length) emitAt(flow, emit, lineOfKey(doc, 'spec'), { desc: `Ingress ${nameOf(doc)} has no TLS configuration, so traffic is served over plain HTTP.`, sev: 'medium' });
          if (/ssl-redirect["']?\s*:\s*["']?false/i.test(JSON.stringify(doc.metadata?.annotations || {}))) emitAt(flow, emit, lineOfKey(doc, 'metadata'), { desc: `Ingress ${nameOf(doc)} disables the HTTP→HTTPS redirect.`, sev: 'medium' });
        } else if (WORKLOADS.has(doc.kind)) {
          const spec = podSpecOf(doc); if (!spec) continue;
          for (const { c, line } of containersOf(spec)) asArray(c.ports).forEach((p) => { if (isMap(p) && p.hostPort !== undefined) emitAt(flow, emit, lineOfKey(p, 'hostPort'), { desc: `Container "${c.name}" in ${doc.kind}/${nameOf(doc)} binds hostPort ${p.hostPort}, exposing it directly on the node.`, sev: 'medium', conf: 'high' }); });
        }
      }
    } }),

  cfg({ id: 'k8s-secret', cls: 'hardcoded secret in IaC template or variable', langs: ['k8s'], sev: 'high', conf: 'high', group: 'secret', title: 'Hardcoded secret in Kubernetes manifest',
    fix: 'Do not commit Secret values: use an external secret manager (External Secrets, Sealed Secrets, SOPS, Vault) and reference secrets through valueFrom/secretKeyRef.',
    run(flow, emit) {
      for (const doc of k8sDocs(flow)) {
        if (doc.kind === 'Secret') {
          for (const sect of ['data', 'stringData']) {
            const d = doc[sect]; if (!isMap(d)) continue;
            for (const [k, v] of Object.entries(d)) if (typeof v === 'string' && v.trim() !== '' && !isPlaceholder(v)) emitAt(flow, emit, lineOfKey(d, k), { redact: true, snippet: `${k}: ****`, desc: `Secret ${nameOf(doc)} contains a literal value for "${k}" committed in the manifest${sect === 'data' ? ' (base64 is encoding, not protection)' : ''}.` });
          }
        } else if (WORKLOADS.has(doc.kind)) {
          const spec = podSpecOf(doc); if (!spec) continue;
          for (const { c } of containersOf(spec)) asArray(c.env).forEach((e, i) => {
            if (!isMap(e) || e.value === undefined || e.valueFrom) return;
            if (SECRETISH.test(String(e.name)) && !isPlaceholder(e.value) && String(e.value).length >= 3 && !/_FILE$/i.test(e.name)) emitAt(flow, emit, c.env.$lines?.[i] || lineOfKey(c, 'env'), { redact: true, snippet: `${e.name}: ****`, desc: `Container "${c.name}" sets ${e.name} to a literal value in the pod spec; use valueFrom.secretKeyRef instead.` });
          });
        } else if (doc.kind === 'ConfigMap' && isMap(doc.data)) {
          for (const [k, v] of Object.entries(doc.data)) if (SECRETISH.test(k) && typeof v === 'string' && !isPlaceholder(v) && v.length >= 6 && !/\.(?:pem|crt|cert|yaml|json|conf|properties|ini)$/i.test(k)) emitAt(flow, emit, lineOfKey(doc.data, k), { redact: true, snippet: `${k}: ****`, desc: `ConfigMap ${nameOf(doc)} stores what looks like a credential ("${k}") in plain text.`, sev: 'medium', conf: 'medium' });
        }
      }
    } }),

  cfg({ id: 'k8s-rbac', cls: 'overly permissive IAM policy or RBAC', langs: ['k8s'], sev: 'high', conf: 'high', group: 'rbac', title: 'Overly permissive RBAC',
    fix: 'Grant least privilege: list the exact resources and verbs needed, avoid wildcards, avoid cluster-admin bindings and never bind roles to system:anonymous / system:unauthenticated / system:authenticated.',
    run(flow, emit) {
      for (const doc of k8sDocs(flow)) {
        if (doc.kind === 'Role' || doc.kind === 'ClusterRole') {
          asArray(doc.rules).forEach((r, i) => {
            if (!isMap(r)) return; const line = doc.rules.$lines?.[i] || lineOfKey(doc, 'rules');
            const verbs = asArray(r.verbs).map(String), res = asArray(r.resources).map(String), grp = asArray(r.apiGroups).map(String);
            const vStar = verbs.includes('*'), rStar = res.includes('*'), gStar = grp.includes('*');
            if (vStar && rStar) emitAt(flow, emit, line, { desc: `${doc.kind} ${nameOf(doc)} grants all verbs on all resources${gStar ? ' in all API groups' : ''} (effectively cluster-admin).`, sev: 'critical' });
            else if (vStar || rStar) emitAt(flow, emit, line, { desc: `${doc.kind} ${nameOf(doc)} uses a wildcard for ${vStar ? 'verbs' : 'resources'}.`, sev: 'high' });
            else if (verbs.some(v => /^(?:escalate|bind|impersonate)$/.test(v))) emitAt(flow, emit, line, { desc: `${doc.kind} ${nameOf(doc)} allows ${verbs.filter(v => /^(?:escalate|bind|impersonate)$/.test(v)).join('/')}, which lets the holder obtain more privileges.`, sev: 'high' });
            else if (res.some(x => /^(?:secrets)$/.test(x)) && verbs.some(v => /^(?:get|list|watch)$/.test(v)) && doc.kind === 'ClusterRole') emitAt(flow, emit, line, { desc: `ClusterRole ${nameOf(doc)} can read Secrets in every namespace.`, sev: 'medium' });
            else if (res.some(x => /^pods\/exec$|^pods\/attach$/.test(x)) && verbs.some(v => /^(?:create|\*)$/.test(v))) emitAt(flow, emit, line, { desc: `${doc.kind} ${nameOf(doc)} allows exec/attach into pods.`, sev: 'medium' });
          });
        } else if (doc.kind === 'RoleBinding' || doc.kind === 'ClusterRoleBinding') {
          const ref = doc.roleRef?.name;
          if (ref === 'cluster-admin') emitAt(flow, emit, lineOfKey(doc.roleRef, 'name'), { desc: `${doc.kind} ${nameOf(doc)} binds the cluster-admin role.`, sev: 'high' });
          asArray(doc.subjects).forEach((s, i) => {
            if (!isMap(s)) return; const line = doc.subjects.$lines?.[i] || lineOfKey(doc, 'subjects');
            if (/^system:(?:anonymous|unauthenticated)$/.test(String(s.name))) emitAt(flow, emit, line, { desc: `${doc.kind} ${nameOf(doc)} grants permissions to ${s.name}, i.e. to unauthenticated clients.`, sev: 'critical' });
            else if (s.name === 'system:authenticated') emitAt(flow, emit, line, { desc: `${doc.kind} ${nameOf(doc)} grants permissions to every authenticated user (system:authenticated).`, sev: 'high' });
            else if (s.kind === 'ServiceAccount' && s.name === 'default' && ref === 'cluster-admin') emitAt(flow, emit, line, { desc: `The default ServiceAccount is bound to cluster-admin.`, sev: 'critical' });
          });
        }
      }
    } }),

  cfg({ id: 'k8s-netpol', cls: 'missing Kubernetes network segmentation', langs: ['k8s'], sev: 'medium', conf: 'high', group: 'k8s', title: 'NetworkPolicy allows all traffic',
    fix: 'Start from a default-deny NetworkPolicy and allow only the required peers and ports; avoid empty rules and 0.0.0.0/0 ipBlocks.',
    run(flow, emit) {
      for (const doc of k8sDocs(flow)) {
        if (doc.kind !== 'NetworkPolicy' || !isMap(doc.spec)) continue;
        const s = doc.spec;
        for (const dir of ['ingress', 'egress']) {
          const rules = s[dir]; if (!Array.isArray(rules)) continue;
          rules.forEach((r, i) => {
            const line = rules.$lines?.[i] || lineOfKey(s, dir);
            const empty = r === null || r === '' || (isMap(r) && Object.keys(r).length === 0);
            const open = isMap(r) && asArray(r[dir === 'ingress' ? 'from' : 'to']).some(p => isMap(p) && isMap(p.ipBlock) && /^(?:0\.0\.0\.0\/0|::\/0)$/.test(String(p.ipBlock.cidr)));
            if (empty) emitAt(flow, emit, line, { desc: `NetworkPolicy ${nameOf(doc)} has an empty ${dir} rule that allows all ${dir} traffic.`, sev: dir === 'ingress' ? 'medium' : 'low' });
            else if (open) emitAt(flow, emit, line, { desc: `NetworkPolicy ${nameOf(doc)} allows ${dir} ${dir === 'ingress' ? 'from' : 'to'} 0.0.0.0/0.`, sev: dir === 'ingress' ? 'medium' : 'low' });
          });
        }
      }
    } }),

  cfg({ id: 'k8s-supply-chain', cls: 'insecure Kubernetes workload supply-chain hygiene', langs: ['k8s'], sev: 'medium', conf: 'high', group: 'k8s', title: 'Unpinned or unverifiable workload image',
    fix: 'Reference images by immutable digest (image@sha256:…) or at least a specific version tag from a trusted registry; do not use :latest; enforce signature verification with an admission policy.',
    run(flow, emit) {
      for (const doc of k8sDocs(flow)) {
        if (!WORKLOADS.has(doc.kind)) continue;
        const spec = podSpecOf(doc); if (!spec) continue;
        for (const { c } of containersOf(spec)) {
          const img = String(c.image || ''); if (!img || /\{\{|\$\{?\w/.test(img)) continue;
          const line = lineOfKey(c, 'image');
          if (/@sha256:[0-9a-f]{16,}/i.test(img)) continue;
          const last = img.split('/').pop();
          if (!/:[^/]+$/.test(last)) emitAt(flow, emit, line, { desc: `Container "${c.name}" uses image "${img}" without a tag (resolves to :latest).`, sev: 'medium' });
          else if (/:latest$/i.test(img)) emitAt(flow, emit, line, { desc: `Container "${c.name}" uses the mutable :latest tag (${img}).`, sev: 'medium' });
          if (String(c.imagePullPolicy || '') === 'IfNotPresent' && /:latest$/i.test(img)) emitAt(flow, emit, lineOfKey(c, 'imagePullPolicy'), { desc: `Container "${c.name}" combines :latest with imagePullPolicy IfNotPresent, so nodes keep running stale, unpatched images.`, sev: 'low' });
        }
      }
    } }),
];

// ═══ Terraform ═══════════════════════════════════════════════════════════════
const TF = ['iac'];
const isTf = (flow) => kindOf(flow) === 'terraform';
const WORLD = /(?:0\.0\.0\.0\/0|::\/0)/;
const lit = (s) => (s === undefined ? undefined : String(s).replace(/^["']|["']$/g, ''));
function tfBlocks(flow) {
  if (flow._tf) return flow._tf;
  return (flow._tf = parseHclBlocks(flow.ctx.code, flow.ctx.literal, flow.ctx.lineAt).map(b => b));
}
const tfRes = (flow) => tfBlocks(flow).filter(b => b.kind === 'resource');
const falseish = (a) => a && /^(?:false|"false")$/i.test(a.text.trim());
const trueish = (a) => a && /^(?:true|"true")$/i.test(a.text.trim());

function policyStatements(text) {
  // statements in JSON / jsonencode()/ heredoc policy text: balanced {...} objects that hold an Effect
  const out = []; const re = /\{/g; let m;
  while ((m = re.exec(text)) !== null) {
    let depth = 0, k = m.index;
    for (; k < text.length; k++) { if (text[k] === '{') depth++; else if (text[k] === '}') { depth--; if (depth === 0) break; } }
    const body = text.slice(m.index, k + 1);
    if (/["']?Effect["']?\s*[:=]\s*["']Allow["']/i.test(body) && !/\{[^{}]*["']?Effect["']?\s*[:=][^{}]*\{[^{}]*["']?Effect/i.test(body)) {
      const pick = (name) => { const mm = new RegExp(String.raw`["']?${name}["']?\s*[:=]\s*(\[[^\]]*\]|"[^"]*"|'[^']*')`, 'i').exec(body); return mm ? mm[1] : ''; };
      out.push({ action: pick('(?:Action|actions)'), resource: pick('(?:Resource|resources)'), principal: /["']?Principal["']?\s*[:=]\s*(\{[^}]*\}|"\*"|'\*')/i.exec(body)?.[1] || '', cond: /["']?Condition["']?\s*[:=]/i.test(body), index: m.index });
    }
  }
  return out;
}
const hasStar = (s) => /(?:^|[\[,\s"'])\*(?:[\]\s,"']|$)/.test(s) && !/\w:\*/.test(s.replace(/["'\[\]\s]/g, '').replace(/\*$/, 'X')) || /^["']\*["']$/.test(s.trim()) || /\[\s*["']\*["']\s*\]/.test(s);

const TF_RULES = [
  cfg({ id: 'tf-public', cls: 'publicly exposed cloud resource', langs: TF, sev: 'high', conf: 'high', group: 'iac', title: 'Publicly exposed cloud resource',
    fix: 'Keep storage private (block public access, no public ACLs or allUsers bindings), place databases and instances in private subnets, and expose services only through an authenticated front end.',
    run(flow, emit) {
      if (!isTf(flow)) return;
      const blocks = tfRes(flow);
      for (const b of blocks) {
        const t = b.type || '';
        const acl = lit(b.val('acl'));
        if (/^aws_s3_bucket(?:_acl)?$/.test(t) && /^public-read(?:-write)?$|^authenticated-read$/.test(acl || '')) emitAt(flow, emit, b.attr('acl').line, { desc: `S3 bucket ${b.name} has the ${acl} ACL, making its objects ${acl === 'authenticated-read' ? 'readable by any AWS account' : 'publicly accessible'}.`, sev: 'critical' });
        if (t === 'aws_s3_bucket_public_access_block') for (const k of ['block_public_acls', 'block_public_policy', 'ignore_public_acls', 'restrict_public_buckets']) { const a = b.attr(k); if (falseish(a)) emitAt(flow, emit, a.line, { desc: `S3 public access block ${b.name} sets ${k} = false, allowing public access to the bucket.`, sev: 'high' }); }
        if (/^aws_(?:db_instance|rds_cluster_instance|redshift_cluster|dms_replication_instance|elasticsearch_domain|opensearch_domain|mq_broker|neptune_cluster_instance|docdb_cluster_instance)$/.test(t)) { const a = b.attr('publicly_accessible'); if (trueish(a)) emitAt(flow, emit, a.line, { desc: `${t} ${b.name} is publicly_accessible = true, reachable from the internet.`, sev: 'high' }); }
        if (t === 'aws_instance' || t === 'aws_launch_template') { const a = b.attr('associate_public_ip_address'); if (trueish(a)) emitAt(flow, emit, a.line, { desc: `${t} ${b.name} is assigned a public IP address.`, sev: 'medium', conf: 'medium' }); }
        if (/^google_(?:storage_bucket|project|folder|organization|cloud_run|cloudfunctions\w*|bigquery_dataset|pubsub_\w+|kms_\w+|compute_\w+)_iam_(?:member|binding)$|^google_\w+_iam_(?:member|binding)$/.test(t)) {
          if (/allUsers|allAuthenticatedUsers/.test(b.bodyLit)) { const line = lineOfText(flow, b, /allUsers|allAuthenticatedUsers/); emitAt(flow, emit, line, { desc: `${t} ${b.name} grants access to allUsers / allAuthenticatedUsers (the public internet).`, sev: 'critical' }); }
        }
        if (/^azurerm_storage_account$/.test(t)) for (const k of ['allow_nested_items_to_be_public', 'allow_blob_public_access']) { const a = b.attr(k); if (trueish(a)) emitAt(flow, emit, a.line, { desc: `Storage account ${b.name} allows public blob access (${k} = true).`, sev: 'high' }); }
        if (/^azurerm_/.test(t)) { const a = b.attr('public_network_access_enabled'); if (trueish(a)) emitAt(flow, emit, a.line, { desc: `${t} ${b.name} has public network access enabled.`, sev: 'medium', conf: 'medium' }); }
        if (t === 'aws_eks_cluster') for (const v of b.sub('vpc_config')) { const a = v.attr('endpoint_public_access'); const c = v.attr('public_access_cidrs'); if (trueish(a) && (!c || WORLD.test(c.text))) emitAt(flow, emit, a.line, { desc: `EKS cluster ${b.name} exposes its API server publicly${c ? ' to 0.0.0.0/0' : ' with no CIDR restriction'}.`, sev: 'high' }); }
        if (t === 'aws_lambda_permission' && /^["']\*["']$/.test((b.attr('principal') || { text: '' }).text.trim())) emitAt(flow, emit, b.attr('principal').line, { desc: `Lambda permission ${b.name} allows any principal (*) to invoke the function.`, sev: 'high' });
        if (/^google_sql_database_instance$/.test(t)) { const m = /authorized_networks[\s\S]*?value\s*=\s*"?(0\.0\.0\.0\/0)"?/.exec(b.bodyLit); if (m) emitAt(flow, emit, lineOfText(flow, b, /0\.0\.0\.0\/0/), { desc: `Cloud SQL instance ${b.name} authorises 0.0.0.0/0 to connect.`, sev: 'high' }); }
        // resource policies with Principal "*"
        if (/(?:policy|bucket_policy|topic_policy|queue_policy|repository_policy|key_policy)$|^aws_(?:s3_bucket_policy|sns_topic_policy|sqs_queue_policy|ecr_repository_policy|kms_key|glacier_vault|secretsmanager_secret_policy|elasticsearch_domain_policy|opensearch_domain_access_policy)$/.test(t) && !/^aws_iam_/.test(t)) {
          for (const s of policyStatements(b.bodyLit)) if (/\*/.test(s.principal) && !s.cond && /^(?:\{\s*["']?(?:AWS|"AWS")["']?\s*[:=]\s*["']\*["']\s*\}|["']\*["']|'\*'|\{[^}]*\*[^}]*\})$/.test(s.principal.trim())) emitAt(flow, emit, lineOfText(flow, b, /\*/, s.index), { desc: `${t} ${b.name} has an Allow statement for Principal "*" with no Condition, making the resource accessible to anyone.`, sev: 'high' });
        }
      }
    } }),

  cfg({ id: 'tf-secret', cls: 'hardcoded secret in IaC template or variable', langs: TF, sev: 'high', conf: 'high', group: 'secret', title: 'Hardcoded secret in Terraform',
    fix: 'Never commit credentials: pass them as sensitive variables from the environment/CI, read them from a secret manager data source, and mark the variable/output sensitive = true. Rotate anything already committed.',
    run(flow, emit) {
      if (!isTf(flow)) return;
      const L = litLines(flow);
      for (const b of tfBlocks(flow)) {
        if (b.kind === 'variable') {
          const d = b.attr('default'); const nm = b.labels[0] || '';
          if (d && SECRETISH.test(nm) && /^["'][^"']{4,}["']$/.test(d.text.trim()) && !isPlaceholder(d.text)) emitAt(flow, emit, d.line, { redact: true, snippet: `default = "****"`, desc: `Variable "${nm}" has a hardcoded default value that looks like a credential.` });
          continue;
        }
        if (!['resource', 'provider', 'module', 'locals', 'data', 'output'].includes(b.kind)) continue;
        const re = /(^|\n)[ \t]*([A-Za-z_][\w-]*)[ \t]*=[ \t]*("(?:[^"\\\n]|\\.)*"|'[^'\n]*')/g; let mm;
        while ((mm = re.exec(b.bodyLit)) !== null) {
          const key = mm[2], val = mm[3].slice(1, -1);
          if (!SECRETISH.test(key) || /(?:_id|_arn|_name|_url|_type|_enabled|_length|_policy|_secret_name|_secret_id|_key_id|_algorithm|_rotation|_rules|_version|_ref|_path|_file|_source)$/i.test(key) && !/(?:password|secret|token|key)$/i.test(key)) continue;
          if (isPlaceholder(val) || val.length < 4 || /^\$\{/.test(val) || /^(?:true|false|\d+)$/i.test(val) || /^arn:/.test(val)) continue;
          const line = flow.ctx.lineAt(b.bodyStart + mm.index + mm[1].length);
          emitAt(flow, emit, line, { redact: true, desc: `${b.kind === 'provider' ? 'Provider' : b.type || b.kind} ${b.name || b.labels[0] || ''} sets ${key} to a literal string in the template.` });
        }
      }
    } }),

  cfg({ id: 'tf-encryption', cls: 'disabled encryption at rest or in transit (IaC)', langs: TF, sev: 'medium', conf: 'high', group: 'iac', title: 'Encryption disabled or not configured',
    fix: 'Enable encryption at rest (storage_encrypted / encrypted with a KMS key) and enforce TLS 1.2+ for all listeners, distributions and storage endpoints.',
    run(flow, emit) {
      if (!isTf(flow)) return;
      const blocks = tfRes(flow); const all = flow.ctx.literal;
      for (const b of blocks) {
        const t = b.type || '';
        const need = (attr, why, sev = 'medium', conf = 'high') => { const a = b.attr(attr); if (falseish(a)) emitAt(flow, emit, a.line, { desc: `${t} ${b.name}: ${attr} = false — ${why}.`, sev, conf }); else if (!a) emitAt(flow, emit, b.line, { desc: `${t} ${b.name} does not set ${attr}, and the default is unencrypted — ${why}.`, sev, conf: 'medium' }); };
        if (t === 'aws_db_instance' || t === 'aws_rds_cluster') need('storage_encrypted', 'database storage is not encrypted at rest', 'medium');
        if (t === 'aws_ebs_volume' || t === 'aws_efs_file_system' || t === 'aws_redshift_cluster') need('encrypted', 'the volume/file system is not encrypted at rest', 'medium');
        if (t === 'aws_elasticache_replication_group') { need('at_rest_encryption_enabled', 'cache data is stored unencrypted', 'medium'); need('transit_encryption_enabled', 'cache traffic is not encrypted', 'medium'); }
        if (t === 'aws_sqs_queue') { const a = b.attr('sqs_managed_sse_enabled'); if (falseish(a)) emitAt(flow, emit, a.line, { desc: `SQS queue ${b.name} disables server-side encryption.`, sev: 'medium' }); }
        if (t === 'aws_kinesis_stream') { const a = b.attr('encryption_type'); if (!a || /NONE/i.test(a.text)) emitAt(flow, emit, a ? a.line : b.line, { desc: `Kinesis stream ${b.name} is not encrypted.`, sev: 'medium', conf: a ? 'high' : 'medium' }); }
        if (t === 'aws_dynamodb_table') for (const s of b.sub('server_side_encryption')) { const a = s.attr('enabled'); if (falseish(a)) emitAt(flow, emit, a.line, { desc: `DynamoDB table ${b.name} disables server-side encryption.`, sev: 'medium' }); }
        if (t === 'aws_s3_bucket' && !b.sub('server_side_encryption_configuration').length && !/aws_s3_bucket_server_side_encryption_configuration/.test(all)) emitAt(flow, emit, b.line, { desc: `S3 bucket ${b.name} has no server-side encryption configuration in this file.`, sev: 'low', conf: 'low' });
        if (/^aws_(?:lb|alb)_listener$/.test(t)) { const p = lit(b.val('protocol')); if (p === 'HTTP' && !/redirect/.test(b.bodyLit)) emitAt(flow, emit, b.attr('protocol').line, { desc: `Load balancer listener ${b.name} serves plain HTTP without redirecting to HTTPS.`, sev: 'medium' }); }
        if (t === 'aws_cloudfront_distribution') {
          if (/viewer_protocol_policy\s*=\s*"allow-all"/.test(b.bodyLit)) emitAt(flow, emit, lineOfText(flow, b, /allow-all/), { desc: `CloudFront distribution ${b.name} allows plain HTTP (viewer_protocol_policy = "allow-all").`, sev: 'medium' });
          const mp = /minimum_protocol_version\s*=\s*"(TLSv1(?:_2016|\.1_2016)?|TLSv1\.1_2016|SSLv3)"/.exec(b.bodyLit); if (mp) emitAt(flow, emit, lineOfText(flow, b, /minimum_protocol_version/), { desc: `CloudFront distribution ${b.name} accepts the obsolete protocol ${mp[1]}.`, sev: 'medium' });
        }
        if (t === 'aws_lb_listener' || t === 'aws_alb_listener') { const sp = lit(b.val('ssl_policy')); if (sp && /(?:TLS-1-0|TLS-1-1|2015-05|2016-08|ELBSecurityPolicy-2016|ELBSecurityPolicy-TLS-1-0)/.test(sp)) emitAt(flow, emit, b.attr('ssl_policy').line, { desc: `Listener ${b.name} uses the legacy TLS policy ${sp}.`, sev: 'medium' }); }
        if (t === 'azurerm_storage_account') { const a = b.attr('enable_https_traffic_only') || b.attr('https_traffic_only_enabled'); if (falseish(a)) emitAt(flow, emit, a.line, { desc: `Storage account ${b.name} permits plain-HTTP access.`, sev: 'high' }); const tl = lit(b.val('min_tls_version')); if (tl && /TLS1_[01]/.test(tl)) emitAt(flow, emit, b.attr('min_tls_version').line, { desc: `Storage account ${b.name} allows ${tl}.`, sev: 'medium' }); }
        if (/^azurerm_(?:app_service|linux_web_app|windows_web_app|function_app|linux_function_app)$/.test(t)) { const a = b.attr('https_only'); if (falseish(a)) emitAt(flow, emit, a.line, { desc: `${t} ${b.name} does not require HTTPS (https_only = false).`, sev: 'medium' }); }
        if (t === 'google_sql_database_instance') { const m = /require_ssl\s*=\s*false/.exec(b.bodyLit) || /ssl_mode\s*=\s*"ALLOW_UNENCRYPTED_AND_ENCRYPTED"/.exec(b.bodyLit); if (m) emitAt(flow, emit, lineOfText(flow, b, /require_ssl|ssl_mode/), { desc: `Cloud SQL instance ${b.name} accepts unencrypted connections.`, sev: 'medium' }); }
        if (t === 'google_compute_ssl_policy') { const mv = lit(b.val('min_tls_version')); if (mv && /TLS_1_[01]/.test(mv)) emitAt(flow, emit, b.attr('min_tls_version').line, { desc: `SSL policy ${b.name} allows ${mv}.`, sev: 'medium' }); }
      }
    } }),

  cfg({ id: 'tf-iam', cls: 'overly permissive IAM policy or RBAC', langs: TF, sev: 'high', conf: 'high', group: 'iac', title: 'Overly permissive IAM policy',
    fix: 'Apply least privilege: list the specific actions and resource ARNs required, avoid "*" actions and resources, never attach AdministratorAccess to workload roles, and scope Principals to named accounts/services.',
    run(flow, emit) {
      if (!isTf(flow)) return;
      for (const b of tfBlocks(flow)) {
        const t = b.type || '';
        if (b.kind === 'resource' && /^aws_iam_(?:role_policy_attachment|user_policy_attachment|group_policy_attachment|policy_attachment)$/.test(t)) { const a = b.attr('policy_arn'); if (a && /(?:AdministratorAccess|IAMFullAccess|PowerUserAccess)\b/.test(a.text)) emitAt(flow, emit, a.line, { desc: `${t} ${b.name} attaches a broad AWS managed policy (${/AdministratorAccess/.test(a.text) ? 'AdministratorAccess' : /IAMFullAccess/.test(a.text) ? 'IAMFullAccess' : 'PowerUserAccess'}).`, sev: /AdministratorAccess|IAMFullAccess/.test(a.text) ? 'high' : 'medium' }); }
        if (b.kind === 'resource' && /^google_(?:project|folder|organization)_iam_(?:member|binding)$/.test(t)) { const a = b.attr('role'); if (a && /roles\/(?:owner|editor|iam\.securityAdmin|iam\.serviceAccountTokenCreator|iam\.serviceAccountUser|resourcemanager\.\w*Admin)\b/.test(a.text)) emitAt(flow, emit, a.line, { desc: `${t} ${b.name} grants the broad role ${lit(a.text)}.`, sev: /owner/.test(a.text) ? 'high' : 'medium' }); }
        if (b.kind === 'resource' && t === 'azurerm_role_assignment') { const a = b.attr('role_definition_name'); if (a && /["'](?:Owner|Contributor|User Access Administrator)["']/.test(a.text)) emitAt(flow, emit, a.line, { desc: `Role assignment ${b.name} grants ${lit(a.text)}${/subscription|\/subscriptions\/[^/"]+["']?\s*$/.test(b.bodyLit) ? ' at subscription scope' : ''}.`, sev: 'medium', conf: 'medium' }); }
        if (b.kind === 'data' && t === 'aws_iam_policy_document') {
          for (const st of b.sub('statement')) {
            const eff = lit(st.val('effect')); if (eff && !/^Allow$/i.test(eff)) continue;
            const act = (st.attr('actions') || { text: '' }).text, res = (st.attr('resources') || { text: '' }).text;
            const aStar = /\[\s*"\*"\s*\]|"\*"/.test(act), rStar = /\[\s*"\*"\s*\]|"\*"/.test(res);
            const svcStar = /"(?:iam|sts|kms|s3|ec2|lambda|organizations|secretsmanager):\*"/.exec(act);
            const line = (st.attr('actions') || st.attr('resources') || { line: st.line }).line;
            if (aStar && rStar) emitAt(flow, emit, line, { desc: `Policy document ${b.name} allows every action on every resource.`, sev: 'critical' });
            else if (aStar) emitAt(flow, emit, line, { desc: `Policy document ${b.name} allows every action ("*").`, sev: 'high' });
            else if (svcStar) emitAt(flow, emit, line, { desc: `Policy document ${b.name} allows all actions of a service (${svcStar[0].replace(/"/g, '')})${rStar ? ' on every resource' : ''}.`, sev: /iam|sts|organizations/.test(svcStar[0]) ? 'high' : 'medium' });
            for (const pr of st.sub('principals')) if (/identifiers\s*=\s*\[\s*"\*"\s*\]/.test(pr.bodyLit) && !st.sub('condition').length) emitAt(flow, emit, pr.line, { desc: `Policy document ${b.name} allows Principal "*" with no condition.`, sev: 'high' });
          }
        }
        if (b.kind === 'resource' && /^aws_iam_(?:policy|role_policy|user_policy|group_policy|role)$/.test(t)) {
          for (const s of policyStatements(b.bodyLit)) {
            const aStar = /^\s*(?:\[\s*)?["']\*["']\s*\]?\s*$/.test(s.action), rStar = /^\s*(?:\[\s*)?["']\*["']\s*\]?\s*$/.test(s.resource);
            const svc = /["'](?:iam|sts|organizations):\*["']/.exec(s.action);
            const line = lineOfText(flow, b, /Action|actions/, s.index);
            if (aStar && rStar) emitAt(flow, emit, line, { desc: `IAM policy ${b.name} allows Action "*" on Resource "*" (full administrator).`, sev: 'critical' });
            else if (aStar) emitAt(flow, emit, line, { desc: `IAM policy ${b.name} allows Action "*".`, sev: 'high' });
            else if (svc) emitAt(flow, emit, line, { desc: `IAM policy ${b.name} allows all ${svc[0].replace(/["']/g, '')} actions, which enables privilege escalation.`, sev: 'high' });
            else if (rStar && /["'](?:iam:PassRole|sts:AssumeRole|kms:\*|s3:\*|ec2:\*|lambda:\*|secretsmanager:\*)["']/.test(s.action)) emitAt(flow, emit, line, { desc: `IAM policy ${b.name} grants powerful actions on every resource ("*").`, sev: 'medium' });
          }
          for (const s of policyStatements(b.bodyLit)) if (/assume_role_policy/.test(b.bodyLit.slice(Math.max(0, s.index - 200), s.index)) && /\*/.test(s.principal) && !s.cond) emitAt(flow, emit, lineOfText(flow, b, /Principal/, s.index), { desc: `Role ${b.name} can be assumed by any principal ("*").`, sev: 'critical' });
        }
      }
    } }),

  cfg({ id: 'tf-network', cls: 'insecure network exposure or unencrypted state (Terraform)', langs: TF, sev: 'high', conf: 'high', group: 'iac', title: 'Insecure network exposure or unprotected Terraform state',
    fix: 'Restrict ingress to known CIDRs and ports (never 0.0.0.0/0 for SSH, RDP or databases); store state in an encrypted, access-controlled remote backend and mark secret outputs sensitive = true.',
    run(flow, emit) {
      if (!isTf(flow)) return;
      const SENSITIVE_PORTS = new Set([22, 3389, 23, 21, 3306, 5432, 1433, 1521, 27017, 6379, 9200, 5601, 2375, 2376, 5900, 445, 139, 11211, 9092, 2181, 8500]);
      const portSpan = (from, to) => { const f = parseInt(from, 10), t = parseInt(to, 10); if (Number.isNaN(f) || Number.isNaN(t)) return null; return [f, t]; };
      const checkRule = (owner, rb, label) => {
        const cidr = rb.attr('cidr_blocks') || rb.attr('ipv6_cidr_blocks') || rb.attr('source_ranges');
        if (!cidr || !WORLD.test(cidr.text)) return;
        const proto = lit(rb.val('protocol')); const span = portSpan(rb.val('from_port'), rb.val('to_port'));
        const all = proto === '-1' || (span && span[0] <= 0 && span[1] >= 65535) || (span && span[0] === 0 && span[1] === 0 && proto === '-1');
        const hit = span ? [...SENSITIVE_PORTS].filter(p => p >= span[0] && p <= span[1]) : [];
        if (all) emitAt(flow, emit, cidr.line, { desc: `${label} allows ingress on all ports from 0.0.0.0/0.`, sev: 'critical' });
        else if (hit.length && span[1] - span[0] < 10) emitAt(flow, emit, cidr.line, { desc: `${label} exposes port ${span[0] === span[1] ? span[0] : span[0] + '-' + span[1]} to the whole internet (0.0.0.0/0).`, sev: 'critical' });
        else if (span && !(span[0] === span[1] && (span[0] === 80 || span[0] === 443))) emitAt(flow, emit, cidr.line, { desc: `${label} allows ingress from 0.0.0.0/0 on ports ${span[0]}-${span[1]}.`, sev: 'high', conf: 'medium' });
      };
      for (const b of tfBlocks(flow)) {
        const t = b.type || '';
        if (b.kind === 'resource' && t === 'aws_security_group') for (const ing of b.sub('ingress')) checkRule(b, ing, `Security group ${b.name}`);
        if (b.kind === 'resource' && t === 'aws_security_group_rule' && /ingress/.test(lit(b.val('type')) || '')) checkRule(b, b, `Security group rule ${b.name}`);
        if (b.kind === 'resource' && t === 'aws_vpc_security_group_ingress_rule') { const c = b.attr('cidr_ipv4') || b.attr('cidr_ipv6'); if (c && WORLD.test(c.text)) { const fp = lit(b.val('from_port')), tp = lit(b.val('to_port')); const sp = portSpan(fp, tp); emitAt(flow, emit, c.line, { desc: `Security group rule ${b.name} allows ingress from the whole internet${sp ? ' on port ' + fp + (fp !== tp ? '-' + tp : '') : ''}.`, sev: sp && [...SENSITIVE_PORTS].some(p => p >= sp[0] && p <= sp[1]) || lit(b.val('ip_protocol')) === '-1' ? 'critical' : 'high' }); } }
        if (b.kind === 'resource' && t === 'google_compute_firewall' && /INGRESS/i.test(b.bodyLit + 'INGRESS')) { const sr = b.attr('source_ranges'); if (sr && WORLD.test(sr.text)) emitAt(flow, emit, sr.line, { desc: `Firewall rule ${b.name} allows ingress from 0.0.0.0/0${/ports\s*=\s*\[[^\]]*"(?:22|3389|3306|5432)"/.test(b.bodyLit) ? ' to a sensitive port' : ''}.`, sev: /ports\s*=\s*\[[^\]]*"(?:22|3389|3306|5432|6379|27017)"/.test(b.bodyLit) || !/ports\s*=/.test(b.bodyLit) ? 'critical' : 'high' }); }
        if (b.kind === 'resource' && /^azurerm_network_security_rule$/.test(t) && /Inbound/i.test(b.bodyLit) && /access\s*=\s*"Allow"/i.test(b.bodyLit)) { const sp = b.attr('source_address_prefix'); if (sp && /^["'](?:\*|0\.0\.0\.0\/0|Internet|any)["']$/i.test(sp.text.trim())) { const dp = lit(b.val('destination_port_range')); emitAt(flow, emit, sp.line, { desc: `NSG rule ${b.name} allows inbound traffic from the internet${dp ? ' on port ' + dp : ''}.`, sev: dp === '*' || SENSITIVE_PORTS.has(parseInt(dp, 10)) ? 'critical' : 'high' }); } }
        if (b.kind === 'resource' && t === 'azurerm_network_security_group') for (const r of b.sub('security_rule')) if (/Inbound/i.test(r.bodyLit) && /access\s*=\s*"Allow"/i.test(r.bodyLit)) { const sp = r.attr('source_address_prefix'); if (sp && /^["'](?:\*|0\.0\.0\.0\/0|Internet|any)["']$/i.test(sp.text.trim())) emitAt(flow, emit, sp.line, { desc: `NSG ${b.name} allows inbound traffic from the internet.`, sev: 'high' }); }
        if (b.kind === 'terraform') for (const be of b.sub('backend')) {
          const kind = be.labels[0];
          if (kind === 's3' && !trueish(be.attr('encrypt'))) emitAt(flow, emit, be.line, { desc: 'The S3 backend does not set encrypt = true, so the Terraform state (which contains secrets) is stored unencrypted.', sev: 'medium' });
          if (kind === 'local') emitAt(flow, emit, be.line, { desc: 'Terraform state is kept in a local backend; it contains secrets in plain text and is easily committed or lost.', sev: 'low', conf: 'low' });
          const addr = be.attr('address'); if (kind === 'http' && addr && /["']http:\/\//.test(addr.text)) emitAt(flow, emit, addr.line, { desc: 'The HTTP state backend uses a plain-HTTP address; state is sent unencrypted.', sev: 'high' });
        }
        if (b.kind === 'provider') for (const k of ['skip_tls_verify', 'insecure', 'insecure_skip_tls_verify', 'skip_ssl_validation', 'allow_unverified_ssl', 'insecure_https']) { const a = b.attr(k); if (trueish(a)) emitAt(flow, emit, a.line, { desc: `Provider ${b.labels[0]} sets ${k} = true, disabling TLS certificate validation.`, sev: 'high' }); }
        if (b.kind === 'output' && SECRETISH.test(b.labels[0] || '') && !trueish(b.attr('sensitive'))) emitAt(flow, emit, b.line, { desc: `Output "${b.labels[0]}" looks like a secret but is not marked sensitive = true, so its value is printed in plan/apply logs and stored in state.`, sev: 'medium', conf: 'medium' });
      }
    } }),
];

function lineOfText(flow, block, re, from = 0) {
  const body = block.bodyLit; const mm = re.exec(body.slice(from)); const off = block.bodyStart + (mm ? from + mm.index : 0);
  return flow.ctx.lineAt(off);
}

// ═══ CloudFormation (YAML / JSON) ════════════════════════════════════════════
function cfnResources(flow) {
  if (flow._cfn) return flow._cfn;
  let res = [];
  let root = null;
  if (/\.json$/i.test(flow.chunk.file || '')) { try { root = JSON.parse(flow.chunk.code); } catch { root = null; } }
  else { const d = parseYamlDocs(flow.ctx.literal)[0]; root = d?.doc || null; }
  if (isMap(root) && isMap(root.Resources)) for (const [name, r] of Object.entries(root.Resources)) if (isMap(r) && r.Type) res.push({ name, type: String(r.Type), props: isMap(r.Properties) ? r.Properties : {}, r, line: lineOfKey(root.Resources, name) });
  return (flow._cfn = { root, res });
}
const isCfn = (flow) => kindOf(flow) === 'cloudformation';
const LITSTR = (v) => typeof v === 'string' && !isPlaceholder(v);

const CFN_RULES = [
  cfg({ id: 'cfn-public', cls: 'publicly exposed cloud resource', langs: TF, sev: 'high', conf: 'high', group: 'iac', title: 'Publicly exposed cloud resource',
    fix: 'Keep buckets and databases private, scope security group ingress to known CIDRs, and never use Principal "*" without a restrictive Condition.',
    run(flow, emit) {
      if (!isCfn(flow)) return;
      for (const { name, type, props, line } of cfnResources(flow).res) {
        const pl = (k) => lineOfKey(props, k) || line;
        if (type === 'AWS::S3::Bucket' && /^(?:PublicRead|PublicReadWrite|AuthenticatedRead)$/.test(String(props.AccessControl || ''))) emitAt(flow, emit, pl('AccessControl'), { desc: `S3 bucket ${name} has AccessControl ${props.AccessControl}.`, sev: 'critical' });
        if (type === 'AWS::S3::Bucket' && isMap(props.PublicAccessBlockConfiguration)) for (const k of ['BlockPublicAcls', 'BlockPublicPolicy', 'IgnorePublicAcls', 'RestrictPublicBuckets']) if (falsy(props.PublicAccessBlockConfiguration[k]) && props.PublicAccessBlockConfiguration[k] !== undefined) emitAt(flow, emit, lineOfKey(props.PublicAccessBlockConfiguration, k), { desc: `S3 bucket ${name} sets ${k}: false.`, sev: 'high' });
        if (/^AWS::(?:RDS::DBInstance|Redshift::Cluster|Elasticsearch::Domain|DMS::ReplicationInstance|MSK::Cluster)$/.test(type) && truthy(props.PubliclyAccessible)) emitAt(flow, emit, pl('PubliclyAccessible'), { desc: `${type} ${name} is PubliclyAccessible: true.`, sev: 'high' });
        if (/^AWS::EC2::SecurityGroup(?:Ingress)?$/.test(type)) {
          const rules = type.endsWith('Ingress') ? [props] : asArray(props.SecurityGroupIngress);
          rules.forEach((r) => { if (!isMap(r)) return; const cidr = String(r.CidrIp ?? r.CidrIpv6 ?? ''); if (!WORLD.test(cidr)) return; const fp = parseInt(r.FromPort, 10), tp = parseInt(r.ToPort, 10); const allp = String(r.IpProtocol) === '-1'; const sens = [22, 3389, 3306, 5432, 1433, 27017, 6379, 9200, 2375].some(p => p >= fp && p <= tp);
            if (allp || sens) emitAt(flow, emit, lineOfKey(r, 'CidrIp') || line, { desc: `Security group ${name} allows ${allp ? 'all traffic' : 'port ' + fp + (fp !== tp ? '-' + tp : '')} from the whole internet (${cidr}).`, sev: 'critical' });
            else if (!(fp === tp && (fp === 80 || fp === 443))) emitAt(flow, emit, lineOfKey(r, 'CidrIp') || line, { desc: `Security group ${name} allows ingress from ${cidr} on ports ${fp}-${tp}.`, sev: 'high', conf: 'medium' }); });
        }
        if (/Policy$/.test(type) || type === 'AWS::S3::BucketPolicy' || type === 'AWS::SQS::QueuePolicy' || type === 'AWS::SNS::TopicPolicy') {
          for (const st of cfnStatements(props.PolicyDocument)) if (isMap(st) && /^Allow$/i.test(String(st.Effect)) && (st.Principal === '*' || (isMap(st.Principal) && (asArray(st.Principal.AWS).includes('*')))) && !st.Condition && !/^AWS::IAM::/.test(type)) emitAt(flow, emit, lineOfKey(props, 'PolicyDocument'), { desc: `${type} ${name} allows Principal "*" with no Condition.`, sev: 'high' });
        }
      }
    } }),
  cfg({ id: 'cfn-secret', cls: 'hardcoded secret in IaC template or variable', langs: TF, sev: 'high', conf: 'high', group: 'secret', title: 'Hardcoded secret in CloudFormation template',
    fix: 'Use dynamic references ({{resolve:secretsmanager:…}} / {{resolve:ssm-secure:…}}) or generate the secret with AWS::SecretsManager::Secret GenerateSecretString instead of literal values.',
    run(flow, emit) {
      if (!isCfn(flow)) return;
      const { root, res } = cfnResources(flow);
      const scan = (obj, owner, seen = 0) => { if (!isMap(obj) || seen > 6) return; for (const [k, v] of Object.entries(obj)) { if (typeof v === 'string') { if (SECRETISH.test(k) && !/(?:Arn|Name|Id|Type|Policy|Enabled|Length|Rotation|Version|Path|Source)$/i.test(k) && LITSTR(v) && v.length >= 4 && !/^(?:true|false|\d+)$/i.test(v) && !/^\{\{resolve:/.test(v)) emitAt(flow, emit, lineOfKey(obj, k), { redact: true, desc: `${owner} sets ${k} to a literal string.` }); } else if (isMap(v)) scan(v, owner, seen + 1); else if (Array.isArray(v)) v.forEach(x => scan(x, owner, seen + 1)); } };
      for (const r of res) scan(r.props, `${r.type} ${r.name}`);
      if (isMap(root?.Parameters)) for (const [n, p] of Object.entries(root.Parameters)) if (isMap(p) && SECRETISH.test(n) && p.Default !== undefined && LITSTR(String(p.Default)) && String(p.Default).length >= 4) emitAt(flow, emit, lineOfKey(p, 'Default'), { redact: true, desc: `Parameter ${n} has a hardcoded Default value.` });
    } }),
  cfg({ id: 'cfn-encryption', cls: 'disabled encryption at rest or in transit (IaC)', langs: TF, sev: 'medium', conf: 'high', group: 'iac', title: 'Encryption disabled or not configured',
    fix: 'Enable encryption at rest with a KMS key and enforce HTTPS/TLS 1.2+ on all listeners and distributions.',
    run(flow, emit) {
      if (!isCfn(flow)) return;
      for (const { name, type, props, line } of cfnResources(flow).res) {
        const pl = (k) => lineOfKey(props, k) || line;
        if (/^AWS::RDS::(?:DBInstance|DBCluster)$/.test(type) && !truthy(props.StorageEncrypted)) emitAt(flow, emit, pl('StorageEncrypted'), { desc: `${type} ${name} does not enable StorageEncrypted.`, sev: 'medium', conf: props.StorageEncrypted === undefined ? 'medium' : 'high' });
        if (/^AWS::(?:EC2::Volume|EFS::FileSystem|Redshift::Cluster)$/.test(type) && !truthy(props.Encrypted)) emitAt(flow, emit, pl('Encrypted'), { desc: `${type} ${name} does not enable Encrypted.`, sev: 'medium', conf: props.Encrypted === undefined ? 'medium' : 'high' });
        if (type === 'AWS::S3::Bucket' && !props.BucketEncryption) emitAt(flow, emit, line, { desc: `S3 bucket ${name} has no BucketEncryption configuration.`, sev: 'low', conf: 'low' });
        if (type === 'AWS::SQS::Queue' && !props.KmsMasterKeyId && !truthy(props.SqsManagedSseEnabled)) emitAt(flow, emit, line, { desc: `SQS queue ${name} has no server-side encryption.`, sev: 'low', conf: 'low' });
        if (type === 'AWS::ElastiCache::ReplicationGroup') { if (!truthy(props.AtRestEncryptionEnabled)) emitAt(flow, emit, pl('AtRestEncryptionEnabled'), { desc: `ElastiCache group ${name} has no at-rest encryption.`, sev: 'medium' }); if (!truthy(props.TransitEncryptionEnabled)) emitAt(flow, emit, pl('TransitEncryptionEnabled'), { desc: `ElastiCache group ${name} has no in-transit encryption.`, sev: 'medium' }); }
        if (type === 'AWS::CloudFront::Distribution') { const dcb = props.DistributionConfig; const beh = [dcb?.DefaultCacheBehavior, ...asArray(dcb?.CacheBehaviors)].filter(isMap); for (const bh of beh) if (String(bh.ViewerProtocolPolicy) === 'allow-all') emitAt(flow, emit, lineOfKey(bh, 'ViewerProtocolPolicy'), { desc: `CloudFront ${name} allows plain HTTP (ViewerProtocolPolicy allow-all).`, sev: 'medium' }); }
        if (/^AWS::ElasticLoadBalancingV2::Listener$/.test(type) && String(props.Protocol) === 'HTTP' && !/redirect/i.test(JSON.stringify(props.DefaultActions || ''))) emitAt(flow, emit, pl('Protocol'), { desc: `Listener ${name} serves plain HTTP without redirecting to HTTPS.`, sev: 'medium' });
      }
    } }),
  cfg({ id: 'cfn-iam', cls: 'overly permissive IAM policy or RBAC', langs: TF, sev: 'high', conf: 'high', group: 'iac', title: 'Overly permissive IAM policy',
    fix: 'Grant least privilege: enumerate the required actions and resources; avoid "*" actions/resources and AdministratorAccess.',
    run(flow, emit) {
      if (!isCfn(flow)) return;
      for (const { name, type, props, line } of cfnResources(flow).res) {
        if (!/^AWS::IAM::(?:Policy|ManagedPolicy|Role|User|Group)$/.test(type)) continue;
        for (const arn of asArray(props.ManagedPolicyArns)) if (/(?:AdministratorAccess|IAMFullAccess)$/.test(String(arn))) emitAt(flow, emit, lineOfKey(props, 'ManagedPolicyArns'), { desc: `${type} ${name} attaches ${String(arn).split('/').pop()}.`, sev: 'high' });
        const docs = [props.PolicyDocument, ...asArray(props.Policies).map(p => p?.PolicyDocument)];
        for (const d of docs) for (const st of cfnStatements(d)) {
          if (!isMap(st) || !/^Allow$/i.test(String(st.Effect))) continue;
          const acts = asArray(st.Action).map(String), res = asArray(st.Resource).map(String);
          const aStar = acts.includes('*'), rStar = res.includes('*');
          if (aStar && rStar) emitAt(flow, emit, lineOfKey(props, 'PolicyDocument') || line, { desc: `${type} ${name} allows every action on every resource.`, sev: 'critical' });
          else if (aStar) emitAt(flow, emit, line, { desc: `${type} ${name} allows Action "*".`, sev: 'high' });
          else if (acts.some(a => /^(?:iam|sts|organizations):\*$/.test(a))) emitAt(flow, emit, line, { desc: `${type} ${name} allows ${acts.find(a => /^(?:iam|sts|organizations):\*$/.test(a))}, enabling privilege escalation.`, sev: 'high' });
        }
        for (const st of cfnStatements(props.AssumeRolePolicyDocument)) if (isMap(st) && /^Allow$/i.test(String(st.Effect)) && !st.Condition && (st.Principal === '*' || (isMap(st.Principal) && asArray(st.Principal.AWS).includes('*')))) emitAt(flow, emit, lineOfKey(props, 'AssumeRolePolicyDocument'), { desc: `Role ${name} can be assumed by any principal.`, sev: 'critical' });
      }
    } }),
];
function cfnStatements(doc) { if (!isMap(doc)) return []; const s = doc.Statement; return Array.isArray(s) ? s : isMap(s) ? [s] : []; }

// ═══ Ansible ═════════════════════════════════════════════════════════════════
function ansibleTasks(flow) {
  if (flow._ans) return flow._ans;
  const tasks = [];
  const visit = (list) => asArray(list).forEach((t) => { if (!isMap(t)) return; tasks.push(t); for (const k of ['block', 'rescue', 'always']) if (t[k]) visit(t[k]); });
  for (const { doc } of parseYamlDocs(flow.ctx.literal)) {
    const plays = Array.isArray(doc) ? doc : [doc];
    plays.forEach((p) => { if (!isMap(p)) return; for (const k of ['tasks', 'pre_tasks', 'post_tasks', 'handlers']) visit(p[k]); if (isMap(p.vars)) tasks.push({ vars: p.vars, $line: p.vars.$line, $lines: { vars: p.vars.$line } }); });
  }
  return (flow._ans = tasks);
}
const ANSIBLE_RULES = [
  cfg({ id: 'ansible-secret', cls: 'hardcoded secret in IaC template or variable', langs: ['iac'], sev: 'high', conf: 'high', group: 'secret', title: 'Hardcoded secret in Ansible playbook',
    fix: 'Encrypt secrets with ansible-vault (inline !vault values or vault files) or fetch them from a lookup plugin at runtime; never commit literal passwords or tokens.',
    run(flow, emit) {
      if (kindOf(flow) !== 'ansible') return;
      const scan = (obj, depth = 0) => { if (!isMap(obj) || depth > 5) return; for (const [k, v] of Object.entries(obj)) { if (typeof v === 'string') { if (SECRETISH.test(k) && !/(?:_file|_path|_name|_id|_type|_enabled|_length|_policy|_user|_src|_dest|_mode)$/i.test(k) && !isPlaceholder(v) && !/\{\{/.test(v) && v.length >= 4 && !/^(?:true|false|yes|no|\d+)$/i.test(v) && !/^\$ANSIBLE_VAULT/.test(v)) emitAt(flow, emit, lineOfKey(obj, k), { redact: true, desc: `${k} is set to a literal value in the playbook.` }); } else if (isMap(v)) scan(v, depth + 1); else if (Array.isArray(v)) v.forEach(x => scan(x, depth + 1)); } };
      for (const t of ansibleTasks(flow)) scan(t);
    } }),
  cfg({ id: 'ansible-tls', cls: 'disabled encryption at rest or in transit (IaC)', langs: ['iac'], sev: 'medium', conf: 'high', group: 'iac', title: 'TLS certificate validation disabled in Ansible task',
    fix: 'Leave validate_certs enabled; supply a CA bundle (ca_path) for private CAs.',
    run(flow, emit) {
      if (kindOf(flow) !== 'ansible') return;
      const scan = (obj, depth = 0) => { if (!isMap(obj) || depth > 4) return; for (const [k, v] of Object.entries(obj)) { if (/^(?:validate_certs|verify_ssl|ssl_verify|insecure_skip_verify|verify_peer|tls_verify)$/i.test(k) && ((/validate|verify|tls/i.test(k) && falsy(v)) || (/insecure/i.test(k) && truthy(v)))) emitAt(flow, emit, lineOfKey(obj, k), { desc: `${k} is disabled, so the task will accept any TLS certificate.` }); else if (isMap(v)) scan(v, depth + 1); } };
      for (const t of ansibleTasks(flow)) scan(t);
    } }),
];

export const CONFIG_RULES = [...DOCKER_RULES, ...K8S_RULES, ...TF_RULES, ...CFN_RULES, ...ANSIBLE_RULES];
