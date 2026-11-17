'use strict';
import { rule, arr, obj, T, F, num } from './util.js';
import { na, unassessed } from '../../vm/lib/engine.js';

const minorOf = (v) => { const m = String(v || '').match(/v?(\d+)\.(\d+)/); return m ? { major: Number(m[1]), minor: Number(m[2]), key: `${m[1]}.${m[2]}` } : null; };
const NOTCP = 'control-plane static pods are not visible (a managed service such as EKS/GKE/AKS — see the k8s-eks-*, k8s-gke-* and k8s-aks-* checks — or a cluster not built with kubeadm)';

export default [
  rule({
    id: 'k8s-api-anonymous-access', area: 'cluster', severity: 'critical', title: 'The API server answers unauthenticated requests',
    description: 'An unauthenticated request was allowed to list namespaces, so anyone who can reach the API endpoint can read cluster data.',
    remediation: 'Set --anonymous-auth=false on the API server and remove RBAC bindings to system:anonymous / system:unauthenticated.',
    evaluate(inv) {
      if (!inv.anonymousProbe) return na('only applicable to a live cluster');
      const { status, error } = inv.anonymousProbe;
      if (!status) return unassessed(`the unauthenticated probe could not complete (${error || 'no response'})`);
      return status >= 200 && status < 300 ? [{ resource: 'api-server', detail: `GET /api/v1/namespaces without credentials returned HTTP ${status}.` }] : [];
    },
  }),
  rule({
    id: 'k8s-apiserver-flags', area: 'cluster', severity: 'high', title: 'API server is started with an insecure option',
    description: 'The kube-apiserver command line weakens authentication, authorization, admission or auditing.',
    remediation: 'Edit /etc/kubernetes/manifests/kube-apiserver.yaml to correct the flag listed in the finding.',
    evaluate(inv) {
      const cp = inv.controlPlane().apiserver;
      if (!cp) return na(NOTCP);
      const a = cp.args, d = [];
      const add = (resource, detail, severity) => d.push({ resource: `kube-apiserver:${resource}`, detail, ...(severity ? { severity } : {}) });
      if (T(a.get('anonymous-auth'))) add('anonymous-auth', '--anonymous-auth=true lets unauthenticated requests reach authorization.', 'high');
      const authz = String(a.get('authorization-mode') || '');
      if (/AlwaysAllow/.test(authz)) add('authorization-mode', '--authorization-mode includes AlwaysAllow: every request is authorized.', 'critical');
      else if (authz && !/RBAC/.test(authz)) add('authorization-mode', `--authorization-mode is "${authz}" and does not include RBAC.`, 'high');
      if (a.has('token-auth-file')) add('token-auth-file', '--token-auth-file uses static bearer tokens that never expire.', 'medium');
      if (a.has('insecure-port') && num(a.get('insecure-port')) > 0) add('insecure-port', `--insecure-port=${a.get('insecure-port')} serves the API without TLS or authentication.`, 'critical');
      if (T(a.get('profiling'))) add('profiling', '--profiling=true exposes profiling endpoints.', 'low');
      if (!a.has('audit-log-path') && !a.has('audit-webhook-config-file')) add('audit-log-path', 'No audit log (--audit-log-path / --audit-webhook-config-file) is configured.', 'medium');
      const plugins = String(a.get('enable-admission-plugins') || '');
      if (/AlwaysAdmit/.test(plugins)) add('enable-admission-plugins', 'AlwaysAdmit is enabled, which disables admission control.', 'high');
      if (!/NodeRestriction/.test(plugins)) add('enable-admission-plugins', 'NodeRestriction is not enabled, so a compromised kubelet can modify other nodes\' objects.', 'medium');
      if (F(a.get('service-account-lookup'))) add('service-account-lookup', '--service-account-lookup=false accepts tokens of deleted service accounts.', 'medium');
      if (!a.has('encryption-provider-config')) add('encryption-provider-config', 'No --encryption-provider-config: Secrets are stored unencrypted in etcd.', 'medium');
      return d;
    },
  }),
  rule({
    id: 'k8s-etcd-flags', area: 'cluster', severity: 'high', title: 'etcd is started with an insecure option',
    description: 'etcd holds all cluster state including Secrets. Client and peer connections must be authenticated with certificates.',
    remediation: 'Edit /etc/kubernetes/manifests/etcd.yaml: --client-cert-auth=true, --peer-client-cert-auth=true and remove --auto-tls / --peer-auto-tls.',
    evaluate(inv) {
      const cp = inv.controlPlane().etcd;
      if (!cp) return na(NOTCP);
      const a = cp.args, d = [];
      if (!T(a.get('client-cert-auth'))) d.push({ resource: 'etcd:client-cert-auth', severity: 'high', detail: '--client-cert-auth is not true: clients are not authenticated.' });
      if (T(a.get('auto-tls'))) d.push({ resource: 'etcd:auto-tls', severity: 'medium', detail: '--auto-tls=true uses self-signed certificates for client connections.' });
      if (!T(a.get('peer-client-cert-auth'))) d.push({ resource: 'etcd:peer-client-cert-auth', severity: 'medium', detail: '--peer-client-cert-auth is not true: peers are not authenticated.' });
      if (T(a.get('peer-auto-tls'))) d.push({ resource: 'etcd:peer-auto-tls', severity: 'medium', detail: '--peer-auto-tls=true uses self-signed certificates between peers.' });
      return d;
    },
  }),
  rule({
    id: 'k8s-controlplane-flags', area: 'cluster', severity: 'low', title: 'Controller manager or scheduler is started with a weak option',
    description: 'Profiling endpoints enlarge the attack surface, and without --use-service-account-credentials the controller manager runs every controller with one shared identity.',
    remediation: 'Set --profiling=false on both components and --use-service-account-credentials=true on kube-controller-manager.',
    evaluate(inv) {
      const cp = inv.controlPlane();
      if (!cp['controller-manager'] && !cp.scheduler) return na(NOTCP);
      const d = [];
      if (cp['controller-manager']) {
        const a = cp['controller-manager'].args;
        if (T(a.get('profiling'))) d.push({ resource: 'kube-controller-manager:profiling', detail: '--profiling=true.' });
        if (!T(a.get('use-service-account-credentials'))) d.push({ resource: 'kube-controller-manager:use-service-account-credentials', detail: '--use-service-account-credentials is not true.' });
      }
      if (cp.scheduler && T(cp.scheduler.args.get('profiling'))) d.push({ resource: 'kube-scheduler:profiling', detail: '--profiling=true.' });
      return d;
    },
  }),
  rule({
    id: 'k8s-kubelet-config', area: 'node', severity: 'high', title: 'Kubelet is configured insecurely',
    description: 'The kubelet API controls the pods on a node. Anonymous access, AlwaysAllow authorization or the unauthenticated read-only port let anyone on the network read or run workloads.',
    remediation: 'In the kubelet configuration: authentication.anonymous.enabled=false, authorization.mode=Webhook, readOnlyPort=0.',
    evaluate(inv) {
      if (!inv.kubeletConfigs.size) return na('--kubelet-configz was not requested (it needs the nodes/proxy permission)');
      const d = [];
      let ok = 0;
      for (const [node, c] of inv.kubeletConfigs) {
        if (c.__error) continue;
        ok++;
        const auth = obj(c.authentication), authz = obj(c.authorization);
        if (T(obj(auth.anonymous).enabled)) d.push({ resource: `Node/${node}:authentication.anonymous`, severity: 'high', detail: 'authentication.anonymous.enabled is true.' });
        if (authz.mode === 'AlwaysAllow') d.push({ resource: `Node/${node}:authorization.mode`, severity: 'critical', detail: 'authorization.mode is AlwaysAllow.' });
        if (num(c.readOnlyPort) > 0) d.push({ resource: `Node/${node}:readOnlyPort`, severity: 'medium', detail: `readOnlyPort is ${c.readOnlyPort} (unauthenticated).` });
        if (F(obj(auth.webhook).enabled)) d.push({ resource: `Node/${node}:authentication.webhook`, severity: 'medium', detail: 'authentication.webhook.enabled is false.' });
      }
      if (!ok) return unassessed(`kubelet configuration could not be read from any node (${[...inv.kubeletConfigs.values()][0].__error})`);
      return d;
    },
  }),

  rule({
    id: 'k8s-node-version-skew', area: 'node', severity: 'medium', title: 'Kubelet version is outside the supported skew',
    description: 'A kubelet must not be newer than the API server and may be at most three minor versions older. Outside that range behaviour is untested and security fixes may be missing.',
    remediation: 'Upgrade (or downgrade) the node so its kubelet is within three minor versions of, and not newer than, the control plane.',
    evaluate(inv) {
      const api = minorOf(inv.version && inv.version.gitVersion);
      if (!api) return inv.fullView ? unassessed('the API server version could not be read') : na('only applicable to a live cluster');
      const d = [];
      for (const n of inv.list('Node')) {
        const k = minorOf(obj(obj(n.status).nodeInfo).kubeletVersion);
        if (!k) continue;
        if (k.minor > api.minor) d.push({ resource: `Node/${n.metadata.name}`, detail: `kubelet ${k.key} is newer than the API server ${api.key}.` });
        else if (api.minor - k.minor > 3) d.push({ resource: `Node/${n.metadata.name}`, detail: `kubelet ${k.key} is ${api.minor - k.minor} minor versions behind the API server ${api.key}.` });
      }
      return d;
    },
  }),
  rule({
    id: 'k8s-node-external-ip', area: 'node', severity: 'low', title: 'Node has a public IP address',
    description: 'Nodes with external IPs expose the kubelet and any host-port or NodePort service directly to the internet unless firewalled.',
    remediation: 'Place nodes in private subnets and expose workloads through load balancers.',
    evaluate(inv) {
      if (!inv.fullView) return na('only applicable to a live cluster');
      return inv.list('Node').filter((n) => arr(obj(n.status).addresses).some((a) => a.type === 'ExternalIP')).map((n) => ({ resource: `Node/${n.metadata.name}`, detail: `ExternalIP ${n.status.addresses.filter((a) => a.type === 'ExternalIP').map((a) => a.address).join(', ')}.` }));
    },
  }),
];
