'use strict';
import { rule, arr, obj, num } from './util.js';
import { na } from '../../vm/lib/engine.js';
import { nsOf } from '../lib/inventory.js';

const SYSTEM_NS = new Set(['kube-system', 'kube-public', 'kube-node-lease']);
const SENSITIVE_PORTS = new Set([22, 23, 3389, 3306, 5432, 6379, 27017, 9200, 9300, 11211, 2379, 2380, 10250, 5984, 1433, 9042, 8001, 2375]);
const INTERNAL_LB = ['service.beta.kubernetes.io/aws-load-balancer-internal', 'service.beta.kubernetes.io/azure-load-balancer-internal', 'networking.gke.io/load-balancer-type', 'cloud.google.com/load-balancer-type', 'service.beta.kubernetes.io/openstack-internal-load-balancer', 'service.beta.kubernetes.io/oci-load-balancer-internal', 'service.beta.kubernetes.io/alibaba-cloud-loadbalancer-address-type'];

const emptySelector = (s) => !s || (!Object.keys(obj(s.matchLabels)).length && !arr(s.matchExpressions).length);
const wlNamespaces = (inv) => { const m = new Map(); for (const w of inv.workloads()) if (w.namespace) m.set(w.namespace, (m.get(w.namespace) || 0) + 1); return m; };
const isInternalLb = (svc) => {
  const a = obj(obj(svc.metadata).annotations);
  return INTERNAL_LB.some((k) => a[k] !== undefined && !/^(false|external|public)$/i.test(String(a[k]))) && !/(internet-facing|external)/i.test(String(a['service.beta.kubernetes.io/aws-load-balancer-scheme'] || ''));
};
const sensitiveOf = (svc) => arr(obj(svc.spec).ports).map((p) => num(p.port)).filter((p) => SENSITIVE_PORTS.has(p));

export default [
  rule({
    id: 'k8s-net-no-networkpolicy', area: 'network', severity: 'medium', title: 'Namespace with workloads has no NetworkPolicy',
    description: 'Without any NetworkPolicy every pod in the namespace can talk to every other pod in the cluster, so one compromised workload can reach all the others (when the CNI plugin enforces policies).',
    remediation: 'Add a default-deny NetworkPolicy to the namespace and then allow only the required flows.',
    evaluate(inv) {
      const why = inv.requireFullView('Detecting a missing NetworkPolicy'); if (why) return na(why);
      const withPolicy = new Set(inv.list('NetworkPolicy').map(nsOf));
      return [...wlNamespaces(inv)].filter(([ns]) => !withPolicy.has(ns) && !SYSTEM_NS.has(ns)).map(([ns, n]) => ({ resource: `Namespace/${ns}`, scope: ns, detail: `${n} workload(s) and no NetworkPolicy.` }));
    },
  }),
  rule({
    id: 'k8s-net-no-default-deny', area: 'network', severity: 'low', title: 'Namespace has NetworkPolicies but no default-deny ingress policy',
    description: 'Pods that no policy selects stay open to all traffic. A default-deny ingress policy (empty podSelector, no ingress rules) makes isolation the default.',
    remediation: 'Add a NetworkPolicy with podSelector: {} and policyTypes: [Ingress] with no ingress rules, then allow flows explicitly.',
    evaluate(inv) {
      const why = inv.requireFullView('Detecting a missing default-deny policy'); if (why) return na(why);
      const by = new Map();
      for (const p of inv.list('NetworkPolicy')) { const ns = nsOf(p); by.set(ns, [...(by.get(ns) || []), p]); }
      const out = [];
      for (const [ns, list] of by) {
        if (SYSTEM_NS.has(ns) || !wlNamespaces(inv).has(ns)) continue;
        const deny = list.some((p) => { const s = obj(p.spec); const types = arr(s.policyTypes); return emptySelector(s.podSelector) && (types.includes('Ingress') || !types.length) && !arr(s.ingress).length; });
        if (!deny) out.push({ resource: `Namespace/${ns}`, scope: ns, detail: `${list.length} NetworkPolicy object(s), none of them a default-deny ingress policy.` });
      }
      return out;
    },
  }),
  rule({
    id: 'k8s-net-allow-all-policy', area: 'network', severity: 'medium', title: 'NetworkPolicy allows all ingress to every pod in the namespace',
    description: 'A policy that selects all pods and allows traffic from anywhere (an empty rule or 0.0.0.0/0) nullifies network isolation while looking like a control.',
    remediation: 'Restrict the ingress rule to specific peers (namespaceSelector / podSelector / ipBlock) and ports.',
    evaluate(inv) {
      const out = [];
      for (const p of inv.list('NetworkPolicy')) {
        const s = obj(p.spec);
        if (!emptySelector(s.podSelector)) continue;
        const open = arr(s.ingress).some((r) => !r || (!arr(r.from).length && !Object.keys(obj(r)).filter((k) => k !== 'from').length) || (r && !('from' in r)) || arr(r.from).some((f) => f && f.ipBlock && /^(0\.0\.0\.0\/0|::\/0)$/.test(f.ipBlock.cidr || '')));
        if (open) out.push({ resource: `NetworkPolicy/${p.metadata.name}`, scope: nsOf(p), detail: 'An ingress rule matches all sources for all pods in the namespace.' });
      }
      return out;
    },
  }),
  rule({
    id: 'k8s-svc-loadbalancer-exposed', area: 'network', severity: 'medium', title: 'LoadBalancer service is open to the internet',
    description: 'A LoadBalancer Service without loadBalancerSourceRanges and without an "internal" annotation is typically reachable from any address on the internet.',
    remediation: 'Restrict spec.loadBalancerSourceRanges, mark the load balancer internal with your cloud\'s annotation, or front it with an authenticated Ingress / WAF.',
    evaluate: (inv) => inv.list('Service').filter((s) => obj(s.spec).type === 'LoadBalancer' && !arr(obj(s.spec).loadBalancerSourceRanges).length && !isInternalLb(s)).map((s) => {
      const sens = sensitiveOf(s);
      return { resource: `Service/${s.metadata.name}`, scope: nsOf(s), severity: sens.length ? 'high' : 'medium', detail: `Exposes port(s) ${arr(s.spec.ports).map((p) => p.port).join(', ')}${sens.length ? ` — including sensitive port(s) ${sens.join(', ')}` : ''} with no source restriction.` };
    }),
  }),
  rule({
    id: 'k8s-svc-nodeport', area: 'network', severity: 'low', title: 'NodePort service exposes a port on every node',
    description: 'NodePort opens the same high port on every node, bypassing ingress controllers and any load-balancer level controls.',
    remediation: 'Use ClusterIP with an Ingress / Gateway or a LoadBalancer with source restrictions.',
    evaluate: (inv) => inv.list('Service').filter((s) => obj(s.spec).type === 'NodePort').map((s) => {
      const sens = sensitiveOf(s);
      return { resource: `Service/${s.metadata.name}`, scope: nsOf(s), severity: sens.length ? 'medium' : 'low', detail: `NodePort(s) ${arr(s.spec.ports).map((p) => p.nodePort || p.port).join(', ')}${sens.length ? `; sensitive port(s) ${sens.join(', ')}` : ''}.` };
    }),
  }),
  rule({
    id: 'k8s-svc-external-ips', area: 'network', severity: 'medium', title: 'Service sets externalIPs',
    description: 'spec.externalIPs lets whoever can create the Service claim traffic to arbitrary IP addresses inside the cluster (CVE-2020-8554 man-in-the-middle).',
    remediation: 'Remove externalIPs and block them with the DenyServiceExternalIPs admission plugin or a policy engine.',
    evaluate: (inv) => inv.list('Service').filter((s) => arr(obj(s.spec).externalIPs).length).map((s) => ({ resource: `Service/${s.metadata.name}`, scope: nsOf(s), detail: `externalIPs: ${s.spec.externalIPs.join(', ')}.` })),
  }),
  rule({
    id: 'k8s-ingress-no-tls', area: 'network', severity: 'medium', title: 'Ingress does not terminate TLS',
    description: 'An Ingress with no tls section serves traffic over plain HTTP, exposing credentials and data in transit.',
    remediation: 'Add spec.tls with a certificate secret (for example from cert-manager) and redirect HTTP to HTTPS.',
    evaluate: (inv) => inv.list('Ingress').filter((i) => arr(obj(i.spec).rules).length && !arr(obj(i.spec).tls).length).map((i) => ({ resource: `Ingress/${i.metadata.name}`, scope: nsOf(i), detail: `Hosts: ${arr(i.spec.rules).map((r) => r.host || '*').join(', ')}.` })),
  }),
  rule({
    id: 'k8s-ingress-snippet-annotations', area: 'network', severity: 'medium', title: 'Ingress injects raw configuration snippets',
    description: 'NGINX snippet annotations paste user-supplied configuration into the proxy; they have been used to read the controller\'s service-account token and escalate (CVE-2021-25742).',
    remediation: 'Remove the snippet annotation, use supported annotations, and disable snippets in the controller (allow-snippet-annotations: false).',
    evaluate: (inv) => inv.list('Ingress').filter((i) => Object.keys(obj(obj(i.metadata).annotations)).some((k) => /(configuration|server|stream|auth|modsecurity)-snippet$/.test(k))).map((i) => ({ resource: `Ingress/${i.metadata.name}`, scope: nsOf(i), detail: `Annotation(s): ${Object.keys(i.metadata.annotations).filter((k) => /snippet$/.test(k)).join(', ')}.` })),
  }),

  rule({
    id: 'k8s-ns-no-pod-security', area: 'namespace', severity: 'medium', title: 'Namespace has no Pod Security Admission enforcement',
    description: 'Without the pod-security.kubernetes.io/enforce label nothing stops a pod in the namespace from using privileged settings (unless another admission policy engine does). Check Kyverno / Gatekeeper / ValidatingAdmissionPolicy if you use one.',
    remediation: 'Label the namespace: kubectl label ns <ns> pod-security.kubernetes.io/enforce=baseline (or restricted).',
    evaluate(inv) {
      const wl = wlNamespaces(inv);
      return inv.list('Namespace').filter((n) => {
        const name = n.metadata.name, l = obj(n.metadata.labels);
        if (SYSTEM_NS.has(name) || l['pod-security.kubernetes.io/enforce']) return false;
        return inv.fullView ? wl.has(name) : true;
      }).map((n) => ({ resource: `Namespace/${n.metadata.name}`, scope: n.metadata.name, detail: 'No pod-security.kubernetes.io/enforce label.' }));
    },
  }),
  rule({
    id: 'k8s-ns-psa-privileged', area: 'namespace', severity: 'low', title: 'Namespace enforces the privileged Pod Security level',
    description: 'The privileged level places no restriction on pods in the namespace. It is appropriate only for trusted system components.',
    remediation: 'Use baseline or restricted for application namespaces.',
    evaluate: (inv) => inv.list('Namespace').filter((n) => !SYSTEM_NS.has(n.metadata.name) && obj(n.metadata.labels)['pod-security.kubernetes.io/enforce'] === 'privileged').map((n) => ({ resource: `Namespace/${n.metadata.name}`, scope: n.metadata.name, detail: 'pod-security.kubernetes.io/enforce=privileged.' })),
  }),
  rule({
    id: 'k8s-ns-no-quota', area: 'namespace', severity: 'low', title: 'Namespace has no ResourceQuota or LimitRange',
    description: 'Without quotas one namespace can consume all cluster capacity, and without a LimitRange pods can be created with no resource limits.',
    remediation: 'Add a ResourceQuota (and a LimitRange with default limits) to each application namespace.',
    evaluate(inv) {
      const why = inv.requireFullView('Detecting a missing quota'); if (why) return na(why);
      const q = new Set([...inv.list('ResourceQuota'), ...inv.list('LimitRange')].map(nsOf));
      return [...wlNamespaces(inv)].filter(([ns]) => !q.has(ns) && !SYSTEM_NS.has(ns)).map(([ns]) => ({ resource: `Namespace/${ns}`, scope: ns, detail: 'No ResourceQuota and no LimitRange.' }));
    },
  }),
];
