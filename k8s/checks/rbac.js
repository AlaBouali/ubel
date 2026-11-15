'use strict';
import { rule, arr, obj, T, F } from './util.js';
import { na } from '../../vm/lib/engine.js';
import { nsOf } from '../lib/inventory.js';

const isDefault = (o) => {
  const md = obj(o.metadata);
  return obj(md.labels)['kubernetes.io/bootstrapping'] === 'rbac-defaults' || /^(system:|kubeadm:)/.test(md.name || '');
};
const SYSTEM_PUBLIC_ROLES = new Set(['system:basic-user', 'system:discovery', 'system:public-info-viewer', 'system:service-account-issuer-discovery']);
const subjName = (s) => `${s.kind}:${s.namespace ? s.namespace + '/' : ''}${s.name}`;
const subjList = (subs) => { const l = arr(subs).map(subjName); return l.slice(0, 6).join(', ') + (l.length > 6 ? `, … ${l.length - 6} more` : ''); };

function bindings(inv) {
  if (inv._bindings) return inv._bindings;
  const all = [
    ...inv.list('ClusterRoleBinding').map((b) => ({ ...b, __kind: 'ClusterRoleBinding' })),
    ...inv.list('RoleBinding').map((b) => ({ ...b, __kind: 'RoleBinding' })),
  ];
  inv._bindings = all;
  return all;
}

/** Subjects a role is granted to (for the finding text). */
function boundTo(inv, kind, role) {
  const name = role.metadata.name, ns = nsOf(role);
  const subs = [];
  for (const b of bindings(inv)) {
    const rr = obj(b.roleRef);
    if (rr.name !== name || rr.kind !== kind) continue;
    if (kind === 'Role' && nsOf(b) !== ns) continue;
    subs.push(...arr(b.subjects));
  }
  return subs;
}

const verbsOf = (r) => arr(r.verbs).map(String);
const resOf = (r) => arr(r.resources).map(String);
const has = (list, x) => list.includes('*') || list.includes(x);

/** Walks Roles + ClusterRoles (non-default) and collects violations from `test(rule, role, kind)`. */
function scanRoles(inv, test) {
  const out = [];
  for (const [kind, key] of [['ClusterRole', 'ClusterRole'], ['Role', 'Role']]) {
    for (const role of inv.list(key)) {
      if (isDefault(role)) continue;
      const hits = [];
      for (const r of arr(role.rules)) { const d = test(r, kind); if (d) hits.push(d); }
      if (!hits.length) continue;
      const subs = boundTo(inv, kind, role);
      if (inv.fullView && !subs.length) continue;           // a role nobody is bound to grants nothing
      out.push({ resource: `${kind}/${role.metadata.name}`, scope: nsOf(role), detail: `${[...new Set(hits)].join('; ')}.${subs.length ? ` Bound to: ${subjList(subs)}.` : ''}`, kind });
    }
  }
  return out;
}

export default [
  rule({
    id: 'k8s-rbac-cluster-admin-binding', area: 'rbac', severity: 'high', title: 'cluster-admin granted to a user, group or service account',
    description: 'cluster-admin gives unrestricted control of the whole cluster. It should be bound to as few identities as possible, never to workloads, and never permanently to individual users.',
    remediation: 'Replace the binding with a narrower ClusterRole/Role bound to the specific identity, and keep cluster-admin for break-glass use.',
    evaluate(inv) {
      const out = [];
      for (const b of bindings(inv)) {
        if (obj(b.roleRef).name !== 'cluster-admin' || isDefault(b)) continue;
        const subs = arr(b.subjects).filter((s) => !(s.kind === 'Group' && s.name === 'system:masters'));
        if (!subs.length) continue;
        const wl = subs.some((s) => s.kind === 'ServiceAccount');
        out.push({ resource: `${b.__kind}/${b.metadata.name}`, scope: nsOf(b), severity: 'high', detail: `Grants cluster-admin to ${subjList(subs)}${wl ? ' — a workload identity holds full cluster control' : ''}.` });
      }
      return out;
    },
  }),
  rule({
    id: 'k8s-rbac-anonymous-binding', area: 'rbac', severity: 'high', title: 'Role granted to anonymous or all authenticated users',
    description: 'Bindings to system:anonymous / system:unauthenticated give permissions to anyone who can reach the API server. system:authenticated is every authenticated identity, which on managed clusters can include accounts outside your organisation.',
    remediation: 'Delete the binding or bind the role to specific users, groups or service accounts.',
    evaluate(inv) {
      const out = [];
      for (const b of bindings(inv)) {
        if (isDefault(b) || SYSTEM_PUBLIC_ROLES.has(obj(b.roleRef).name)) continue;
        const subs = arr(b.subjects).filter((s) => ['system:anonymous', 'system:unauthenticated', 'system:authenticated'].includes(s.name));
        if (!subs.length) continue;
        const anon = subs.some((s) => s.name !== 'system:authenticated');
        out.push({ resource: `${b.__kind}/${b.metadata.name}`, scope: nsOf(b), severity: anon ? 'critical' : 'high', detail: `Role ${obj(b.roleRef).name} is granted to ${subs.map((s) => s.name).join(', ')}.` });
      }
      return out;
    },
  }),
  rule({
    id: 'k8s-rbac-system-masters', area: 'rbac', severity: 'critical', title: 'Binding references the system:masters group',
    description: 'Members of system:masters bypass RBAC entirely and cannot be restricted or revoked by deleting a binding. Nothing should be added to this group.',
    remediation: 'Remove the subject and use a normal cluster-admin (or narrower) binding for the identity.',
    evaluate(inv) {
      const out = [];
      for (const b of bindings(inv)) {
        if (isDefault(b) || obj(b.roleRef).name === 'cluster-admin' && b.metadata.name === 'cluster-admin') continue;
        if (arr(b.subjects).some((s) => s.kind === 'Group' && s.name === 'system:masters')) out.push({ resource: `${b.__kind}/${b.metadata.name}`, scope: nsOf(b), detail: 'A subject is the system:masters group.' });
      }
      return out;
    },
  }),
  rule({
    id: 'k8s-rbac-wildcard-role', area: 'rbac', severity: 'medium', title: 'Role uses wildcards for verbs or resources',
    description: 'Wildcards grant every present and future verb or resource, including ones added by CRDs and new Kubernetes versions. Combined, they are equivalent to cluster-admin.',
    remediation: 'List the exact verbs and resources the subject needs.',
    evaluate(inv) {
      return scanRoles(inv, (r) => {
        const v = verbsOf(r), res = resOf(r);
        if (v.includes('*') && res.includes('*')) return 'verbs: ["*"] on resources: ["*"] (full control)';
        if (v.includes('*')) return `verbs: ["*"] on ${res.join(', ') || 'unspecified resources'}`;
        if (res.includes('*')) return `${v.join('/')} on resources: ["*"]`;
        return null;
      }).map((x) => ({ ...x, severity: /full control/.test(x.detail) ? 'high' : 'medium' }));
    },
  }),
  rule({
    id: 'k8s-rbac-secrets-access', area: 'rbac', severity: 'medium', title: 'Role can read Secrets',
    description: 'Access to get/list/watch on Secrets exposes every credential in scope (list returns all values). It should be limited to named secrets and the identities that truly need them.',
    remediation: 'Remove get/list/watch on secrets, or restrict with resourceNames and a namespaced Role.',
    evaluate(inv) {
      return scanRoles(inv, (r) => {
        if (!has(resOf(r), 'secrets') || arr(r.resourceNames).length) return null;
        const v = verbsOf(r).filter((x) => ['get', 'list', 'watch', '*'].includes(x));
        return v.length ? `${v.join('/')} on secrets` : null;
      }).map((x) => ({ ...x, severity: x.kind === 'ClusterRole' ? 'medium' : 'low' }));
    },
  }),
  rule({
    id: 'k8s-rbac-escalation-verbs', area: 'rbac', severity: 'high', title: 'Role can escalate, bind or impersonate',
    description: 'The escalate, bind and impersonate verbs let a subject grant itself more permissions or act as another identity, defeating the rest of the RBAC model.',
    remediation: 'Remove the verb; only cluster administrators and controllers that manage RBAC should hold it.',
    evaluate(inv) {
      return scanRoles(inv, (r) => {
        const v = verbsOf(r).filter((x) => ['escalate', 'bind', 'impersonate'].includes(x));
        return v.length ? `${v.join('/')} on ${resOf(r).join(', ') || 'unspecified resources'}` : null;
      });
    },
  }),
  rule({
    id: 'k8s-rbac-pod-access', area: 'rbac', severity: 'medium', title: 'Role can create pods or run commands in pods',
    description: 'Anyone who can create pods can mount any Secret or host path in the namespace and run as any ServiceAccount there; pods/exec and pods/attach give a shell inside running workloads.',
    remediation: 'Remove create on pods and pods/exec|attach from roles that do not need them; use admission policies to constrain what pods may do.',
    evaluate(inv) {
      return scanRoles(inv, (r) => {
        const v = verbsOf(r), res = resOf(r);
        if (!(v.includes('create') || v.includes('*'))) return null;
        const hit = res.filter((x) => ['pods', 'pods/exec', 'pods/attach', '*'].includes(x) && x !== '*');
        return hit.length ? `create on ${hit.join(', ')}` : null;
      }).map((x) => ({ ...x, severity: x.kind === 'ClusterRole' ? 'medium' : 'low' }));
    },
  }),
  rule({
    id: 'k8s-rbac-dangerous-permissions', area: 'rbac', severity: 'high', title: 'Role grants a permission that leads to privilege escalation',
    description: 'Some permissions are escalation paths on their own: nodes/proxy (reach every kubelet), minting service-account tokens, approving certificate requests, editing admission webhooks, or creating PersistentVolumes (hostPath).',
    remediation: 'Remove the permission or restrict it to the controller that needs it.',
    evaluate(inv) {
      return scanRoles(inv, (r) => {
        const v = verbsOf(r), res = resOf(r);
        const w = (verb) => v.includes(verb) || v.includes('*');
        const d = [];
        if (has(res, 'nodes/proxy') && (w('get') || w('create'))) d.push('nodes/proxy (access to every kubelet API)');
        if (has(res, 'serviceaccounts/token') && w('create')) d.push('create serviceaccounts/token (mint tokens for any service account)');
        if (has(res, 'certificatesigningrequests/approval') && (w('update') || w('patch'))) d.push('approve certificatesigningrequests');
        if (has(res, 'signers') && v.includes('approve')) d.push('approve certificate signers');
        if ((has(res, 'validatingwebhookconfigurations') || has(res, 'mutatingwebhookconfigurations')) && (w('create') || w('update') || w('patch'))) d.push('edit admission webhook configurations');
        if (has(res, 'persistentvolumes') && w('create')) d.push('create persistentvolumes (hostPath volumes)');
        return d.length ? d.join(', ') : null;
      }).map((x) => ({ ...x, severity: /^create persistentvolumes/.test(x.detail) ? 'medium' : 'high' }));
    },
  }),
  rule({
    id: 'k8s-sa-default-bound', area: 'rbac', severity: 'medium', title: 'A role is bound to a namespace\'s default service account',
    description: 'Every pod that does not name a ServiceAccount runs as "default", so any role bound to it is silently granted to all of those pods.',
    remediation: 'Bind roles to dedicated ServiceAccounts and remove the binding from "default".',
    evaluate(inv) {
      const out = [];
      for (const b of bindings(inv)) {
        if (isDefault(b)) continue;
        const subs = arr(b.subjects).filter((s) => s.kind === 'ServiceAccount' && s.name === 'default');
        if (subs.length) out.push({ resource: `${b.__kind}/${b.metadata.name}`, scope: nsOf(b), detail: `Role ${obj(b.roleRef).name} is bound to ServiceAccount default (${subs.map((s) => s.namespace || nsOf(b)).join(', ')}).` });
      }
      return out;
    },
  }),
  rule({
    id: 'k8s-sa-default-automount', area: 'rbac', severity: 'low', title: 'Default service account token is auto-mounted',
    description: 'The default ServiceAccount does not disable automountServiceAccountToken, so every pod using it receives an API token whether or not it needs one.',
    remediation: 'Set automountServiceAccountToken: false on the default ServiceAccount of each namespace and opt in per pod where needed.',
    evaluate(inv) {
      return inv.list('ServiceAccount').filter((s) => obj(s.metadata).name === 'default' && !F(s.automountServiceAccountToken))
        .map((s) => ({ resource: 'ServiceAccount/default', scope: nsOf(s), detail: 'automountServiceAccountToken is not false.' }));
    },
  }),
  rule({
    id: 'k8s-sa-legacy-token-secret', area: 'rbac', severity: 'medium', title: 'Long-lived service-account token Secret exists',
    description: 'Secrets of type kubernetes.io/service-account-token are non-expiring credentials. Modern clusters issue short-lived bound tokens instead; legacy ones remain valid until deleted.',
    remediation: 'Delete the Secret and use projected (bound) service-account tokens or the TokenRequest API.',
    evaluate(inv) {
      return inv.list('Secret').filter((s) => s.type === 'kubernetes.io/service-account-token' || obj(obj(s.metadata).annotations)['kubernetes.io/service-account.name'])
        .map((s) => ({ resource: `Secret/${s.metadata.name}`, scope: nsOf(s), detail: `Token for ServiceAccount ${obj(s.metadata.annotations)['kubernetes.io/service-account.name'] || '(unknown)'}.` }));
    },
  }),
];
