'use strict';
// inventory.js — the data every ubel-k8s rule reads, from either a live cluster (read-only GETs) or manifest files.
//
// list(kind) returns the objects of a kind, or throws Unavailable when the cluster refused / failed that list, so the
// rule that needed it is reported as "not assessed" rather than passing on missing data. In manifest mode a kind that
// simply has no document yields an empty list (a manifest set is not a cluster); rules that conclude something from
// the ABSENCE of objects (no NetworkPolicy, no quota …) first ask requireFullView() and are not applicable to manifests.

import { ApiError } from './client.js';

class Unavailable extends Error {}

// kind, API path, namespaced, metadata only
const RESOURCES = [
  ['Namespace', '/api/v1/namespaces', false, false],
  ['Node', '/api/v1/nodes', false, false],
  ['Pod', '/api/v1/pods', true, false],
  ['Service', '/api/v1/services', true, false],
  ['ServiceAccount', '/api/v1/serviceaccounts', true, false],
  ['Secret', '/api/v1/secrets', true, true],
  ['ResourceQuota', '/api/v1/resourcequotas', true, false],
  ['LimitRange', '/api/v1/limitranges', true, false],
  ['ReplicationController', '/api/v1/replicationcontrollers', true, false],
  ['Deployment', '/apis/apps/v1/deployments', true, false],
  ['DaemonSet', '/apis/apps/v1/daemonsets', true, false],
  ['StatefulSet', '/apis/apps/v1/statefulsets', true, false],
  ['ReplicaSet', '/apis/apps/v1/replicasets', true, false],
  ['Job', '/apis/batch/v1/jobs', true, false],
  ['CronJob', '/apis/batch/v1/cronjobs', true, false],
  ['Ingress', '/apis/networking.k8s.io/v1/ingresses', true, false],
  ['NetworkPolicy', '/apis/networking.k8s.io/v1/networkpolicies', true, false],
  ['Role', '/apis/rbac.authorization.k8s.io/v1/roles', true, false],
  ['RoleBinding', '/apis/rbac.authorization.k8s.io/v1/rolebindings', true, false],
  ['ClusterRole', '/apis/rbac.authorization.k8s.io/v1/clusterroles', false, false],
  ['ClusterRoleBinding', '/apis/rbac.authorization.k8s.io/v1/clusterrolebindings', false, false],
];
const KINDS = RESOURCES.map((r) => r[0]);
const nsOf = (o) => (o && o.metadata && o.metadata.namespace) || '';

class Inventory {
  constructor(mode) {
    this.mode = mode;                        // 'cluster' | 'manifests'
    this.data = new Map(KINDS.map((k) => [k, []]));
    this.status = new Map();                 // kind → { ok, reason }
    this.version = null;                     // { gitVersion, major, minor }
    this.notes = [];
    this.kubeletConfigs = new Map();         // node name → kubelet configuration (opt-in)
    this.anonymousProbe = null;              // { status } of the unauthenticated list probe
    this.options = {};
    this.now = new Date();
    this._wl = null;
  }

  get fullView() { return this.mode === 'cluster'; }

  list(kind) {
    const st = this.status.get(kind);
    if (st && !st.ok) throw new Unavailable(`${kind} list unavailable: ${st.reason}`);
    return this.data.get(kind) || [];
  }

  /** Rules that conclude from missing objects call this first. */
  requireFullView(what) {
    return this.fullView ? null : `${what} needs a view of the whole cluster, which a set of manifest files is not`;
  }

  get namespaces() { return this.list('Namespace'); }

  /** Pod-spec carrying objects, de-duplicated so one workload is audited once. */
  workloads() {
    if (this._wl) return this._wl;
    const out = [];
    const ok = (k) => { const s = this.status.get(k); return !s || s.ok; };
    const ctrlOwner = (o) => ((o.metadata && o.metadata.ownerReferences) || []).find((r) => r.controller !== false && r.kind !== 'Node');
    const add = (kind, o, spec, tmplMeta) => {
      if (!spec) return;
      const md = o.metadata || {};
      out.push({
        kind, name: md.name || '(unnamed)', namespace: md.namespace || '', spec,
        labels: (tmplMeta && tmplMeta.labels) || md.labels || {}, annotations: { ...(md.annotations || {}), ...((tmplMeta && tmplMeta.annotations) || {}) },
        ref: `${kind}/${md.name || '(unnamed)'}`, file: o.__file || null,
      });
    };
    const manifests = this.mode === 'manifests';
    for (const o of this.list('Pod')) {
      const own = ctrlOwner(o);
      if (!manifests && own) {
        const covered = (own.kind === 'ReplicaSet' && ok('ReplicaSet')) || (own.kind === 'StatefulSet' && ok('StatefulSet')) || (own.kind === 'DaemonSet' && ok('DaemonSet'))
          || (own.kind === 'Job' && ok('Job')) || (own.kind === 'ReplicationController' && ok('ReplicationController'));
        if (covered) continue;
      }
      add('Pod', o, o.spec);
    }
    for (const k of ['Deployment', 'DaemonSet', 'StatefulSet']) for (const o of this.list(k)) add(k, o, o.spec && o.spec.template && o.spec.template.spec, o.spec && o.spec.template && o.spec.template.metadata);
    for (const o of this.list('ReplicaSet')) {
      const own = ctrlOwner(o);
      if (!manifests && own && own.kind === 'Deployment' && ok('Deployment')) continue;
      add('ReplicaSet', o, o.spec && o.spec.template && o.spec.template.spec, o.spec && o.spec.template && o.spec.template.metadata);
    }
    for (const o of this.list('ReplicationController')) {
      const own = ctrlOwner(o);
      if (!manifests && own) continue;
      add('ReplicationController', o, o.spec && o.spec.template && o.spec.template.spec, o.spec && o.spec.template && o.spec.template.metadata);
    }
    for (const o of this.list('Job')) {
      const own = ctrlOwner(o);
      if (!manifests && own && own.kind === 'CronJob' && ok('CronJob')) continue;
      add('Job', o, o.spec && o.spec.template && o.spec.template.spec, o.spec && o.spec.template && o.spec.template.metadata);
    }
    for (const o of this.list('CronJob')) {
      const t = o.spec && o.spec.jobTemplate && o.spec.jobTemplate.spec && o.spec.jobTemplate.spec.template;
      add('CronJob', o, t && t.spec, t && t.metadata);
    }
    this._wl = out;
    return out;
  }

  /** Static control-plane pods (kubeadm-style clusters) by component: apiserver | controller-manager | scheduler | etcd. */
  controlPlane() {
    const found = {};
    let pods;
    try { pods = this.list('Pod'); } catch { return found; }
    for (const p of pods) {
      const l = (p.metadata && p.metadata.labels) || {};
      const comp = l.component;
      if (nsOf(p) !== 'kube-system' || !['kube-apiserver', 'kube-controller-manager', 'kube-scheduler', 'etcd'].includes(comp)) continue;
      const c = ((p.spec && p.spec.containers) || [])[0];
      if (!c) continue;
      found[comp.replace(/^kube-/, '')] = { name: p.metadata.name, args: parseArgs([...(c.command || []), ...(c.args || [])]) };
    }
    return found;
  }

  // ── loaders ────────────────────────────────────────────────────────────────
  static fromManifests(loaded, { namespaces = [], excludeNamespaces = [] } = {}) {
    const inv = new Inventory('manifests');
    const nsOk = (o) => { const n = nsOf(o); return (!namespaces.length || !n || namespaces.includes(n)) && !excludeNamespaces.includes(n); };
    for (const d of loaded.docs) {
      if (!inv.data.has(d.kind)) continue;
      if (d.kind === 'Namespace' ? (excludeNamespaces.includes(d.metadata && d.metadata.name) || (namespaces.length && !namespaces.includes(d.metadata && d.metadata.name))) : !nsOk(d)) continue;
      inv.data.get(d.kind).push(d);
    }
    const seen = new Set(inv.data.get('Namespace').map((n) => n.metadata && n.metadata.name).filter(Boolean));
    for (const [k, arr] of inv.data) if (k !== 'Namespace') for (const o of arr) if (nsOf(o)) seen.add(nsOf(o));
    inv.scopes = [...seen].sort();
    inv.manifest = { files: loaded.files, skipped: loaded.skipped, documents: loaded.documents };
    return inv;
  }

  static async fromCluster(client, { namespaces = [], excludeNamespaces = [], kubeletConfigz = false, log = () => {} } = {}) {
    const inv = new Inventory('cluster');
    try { inv.version = await client.get('/version'); } catch (e) { inv.notes.push(`/version failed: ${e.message}`); }

    const jobs = [];
    for (const [kind, p, namespaced, metaOnly] of RESOURCES) {
      jobs.push((async () => {
        try {
          let items;
          if (kind === 'Namespace' && namespaces.length) {
            // read the named namespaces one by one: needs no cluster-wide "list namespaces" permission
            items = [];
            for (const ns of namespaces) {
              try { items.push(await client.get(`/api/v1/namespaces/${encodeURIComponent(ns)}`)); } catch (e) { if (!(e instanceof ApiError) || e.status !== 404) throw e; }
            }
          } else if (namespaced && namespaces.length) {
            items = [];
            const base = p.replace(/^(\/apis?\/[^/]+(?:\/[^/]+)?)\/(.+)$/, (m, g, r) => `${g}/namespaces/\u0000/${r}`);
            for (const ns of namespaces) items.push(...await client.list(base.replace('\u0000', encodeURIComponent(ns)), { metadataOnly: metaOnly }));
          } else {
            items = await client.list(p, { metadataOnly: metaOnly });
          }
          if (kind === 'Secret') items = items.map((s) => ({ kind: 'Secret', metadata: s.metadata, type: s.type }));   // never keep values
          for (const it of items) if (!it.kind) it.kind = kind;
          if (kind === 'Namespace') items = items.filter((n) => !excludeNamespaces.includes(n.metadata.name) && (!namespaces.length || namespaces.includes(n.metadata.name)));
          else if (namespaced) items = items.filter((o) => !excludeNamespaces.includes(nsOf(o)));
          inv.data.set(kind, items);
          inv.status.set(kind, { ok: true });
          log(`  fetched ${items.length} ${kind}`);
        } catch (e) {
          let reason = e.message;
          if (e instanceof ApiError && e.status === 403) reason = `${e.message}${namespaced && !namespaces.length ? ' — grant list access cluster-wide, or restrict the scan with --namespace' : ''}`;
          if (e instanceof ApiError && e.status === 404) reason = `${kind} API not served by this cluster (${e.message})`;
          inv.status.set(kind, { ok: false, reason, status: e.status || 0 });
          log(`  ${kind}: ${reason}`);
        }
      })());
    }
    await Promise.all(jobs);

    // namespaces the scan covers (for the diff): what was listed, or the explicit filter
    inv.scopes = (namespaces.length ? namespaces : inv.data.get('Namespace').map((n) => n.metadata.name)).filter((n) => !excludeNamespaces.includes(n)).sort();

    // anonymous access probe: an unauthenticated request that must NOT be allowed to list namespaces
    const probe = await client.getAnonymous('/api/v1/namespaces?limit=1');
    inv.anonymousProbe = { status: probe.status, error: probe.error || null };

    if (kubeletConfigz) {
      for (const n of inv.data.get('Node')) {
        try {
          const c = await client.get(`/api/v1/nodes/${encodeURIComponent(n.metadata.name)}/proxy/configz`);
          if (c && c.kubeletconfig) inv.kubeletConfigs.set(n.metadata.name, c.kubeletconfig);
        } catch (e) { inv.kubeletConfigs.set(n.metadata.name, { __error: e.message }); }
      }
    }
    return inv;
  }
}

/** ["--a=1", "--b", "2", "--c"] → Map flag → value ("true" for a bare flag). */
function parseArgs(list) {
  const m = new Map();
  const a = list.map(String);
  for (let i = 0; i < a.length; i++) {
    const t = a[i];
    if (!t.startsWith('--')) continue;
    const eq = t.indexOf('=');
    if (eq > 0) m.set(t.slice(2, eq), t.slice(eq + 1));
    else if (a[i + 1] !== undefined && !a[i + 1].startsWith('--')) { m.set(t.slice(2), a[i + 1]); i++; }
    else m.set(t.slice(2), 'true');
  }
  return m;
}

export { Inventory, Unavailable, RESOURCES, KINDS, nsOf, parseArgs };
