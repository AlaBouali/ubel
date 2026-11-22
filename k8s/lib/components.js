'use strict';
// components.js — the software the cluster itself reports, as package URLs for the SCA engine (vm/lib/scascan.js → scanComponents).
//
// ubel-k8s sees API objects, never what is inside a container, so it cannot scan an image's packages (that is what ubel-docker does),
// nor the operating-system packages of the nodes (ubel-vm --root <mount> / --host-proc, run as a DaemonSet). What the API does state
// are versions of components whose code is known by name, and those are checked:
//   - the API server's version (GET /version) and every kubelet's (node.status.nodeInfo.kubeletVersion)      → k8s.io/kubernetes
//   - the container runtime of every node (containerRuntimeVersion: containerd / CRI-O)                    → github.com/containerd/containerd, github.com/cri-o/cri-o
//   - the control-plane and add-on images of kube-system that come from the official Kubernetes registries:
//     kube-apiserver / kube-controller-manager / kube-scheduler / kube-proxy, etcd, CoreDNS
// Vendor suffixes (-eks-…, -gke.…, +k3s1, +rke2r1) are cut: advisories are written against the upstream release. A managed control plane
// (EKS / GKE / AKS) is patched by its provider, who may have back-ported a fix without changing the version, so a finding on it says so.

import { arr, obj } from '../checks/util.js';

const GO = (module, v) => `pkg:golang/${module}@v${v}`;
const semver = (s) => { const m = /(\d+)\.(\d+)\.(\d+)/.exec(String(s || '')); return m ? `${m[1]}.${m[2]}.${m[3]}` : null; };
const OFFICIAL = /^(?:registry\.k8s\.io|k8s\.gcr\.io|gcr\.io\/google_containers|gcr\.io\/k8s-staging-[\w-]+|(?:docker\.io\/)?coredns)(?:\/|$)/;

/** "registry/path/name:tag@sha256:…" → { repo, name, tag } */
export function parseImage(image) {
  const noDigest = String(image || '').split('@')[0];
  const i = noDigest.lastIndexOf(':');
  const hasTag = i > noDigest.lastIndexOf('/');
  const repo = hasTag ? noDigest.slice(0, i) : noDigest;
  return { repo, name: repo.split('/').pop(), tag: hasTag ? noDigest.slice(i + 1) : '' };
}

const KUBE_IMAGES = new Set(['kube-apiserver', 'kube-controller-manager', 'kube-scheduler', 'kube-proxy']);

/**
 * @param {import('./inventory.js').Inventory} inv  a live-cluster inventory
 * @returns {{ components: {purl:string, name:string, version:string, role:string, where:string[]}[], managed: string|null }}
 */
export function clusterComponents(inv) {
  const byPurl = new Map();
  const add = (purl, name, version, role, where) => {
    if (!byPurl.has(purl)) byPurl.set(purl, { purl, name, version, role, where: [] });
    const e = byPurl.get(purl);
    if (!e.role.split(', ').includes(role)) e.role += `, ${role}`;
    if (where && !e.where.includes(where)) e.where.push(where);
  };
  const gv = inv.version && inv.version.gitVersion;
  const managed = !gv ? null : /-eks-/.test(gv) ? 'EKS' : /-gke\./.test(gv) ? 'GKE' : null;
  const api = semver(gv);
  if (api) add(GO('k8s.io/kubernetes', api), 'k8s.io/kubernetes', `v${api}`, 'API server', 'the API server');

  for (const n of inv.list('Node')) {
    const info = obj(obj(n.status).nodeInfo), name = (n.metadata && n.metadata.name) || '(node)';
    const kv = semver(info.kubeletVersion);
    if (kv) add(GO('k8s.io/kubernetes', kv), 'k8s.io/kubernetes', `v${kv}`, 'kubelet', `node ${name}`);
    const rt = /^(containerd|cri-o):\/\/v?(\d+\.\d+\.\d+)/i.exec(String(info.containerRuntimeVersion || ''));
    if (rt) {
      const [mod, label] = rt[1].toLowerCase() === 'containerd' ? ['github.com/containerd/containerd', 'containerd'] : ['github.com/cri-o/cri-o', 'CRI-O'];
      add(GO(mod, rt[2]), mod, `v${rt[2]}`, `${label} (container runtime)`, `node ${name}`);
    }
  }

  for (const w of inv.workloads()) {
    if (w.namespace !== 'kube-system') continue;
    for (const c of [...arr(w.spec.containers), ...arr(w.spec.initContainers)]) {
      const { repo, name, tag } = parseImage(c && c.image);
      if (!OFFICIAL.test(repo) || !tag) continue;
      const v = semver(tag);
      if (!v) continue;
      if (KUBE_IMAGES.has(name)) add(GO('k8s.io/kubernetes', v), 'k8s.io/kubernetes', `v${v}`, name, w.ref);
      else if (name === 'etcd') add(GO('go.etcd.io/etcd/server/v3', v), 'go.etcd.io/etcd/server/v3', `v${v}`, 'etcd', w.ref);
      else if (name === 'coredns' && /coredns$/.test(repo)) add(GO('github.com/coredns/coredns', v), 'github.com/coredns/coredns', `v${v}`, 'CoreDNS', w.ref);
    }
  }
  return { components: [...byPurl.values()], managed };
}
