'use strict';
import { rule } from './util.js';
import { na, unassessed } from '../../vm/lib/engine.js';
import { clusterComponents } from '../lib/components.js';
import { scViolation, sortViolations } from '../../vm/lib/scfinding.js';

export default [
  rule({
    id: 'k8s-component-vulnerable', area: 'components', severity: 'high', title: 'A Kubernetes component version has a known vulnerability',
    description: 'The SCA engine (OSV.dev) finds a security advisory for a component version the cluster reports: the API server, a kubelet, a node\'s container runtime (containerd / CRI-O) or an official control-plane or add-on image in kube-system (kube-proxy, etcd, CoreDNS …). The tool does not look inside images or at the packages of the nodes: scan images with ubel-docker and the nodes with ubel-vm.',
    remediation: 'Upgrade the component to a release that contains the fix: the control plane and kubelets to a patched Kubernetes release, the container runtime to its fixed release, the add-on image to its fixed tag. On a managed service, take the provider\'s patched control-plane version.',
    cap: 100,
    async evaluate(inv) {
      if (!inv.fullView) return na('only applicable to a live cluster (the versions come from the API server and the nodes)');
      if (inv.options.noLookups) return na('advisory lookups disabled (--no-lookups)');
      const { components, managed } = clusterComponents(inv);
      if (!components.length) return unassessed('the cluster did not report any component version (/version and node info are unreadable)');
      const { scanComponents } = await import('../../vm/lib/scascan.js');
      const r = await scanComponents({ components, workDir: inv.options.workDir, threatIntel: inv.options.threatIntel, log: inv.options.log || (() => {}) });
      for (const w of r.scan_warnings || []) if (!inv.notes.includes(w)) inv.notes.push(w);
      inv.notes.push(`${components.length} component version(s) reported by the cluster were checked against OSV.dev by the SCA engine; container images and node packages are not scanned by ubel-k8s.`);
      const byId = new Map(components.map((c) => [c.purl, c]));
      const items = new Map(r.inventory.map((c) => [c.id, c]));
      return r.vulnerabilities.map((v) => {
        const c = byId.get(v.affected_package_id) || { role: 'component', where: [] };
        const where = c.where.length > 3 ? `${c.where.slice(0, 3).join(', ')} and ${c.where.length - 3} more` : c.where.join(', ');
        const isApi = /API server/.test(c.role);
        // the SCA item of the component, placed where the cluster reports it (the role and each node / workload it runs on)
        const item = items.get(v.affected_package_id);
        return scViolation(v, {
          comp: item && { ...item, paths: c.where.length ? c.where.map((w) => `${c.role}: ${w}`) : [c.role] },
          resource: `${c.role}: ${v.affected_dependency}@${v.affected_dependency_version}: ${(v.aliases || []).find((a) => /^CVE-/.test(a)) || v.id}`,
          where: `runs as ${c.role} (${where})${isApi && managed ? `; this is a managed ${managed} control plane — the provider may have back-ported the fix without changing the version` : ''}`,
        });
      }).sort(sortViolations);
    },
  }),
];
