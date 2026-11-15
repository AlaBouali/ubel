'use strict';
// ubel-k8s — stdlib-only Kubernetes security audit (live cluster or manifest files).
//
// Talks to the API server with node:https (read-only GETs) or reads YAML/JSON manifests, and evaluates a baseline of
// checks: Pod Security Standards, RBAC, network exposure, namespace guardrails, control plane and node settings.
// Node.js built-ins only: no third-party packages, no kubectl, no other program is executed.

import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { runCli, UsageError } from '../vm/lib/runner.js';
import { rules } from './checks/index.js';
import { K8S_PROFILE } from './profile.js';
import { Inventory, RESOURCES } from './lib/inventory.js';
import { loadManifests } from './lib/manifests.js';
import { resolveConnection, KubeConfigError } from './lib/kubeconfig.js';
import { KubeClient } from './lib/client.js';
import { getComplianceForK8sCheck, getFrameworkIdsForK8sCheck } from '../sca/compliance_mappings.js';

const HELP = `
k8s-scanner — stdlib-only Kubernetes security audit

Usage:
  ubel-k8s [--kubeconfig <file>] [--context <name>] [--token-file <file>] [--namespace <ns,..>] [--exclude-namespace <ns,..>]
           [--kubelet-configz] [--allowed-registries <reg,..>] [--insecure-skip-tls-verify] [--timeout <seconds>]
  ubel-k8s --manifests <file|dir>[,<file|dir>…]
           [--working-dir <path>] [--min-severity <sev>] [--fail-on <sev|none|N:sev>] [--only …] [--skip …]
           [--allow-partial] [--verbose] [--quiet]

Live mode (default) uses your kubeconfig ($KUBECONFIG, ~/.kube/config) or the in-cluster service account and only sends
read (GET) requests. Secrets are requested as metadata only; their values are never fetched or stored. The credentials
need read access to the listed resources (the built-in "view" ClusterRole plus RBAC objects and nodes is enough; where
a list is forbidden the checks that need it are reported as "not assessed" and the run exits 3 unless --allow-partial).
exec-based credential plugins (aws eks get-token, gke-gcloud-auth-plugin …) are not supported because ubel-k8s never
runs another program: use --token-file <file> (or $KUBE_TOKEN) or a client-certificate kubeconfig.

Manifest mode (--manifests) audits YAML / JSON files offline (Helm templates must be rendered first). Checks that need
a view of the whole cluster (missing NetworkPolicy, quotas, API server version …) are reported as not applicable.

Options:
  --kubeconfig <file>          kubeconfig to use (default: $KUBECONFIG, then ~/.kube/config, then in-cluster)
  --context <name>             kubeconfig context (default: current-context)
  --token-file <file>          Bearer token file (overrides the kubeconfig credentials; $KUBE_TOKEN also works)
  --insecure-skip-tls-verify   Do not verify the API server certificate (reported as a coverage note)
  --namespace <a,b>            Audit only these namespaces (lists per namespace, so namespace-scoped access is enough)
  --exclude-namespace <a,b>    Skip these namespaces (for example kube-system)
  --kubelet-configz            Also read each kubelet's configuration (needs the nodes/proxy permission)
  --allowed-registries <a,b>   Flag images that do not come from these registries (e.g. registry.example.com,ghcr.io)
  --manifests <paths>          Audit manifest files / directories instead of a cluster
  --timeout <seconds>          Per-request timeout (default 30)
`;

const spec = {
  cli: 'ubel-k8s',
  tag: 'k8s',
  profile: K8S_PROFILE,
  heading: 'Kubernetes Security Scan Summary',
  help: HELP,
  flags: {
    '--kubeconfig': { key: 'kubeconfig', value: true },
    '--context': { key: 'context', value: true },
    '--token-file': { key: 'tokenFile', value: true },
    '--insecure-skip-tls-verify': { key: 'insecure', value: false },
    '--namespace': { key: 'namespaces', value: true, list: true },
    '--exclude-namespace': { key: 'excludeNamespaces', value: true, list: true },
    '--kubelet-configz': { key: 'kubeletConfigz', value: false },
    '--allowed-registries': { key: 'allowedRegistries', value: true, list: true },
    '--manifests': { key: 'manifests', value: true, list: true },
    '--timeout': { key: 'timeout', value: true, number: true },
  },
  async catalogue() { return { rules }; },
  async prepare(args, log) {
    const namespaces = args.namespaces || [], excludeNamespaces = args.excludeNamespaces || [];
    const deps = { complianceFor: getComplianceForK8sCheck, frameworksFor: getFrameworkIdsForK8sCheck };
    const options = {
      ...(namespaces.length ? { namespaces } : {}), ...(excludeNamespaces.length ? { excluded_namespaces: excludeNamespaces } : {}),
      ...(args.allowedRegistries ? { allowed_registries: args.allowedRegistries } : {}),
    };

    // ── manifest mode ──
    if (args.manifests && args.manifests.length) {
      const loaded = loadManifests(args.manifests);
      if (!loaded.documents) {
        throw new UsageError(`No Kubernetes documents found in: ${args.manifests.join(', ')}${loaded.skipped.length ? `\nSkipped: ${loaded.skipped.slice(0, 5).map((s) => `${s.file} (${s.reason})`).join('; ')}` : ''}`);
      }
      const inv = Inventory.fromManifests(loaded, { namespaces, excludeNamespaces });
      inv.options = { allowedRegistries: args.allowedRegistries || [] };
      log(`Loaded ${loaded.documents} document(s) from ${loaded.files.length} file(s)`);
      const target = { subject: path.basename(path.resolve(args.manifests[0])), source: 'manifests', paths: args.manifests.map((p) => path.resolve(p)), files: loaded.files.length, documents: loaded.documents, scopes_scanned: inv.scopes };
      return {
        ctx: inv, rules, target, deps, options: { ...options, manifests: args.manifests },
        notes: () => loaded.skipped.map((s) => `Skipped ${s.file}: ${s.reason}.`),
        sameTarget: (prev) => !prev.target || !prev.target.source || prev.target.source === 'manifests',
      };
    }

    // ── live cluster ──
    let conn;
    try { conn = resolveConnection({ kubeconfig: args.kubeconfig, context: args.context, tokenFile: args.tokenFile, insecure: args.insecure }); }
    catch (e) { if (e instanceof KubeConfigError) throw new UsageError(e.message); throw e; }
    const client = new KubeClient(conn, { timeoutMs: (args.timeout || 30) * 1000 });
    log(`Connecting to ${conn.server} (${conn.source})`);
    const inv = await Inventory.fromCluster(client, { namespaces, excludeNamespaces, kubeletConfigz: !!args.kubeletConfigz, log });
    inv.options = { allowedRegistries: args.allowedRegistries || [] };
    const failed = [...inv.status.values()].filter((s) => !s.ok);
    if (failed.length === RESOURCES.length && !inv.version) {
      client.close();
      throw new Error(`Cannot read anything from ${conn.server}: ${failed[0].reason}`);
    }
    const v = (inv.version && inv.version.gitVersion) || null;
    let origin; try { origin = new URL(conn.server).origin; } catch { origin = conn.server; }
    const target = {
      subject: conn.contextName || conn.clusterName, source: 'cluster', cluster: conn.clusterName, ...(conn.contextName ? { context: conn.contextName } : {}), server: origin,
      credentials: conn.cert && conn.key ? 'client certificate' : (conn.token ? 'bearer token' : 'none'), connection: conn.source,
      server_version: v, ...(v ? { platform: /-eks-/.test(v) ? 'EKS' : /-gke\./.test(v) ? 'GKE' : /\+k3s/.test(v) ? 'k3s' : /\+rke2/.test(v) ? 'RKE2' : undefined } : {}),
      nodes: inv.data.get('Node').length, namespaces_total: inv.data.get('Namespace').length, scopes_scanned: inv.scopes,
    };
    return {
      ctx: inv, rules, target, deps, options: { ...options, ...(conn.insecure ? { tls_verification: 'disabled' } : {}), ...(args.kubeletConfigz ? { kubelet_configz: true } : {}) },
      close: () => client.close(),
      notes: () => {
        const n = [...conn.warnings, ...inv.notes];
        if (conn.insecure) n.push('TLS verification of the API server certificate was disabled (--insecure-skip-tls-verify or the kubeconfig).');
        for (const [kind, st] of inv.status) if (!st.ok) n.push(`${kind}: ${st.reason}`);
        return n;
      },
      sameTarget: (prev) => !prev.target || !prev.target.cluster || prev.target.cluster === target.cluster,
    };
  },
};

async function main(argv) { return runCli(spec, argv); }

export { main, spec };

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => { console.error('Fatal error:', err.stack || err.message); process.exitCode = 1; });
}
