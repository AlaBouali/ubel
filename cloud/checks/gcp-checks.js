'use strict';
import * as storage from '../providers/gcp/storage.js';
import * as compute from '../providers/gcp/compute.js';
import * as iam from '../providers/gcp/iam.js';
import * as cloudsql from '../providers/gcp/sql.js';
import * as bigquery from '../providers/gcp/bigquery.js';
import * as cloudrun from '../providers/gcp/run.js';
import * as cloudfunctions from '../providers/gcp/functions.js';
import * as gke from '../providers/gcp/gke.js';
import { mapLimit } from '../lib/concurrency.js';

const SENSITIVE_PORTS = {
  22: 'SSH',
  3389: 'RDP',
  3306: 'MySQL',
  5432: 'PostgreSQL',
  27017: 'MongoDB',
  6379: 'Redis',
  9200: 'Elasticsearch',
};
const PUBLIC_MEMBERS = new Set(['allUsers', 'allAuthenticatedUsers']);
const PRIMITIVE_ADMIN_ROLES = new Set(['roles/owner', 'roles/editor']);
const CONCURRENCY = 8;
// item 4 of the later review: an unscoped (no targetTags) firewall rule
// applies to every instance on the network, while a tag-scoped one only
// applies to instances carrying that tag -- materially smaller blast
// radius for the same rule, worth a severity notch down rather than
// treating them identically.
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

function portInRange(portsSpec, port) {
  // portsSpec entries look like "22" or "20-8080"; empty ports array on a
  // GCP firewall "allowed" entry means "all ports" for that protocol.
  if (!portsSpec || portsSpec.length === 0) return true;
  for (const spec of portsSpec) {
    const [lo, hi] = spec.includes('-') ? spec.split('-').map(Number) : [Number(spec), Number(spec)];
    if (port >= lo && port <= hi) return true;
  }
  return false;
}

function severityForTagScope(baseSeverity, isTagScoped) {
  if (!isTagScoped) return baseSeverity;
  const idx = SEVERITY_ORDER.indexOf(baseSeverity);
  return SEVERITY_ORDER[Math.min(idx + 1, SEVERITY_ORDER.length - 1)];
}

async function runStorageChecks(project, accessToken, reporter, log) {
  let buckets;
  try {
    buckets = await storage.listBuckets(project, accessToken);
  } catch (err) {
    log(`  [gcp:storage] listBuckets failed: ${err.message}`);
    return;
  }
  log(`  [gcp:storage] ${buckets.length} bucket(s) found`);

  await mapLimit(buckets, CONCURRENCY, async (bucket) => {
    try {
      const bindings = await storage.getBucketIamPolicy(bucket.name, accessToken);
      // item 4 of the later review: publicAccessPrevention was already
      // fetched by storage.js (see its comment) but never reported on --
      // a bucket with it "enforced" makes a public IAM binding below
      // inert, while "inherited" (i.e. not enforced) means the binding
      // is exploitable as written. Worth surfacing as a pair, per the
      // review, so the public-binding finding says which case this is
      // rather than reading identically either way.
      const papEnforced = bucket.publicAccessPrevention === 'enforced';
      const papNote = papEnforced
        ? ' Public Access Prevention is "enforced" on this bucket, which should already block this binding from being exploitable — worth checking whether the binding predates PAP being enabled, or whether enforcement is actually taking effect.'
        : ` Public Access Prevention is "${bucket.publicAccessPrevention || 'inherited'}" (not "enforced") on this bucket, so this binding is exploitable as written.`;
      for (const b of bindings) {
        const publicMembers = (b.members || []).filter((m) => PUBLIC_MEMBERS.has(m));
        if (publicMembers.length === 0) continue;
        reporter.add({
          provider: 'gcp',
          service: 'storage',
          check: 'gcs-bucket-public-iam',
          severity: publicMembers.includes('allUsers') ? 'critical' : 'high',
          action: 'gcs-remove-public-iam',
          title: `GCS bucket IAM policy grants "${b.role}" to ${publicMembers.join(', ')}`,
          resource: bucket.name,
          region: bucket.location,
          description: `${publicMembers.join(', ')} means anyone on the internet (allUsers) or any Google account (allAuthenticatedUsers) has "${b.role}" on this bucket.${papNote}`,
          remediation: `gcloud storage buckets remove-iam-policy-binding gs://${bucket.name} --member=${publicMembers[0]} --role=${b.role}`,
        });
      }
      if (!papEnforced) {
        reporter.add({
          provider: 'gcp',
          service: 'storage',
          check: 'gcs-bucket-public-access-prevention-not-enforced',
          severity: 'low',
          action: 'gcs-enforce-public-access-prevention',
          title: 'GCS bucket does not enforce Public Access Prevention',
          resource: bucket.name,
          region: bucket.location,
          description: `publicAccessPrevention is "${bucket.publicAccessPrevention || 'inherited'}", not "enforced" — a public IAM binding or ACL added to this bucket (now or by mistake in the future) would not be blocked outright.`,
          remediation: `gcloud storage buckets update gs://${bucket.name} --public-access-prevention`,
        });
      }
      if (!bucket.uniformBucketLevelAccess) {
        reporter.add({
          provider: 'gcp',
          service: 'storage',
          check: 'gcs-bucket-fine-grained-acl',
          severity: 'low',
          action: 'gcs-enable-uniform-access',
          title: 'GCS bucket uses fine-grained ACLs instead of uniform bucket-level access',
          resource: bucket.name,
          region: bucket.location,
          description: 'Fine-grained (legacy ACL) mode allows per-object ACLs that are easy to lose track of and audit.',
          remediation: `gcloud storage buckets update gs://${bucket.name} --uniform-bucket-level-access`,
        });
      }
    } catch (err) {
      log(`  [gcp:storage] ${bucket.name}: ${err.message}`);
    }
  });
}

async function runFirewallChecks(project, accessToken, reporter, log) {
  let rules;
  try {
    rules = await compute.listFirewalls(project, accessToken);
  } catch (err) {
    log(`  [gcp:compute] listFirewalls failed: ${err.message}`);
    return;
  }
  log(`  [gcp:compute] ${rules.length} firewall rule(s) found`);

  for (const rule of rules) {
    if (rule.disabled || rule.direction !== 'INGRESS') continue;
    // item 5: only 0.0.0.0/0 was ever checked — ::/0 (IPv6 "the whole
    // internet") slipped through entirely.
    const openV4 = rule.sourceRanges.includes('0.0.0.0/0');
    const openV6 = rule.sourceRanges.includes('::/0');
    if (!openV4 && !openV6) continue;
    const openRange = openV4 ? '0.0.0.0/0' : '::/0';
    // Surface tag scoping in the description (rather than skipping the
    // finding) — a targetTags-scoped rule is still open to the internet
    // for whichever instances carry that tag, it's just not every
    // instance in the network (item 5: "ignore sourceTags/targetTags").
    const isTagScoped = rule.targetTags.length > 0;
    const scopeNote = isTagScoped ? ` Applies only to instances tagged: ${rule.targetTags.join(', ')}.` : '';

    for (const allowed of rule.allowed) {
      if (allowed.protocol === 'all') {
        reporter.add({
          provider: 'gcp',
          service: 'compute',
          check: 'gcp-fw-open-all',
          severity: severityForTagScope('critical', isTagScoped),
          action: 'gcp-fw-restrict-source',
          title: 'Firewall rule allows ALL protocols/ports from the internet',
          resource: rule.name,
          description: `Rule "${rule.name}" allows all traffic from ${openRange} on network ${rule.network}.${scopeNote}`,
          remediation: `gcloud compute firewall-rules update ${rule.name} --source-ranges=<restricted-cidr>`,
        });
        continue;
      }
      if (allowed.ports.length === 0) {
        reporter.add({
          provider: 'gcp',
          service: 'compute',
          check: 'gcp-fw-open-all-ports-protocol',
          severity: severityForTagScope('high', isTagScoped),
          action: 'gcp-fw-restrict-source',
          title: `Firewall rule allows all ${allowed.protocol.toUpperCase()} ports from the internet`,
          resource: rule.name,
          description: `Rule "${rule.name}" allows all ${allowed.protocol} ports from ${openRange}.${scopeNote}`,
          remediation: `gcloud compute firewall-rules update ${rule.name} --source-ranges=<restricted-cidr>`,
        });
        continue;
      }
      const hitPorts = Object.keys(SENSITIVE_PORTS)
        .map(Number)
        .filter((p) => portInRange(allowed.ports, p));
      if (hitPorts.length > 0) {
        for (const port of hitPorts) {
          reporter.add({
            provider: 'gcp',
            service: 'compute',
            check: 'gcp-fw-open-sensitive-port',
            severity: severityForTagScope('high', isTagScoped),
            action: 'gcp-fw-restrict-source',
            title: `Firewall rule exposes ${SENSITIVE_PORTS[port]} (port ${port}) to the internet`,
            resource: rule.name,
            description: `Rule "${rule.name}" allows ${allowed.protocol} port ${port} from ${openRange}.${scopeNote}`,
            remediation: `gcloud compute firewall-rules update ${rule.name} --source-ranges=<restricted-cidr>`,
          });
        }
      } else {
        reporter.add({
          provider: 'gcp',
          service: 'compute',
          check: 'gcp-fw-open-ingress',
          severity: severityForTagScope('medium', isTagScoped),
          action: 'gcp-fw-restrict-source',
          title: 'Firewall rule allows inbound access from the internet',
          resource: rule.name,
          description: `Rule "${rule.name}" allows ${allowed.protocol} ports ${allowed.ports.join(',')} from ${openRange}.${scopeNote}`,
          remediation: 'Narrow source-ranges to only what needs this access.',
        });
      }
    }
  }
}

async function runIamChecks(project, accessToken, reporter, log) {
  let bindings;
  try {
    bindings = await iam.getProjectIamPolicy(project, accessToken);
  } catch (err) {
    log(`  [gcp:iam] getIamPolicy failed: ${err.message}`);
    return;
  }
  log(`  [gcp:iam] ${bindings.length} role binding(s) found`);

  for (const b of bindings) {
    const publicMembers = (b.members || []).filter((m) => PUBLIC_MEMBERS.has(m));
    if (publicMembers.length === 0) continue;
    const isAdminRole = PRIMITIVE_ADMIN_ROLES.has(b.role);
    reporter.add({
      provider: 'gcp',
      service: 'iam',
      check: 'gcp-project-iam-public',
      severity: isAdminRole ? 'critical' : 'high',
      action: 'gcp-iam-remove-public-binding',
      title: `Project IAM policy grants "${b.role}" to ${publicMembers.join(', ')}`,
      resource: project,
      description: isAdminRole
        ? `"${b.role}" bound to ${publicMembers.join(', ')} means anyone can administer this entire GCP project.`
        : `"${b.role}" is bound to ${publicMembers.join(', ')}, exposing it to the public internet or any Google account.`,
      remediation: `gcloud projects remove-iam-policy-binding ${project} --member=${publicMembers[0]} --role=${b.role}`,
    });
  }
}

async function runComputeInstanceChecks(project, accessToken, reporter, log) {
  let instances;
  try {
    instances = await compute.listInstances(project, accessToken);
  } catch (err) {
    log(`  [gcp:compute] listInstances failed: ${err.message}`);
    return;
  }
  log(`  [gcp:compute] ${instances.length} instance(s) found`);

  for (const inst of instances) {
    const defaultSaFullAccess = inst.serviceAccounts.some(
      (sa) =>
        sa.email.includes('-compute@developer.gserviceaccount.com') &&
        sa.scopes.includes('https://www.googleapis.com/auth/cloud-platform')
    );
    if (inst.hasExternalIp && defaultSaFullAccess) {
      reporter.add({
        provider: 'gcp',
        service: 'compute',
        check: 'gcp-instance-default-sa-full-access',
        severity: 'medium',
        action: 'gcp-instance-scope-service-account',
        title: 'Internet-facing instance uses the default service account with full API access',
        resource: inst.name,
        region: inst.zone,
        description: 'This instance has a public IP and its default service account is scoped to cloud-platform (full API access) — a compromise of the instance compromises the whole project.',
        remediation: 'Attach a scoped, purpose-built service account instead of the default one, or narrow its OAuth scopes.',
      });
    }
  }
}

/** item 5: Cloud SQL had no checks at all before, despite being "a very
 * common misconfiguration" per the review. */
async function runCloudSqlChecks(project, accessToken, reporter, log) {
  let instances;
  try {
    instances = await cloudsql.listInstances(project, accessToken);
  } catch (err) {
    log(`  [gcp:sql] listInstances failed: ${err.message}`);
    return;
  }
  log(`  [gcp:sql] ${instances.length} Cloud SQL instance(s) found`);

  for (const inst of instances) {
    if (inst.hasOpenAuthorizedNetwork) {
      reporter.add({
        provider: 'gcp',
        service: 'sql',
        check: 'cloudsql-authorized-network-open',
        severity: 'critical',
        action: 'cloudsql-restrict-authorized-networks',
        title: 'Cloud SQL instance authorizes connections from the entire internet',
        resource: inst.name,
        region: inst.region,
        description: `Instance "${inst.name}" has 0.0.0.0/0 in its authorized networks list.`,
        remediation: `gcloud sql instances patch ${inst.name} --clear-authorized-networks`,
      });
    } else if (inst.publicIpEnabled) {
      reporter.add({
        provider: 'gcp',
        service: 'sql',
        check: 'cloudsql-public-ip-enabled',
        severity: 'medium',
        action: 'cloudsql-disable-public-ip',
        title: 'Cloud SQL instance has a public IP address',
        resource: inst.name,
        region: inst.region,
        description: `Instance "${inst.name}" has a public IPv4 address configured. Combined with a permissive authorized-networks list this becomes internet-exposed.`,
        remediation: `gcloud sql instances patch ${inst.name} --no-assign-ip (use Private IP / a Cloud SQL Auth Proxy instead)`,
      });
    }
    if (!inst.requireSsl) {
      reporter.add({
        provider: 'gcp',
        service: 'sql',
        check: 'cloudsql-ssl-not-required',
        severity: 'medium',
        action: 'cloudsql-require-ssl',
        title: 'Cloud SQL instance does not require SSL/TLS for connections',
        resource: inst.name,
        region: inst.region,
        description: `Instance "${inst.name}" allows unencrypted client connections.`,
        remediation: `gcloud sql instances patch ${inst.name} --require-ssl`,
      });
    }
  }
}

/** item 5: BigQuery public datasets had no check at all before. */
async function runBigQueryChecks(project, accessToken, reporter, log) {
  let datasetIds;
  try {
    datasetIds = await bigquery.listDatasetIds(project, accessToken);
  } catch (err) {
    log(`  [gcp:bigquery] listDatasetIds failed: ${err.message}`);
    return;
  }
  log(`  [gcp:bigquery] ${datasetIds.length} dataset(s) found`);

  await mapLimit(datasetIds, CONCURRENCY, async (datasetId) => {
    try {
      const publicEntries = await bigquery.getDatasetAccess(project, datasetId, accessToken);
      for (const entry of publicEntries) {
        reporter.add({
          provider: 'gcp',
          service: 'bigquery',
          check: 'bigquery-dataset-public',
          severity: entry.member === 'allUsers' ? 'critical' : 'high',
          action: 'bigquery-remove-public-access',
          title: `BigQuery dataset grants "${entry.role}" to ${entry.member}`,
          resource: datasetId,
          description: `Dataset "${datasetId}" has an access entry granting "${entry.role}" to ${entry.member} — ${entry.member === 'allUsers' ? 'anyone on the internet' : 'any Google account'} can query it.`,
          remediation: `bq update --dataset --remove_all_access_for=${entry.member} ${project}:${datasetId} (or edit the dataset's access list in the console)`,
        });
      }
    } catch (err) {
      log(`  [gcp:bigquery] ${datasetId}: ${err.message}`);
    }
  });
}

/** item 4: Cloud Run had no check at all before, despite unauthenticated
 * invocation being an extremely common (and sometimes intentional --
 * public webhooks/APIs) misconfiguration to leave unreviewed. */
async function runCloudRunChecks(project, accessToken, reporter, log) {
  let services;
  try {
    services = await cloudrun.listServices(project, accessToken);
  } catch (err) {
    log(`  [gcp:run] listServices failed: ${err.message}`);
    return;
  }
  log(`  [gcp:run] ${services.length} Cloud Run service(s) found`);

  await mapLimit(services, CONCURRENCY, async (svc) => {
    try {
      const bindings = await cloudrun.getServiceIamPolicy(svc.name, accessToken);
      for (const b of bindings) {
        const publicMembers = (b.members || []).filter((m) => PUBLIC_MEMBERS.has(m));
        if (publicMembers.length === 0) continue;
        const isInvokerOnly = b.role === 'roles/run.invoker';
        reporter.add({
          provider: 'gcp',
          service: 'run',
          check: 'cloudrun-service-public-iam',
          severity: isInvokerOnly ? 'medium' : 'high',
          action: 'cloudrun-remove-public-iam',
          title: isInvokerOnly
            ? 'Cloud Run service allows unauthenticated invocation'
            : `Cloud Run service grants "${b.role}" to ${publicMembers.join(', ')}`,
          resource: svc.displayName,
          region: svc.location,
          description: isInvokerOnly
            ? `"${b.role}" is bound to ${publicMembers.join(', ')} on service "${svc.displayName}" — anyone on the internet can invoke it without credentials. This is often intentional for public HTTP endpoints/webhooks, but worth confirming that's the intent here.`
            : `"${b.role}" is bound to ${publicMembers.join(', ')} on service "${svc.displayName}", which is broader than just invoking it.`,
          remediation: `gcloud run services remove-iam-policy-binding ${svc.displayName} --region=${svc.location} --member=${publicMembers[0]} --role=${b.role}`,
        });
      }
    } catch (err) {
      log(`  [gcp:run] ${svc.displayName}: getIamPolicy failed: ${err.message}`);
    }
  });
}

/** item 4: Cloud Functions had no check at all before -- same
 * public-invoker reasoning as Cloud Run above. */
async function runCloudFunctionsChecks(project, accessToken, reporter, log) {
  let fns;
  try {
    fns = await cloudfunctions.listFunctions(project, accessToken);
  } catch (err) {
    log(`  [gcp:functions] listFunctions failed: ${err.message}`);
    return;
  }
  log(`  [gcp:functions] ${fns.length} Cloud Function(s) found`);

  await mapLimit(fns, CONCURRENCY, async (fn) => {
    try {
      const bindings = await cloudfunctions.getFunctionIamPolicy(fn.name, accessToken);
      for (const b of bindings) {
        const publicMembers = (b.members || []).filter((m) => PUBLIC_MEMBERS.has(m));
        if (publicMembers.length === 0) continue;
        const isInvokerOnly = b.role === 'roles/cloudfunctions.invoker';
        reporter.add({
          provider: 'gcp',
          service: 'functions',
          check: 'cloudfunctions-public-iam',
          severity: isInvokerOnly ? 'medium' : 'high',
          action: 'cloudfunctions-remove-public-iam',
          title: isInvokerOnly
            ? 'Cloud Function allows unauthenticated invocation'
            : `Cloud Function grants "${b.role}" to ${publicMembers.join(', ')}`,
          resource: fn.displayName,
          region: fn.location,
          description: isInvokerOnly
            ? `"${b.role}" is bound to ${publicMembers.join(', ')} on function "${fn.displayName}" — anyone on the internet can invoke it without credentials. This is often intentional for public HTTP triggers, but worth confirming that's the intent here.`
            : `"${b.role}" is bound to ${publicMembers.join(', ')} on function "${fn.displayName}", which is broader than just invoking it.`,
          remediation: `gcloud functions remove-iam-policy-binding ${fn.displayName} --region=${fn.location} --member=${publicMembers[0]} --role=${b.role}`,
        });
      }
    } catch (err) {
      log(`  [gcp:functions] ${fn.displayName}: getIamPolicy failed: ${err.message}`);
    }
  });
}

/** item 4: GKE had no check at all before -- public control plane with
 * no authorized-networks restriction, legacy ABAC (deprecated,
 * coarse-grained authorization), and legacy static/basic-auth
 * credentials are all long-standing "obvious" GKE findings. */
async function runGkeChecks(project, accessToken, reporter, log) {
  let clusters;
  try {
    clusters = await gke.listClusters(project, accessToken);
  } catch (err) {
    log(`  [gcp:gke] listClusters failed: ${err.message}`);
    return;
  }
  log(`  [gcp:gke] ${clusters.length} GKE cluster(s) found`);

  for (const cluster of clusters) {
    if (cluster.publicEndpoint && !cluster.masterAuthorizedNetworksEnabled) {
      reporter.add({
        provider: 'gcp',
        service: 'gke',
        check: 'gke-public-control-plane-no-authorized-networks',
        severity: 'high',
        action: 'gke-restrict-control-plane-access',
        title: 'GKE control plane is public with no authorized networks restriction',
        resource: cluster.name,
        region: cluster.location,
        description: `Cluster "${cluster.name}" has a publicly reachable API server endpoint and no master-authorized-networks configured, so the Kubernetes API is reachable from any IP address (valid credentials are still required, but the attack surface is the entire internet).`,
        remediation: `gcloud container clusters update ${cluster.name} --location=${cluster.location} --enable-master-authorized-networks --master-authorized-networks=<cidr1,cidr2> (or --enable-private-endpoint to remove the public one entirely)`,
      });
    }
    if (cluster.legacyAbacEnabled) {
      reporter.add({
        provider: 'gcp',
        service: 'gke',
        check: 'gke-legacy-abac-enabled',
        severity: 'high',
        action: 'gke-disable-legacy-abac',
        title: 'GKE cluster has legacy ABAC authorization enabled',
        resource: cluster.name,
        region: cluster.location,
        description: `Cluster "${cluster.name}" has legacy Attribute-Based Access Control enabled alongside (or instead of) RBAC — ABAC is deprecated, coarse-grained, and effectively grants broad access that RBAC is meant to replace.`,
        remediation: `gcloud container clusters update ${cluster.name} --location=${cluster.location} --no-enable-legacy-authorization`,
      });
    }
    if (cluster.basicAuthConfigured) {
      reporter.add({
        provider: 'gcp',
        service: 'gke',
        check: 'gke-basic-auth-configured',
        severity: 'medium',
        action: 'gke-disable-basic-auth',
        title: 'GKE cluster has legacy basic authentication configured',
        resource: cluster.name,
        region: cluster.location,
        description: `Cluster "${cluster.name}" still has a static username/password credential configured for the API server — a long-lived, hard-to-rotate credential that bypasses normal IAM/OIDC auth and its audit trail.`,
        remediation: `gcloud container clusters update ${cluster.name} --location=${cluster.location} --no-issue-client-certificate (recreate the cluster to fully remove basic auth credentials, which can't be unset on an existing cluster).`,
      });
    }
  }
}

async function runGcpChecks({ project, accessToken }, reporter, log = () => {}) {
  await runStorageChecks(project, accessToken, reporter, log);
  await runFirewallChecks(project, accessToken, reporter, log);
  await runIamChecks(project, accessToken, reporter, log);
  await runComputeInstanceChecks(project, accessToken, reporter, log);
  await runCloudSqlChecks(project, accessToken, reporter, log);
  await runBigQueryChecks(project, accessToken, reporter, log);
  await runCloudRunChecks(project, accessToken, reporter, log);
  await runCloudFunctionsChecks(project, accessToken, reporter, log);
  await runGkeChecks(project, accessToken, reporter, log);
}

export { runGcpChecks };
