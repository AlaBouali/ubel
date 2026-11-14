'use strict';
/**
 * GCP checks for areas gcp-checks.js doesn't cover: VPC networks and subnets,
 * project-wide Compute metadata (OS Login, serial ports), project IAM beyond
 * public bindings (audit-log configuration, service-account admin and
 * impersonation roles), service-account keys, log export sinks, Cloud DNS DNSSEC
 * and Pub/Sub IAM.
 *
 * Called from the end of runGcpChecks(). Read-only, per-step try/catch (a
 * disabled API just logs and moves on), bounded concurrency, stdlib only.
 */
import * as compute from '../providers/gcp/compute.js';
import * as iam from '../providers/gcp/iam.js';
import * as logging from '../providers/gcp/logging.js';
import * as dns from '../providers/gcp/dns.js';
import * as pubsub from '../providers/gcp/pubsub.js';
import { mapLimit } from '../lib/concurrency.js';

const PUBLIC_MEMBERS = new Set(['allUsers', 'allAuthenticatedUsers']);
const CONCURRENCY = 8;
const NINETY_DAYS_MS = 90 * 24 * 60 * 60 * 1000;

// Google-managed service agents are granted broad roles by Google itself and
// aren't something the project owner can (or should) change.
const GOOGLE_MANAGED_SA = /^serviceAccount:(service-\d+@|\d+@cloudservices\.gserviceaccount\.com$|[^@]+@(gcp-sa-[^.]+|container-engine-robot|compute-system|cloudbuild|dataflow-service-producer-prod)\.)/;

function isGoogleManagedServiceAccount(member) {
  return GOOGLE_MANAGED_SA.test(member);
}

// ─── Networks ───────────────────────────────────────────────────────────

async function runNetworkChecks(project, accessToken, reporter, log) {
  try {
    const nets = await compute.listNetworks(project, accessToken);
    log(`  [gcp:network] ${nets.length} VPC network(s) found`);
    for (const n of nets) {
      if (n.isLegacy) {
        reporter.add({
          provider: 'gcp',
          service: 'network',
          check: 'gcp-legacy-network-exists',
          severity: 'medium',
          action: 'gcp-delete-legacy-network',
          title: 'Project has a legacy-mode VPC network',
          resource: n.name,
          description: `Network "${n.name}" is a legacy network (a single global IP range, no subnets). Legacy networks can't use modern controls such as per-subnet flow logs or private Google access, and can't be converted.`,
          remediation: `Migrate workloads to a VPC network with subnets, then: gcloud compute networks delete ${n.name}`,
        });
      } else if (n.name === 'default') {
        reporter.add({
          provider: 'gcp',
          service: 'network',
          check: 'gcp-default-network-exists',
          severity: 'low',
          action: 'gcp-delete-default-network',
          title: 'The auto-created "default" VPC network still exists',
          resource: 'default',
          description: 'The default network ships with permissive pre-created firewall rules (SSH, RDP and ICMP from anywhere, and all traffic within the network) and one subnet in every region. Production projects should use purpose-built networks instead.',
          remediation: 'Once nothing depends on it: gcloud compute networks delete default (delete its firewall rules first).',
        });
      }
    }
  } catch (err) {
    log(`  [gcp:network] listNetworks failed: ${err.message}`);
  }

  try {
    const subnets = await compute.listSubnetworks(project, accessToken);
    log(`  [gcp:network] ${subnets.length} subnet(s) found`);
    for (const s of subnets) {
      // Only ordinary (PRIVATE) subnets can have flow logs; proxy-only, PSC and
      // load-balancer subnets can't.
      if (s.purpose !== 'PRIVATE' && s.purpose !== 'PRIVATE_RFC_1918') continue;
      if (s.flowLogsEnabled) continue;
      reporter.add({
        provider: 'gcp',
        service: 'network',
        check: 'gcp-subnet-flow-logs-disabled',
        severity: 'low',
        action: 'gcp-enable-subnet-flow-logs',
        title: 'VPC subnet has flow logs disabled',
        resource: `${s.network} / ${s.name}`,
        region: s.region,
        description: `Subnet "${s.name}" (network ${s.network}) does not record VPC flow logs, so there is no network-traffic audit trail for what runs in it.`,
        remediation: `gcloud compute networks subnets update ${s.name} --region=${s.region} --enable-flow-logs`,
      });
    }
  } catch (err) {
    log(`  [gcp:network] listSubnetworks failed: ${err.message}`);
  }
}

// ─── Project-wide Compute metadata ──────────────────────────────────────

async function runProjectMetadataChecks(project, accessToken, reporter, log) {
  let md;
  try {
    md = await compute.getProjectMetadata(project, accessToken);
  } catch (err) {
    log(`  [gcp:compute] project metadata read failed: ${err.message}`);
    return;
  }
  if (!md.osLoginEnabled) {
    reporter.add({
      provider: 'gcp',
      service: 'compute',
      check: 'gcp-project-oslogin-disabled',
      severity: 'low',
      action: 'gcp-enable-oslogin',
      title: 'OS Login is not enabled for the project',
      resource: project,
      description: 'Without enable-oslogin=TRUE in project metadata, SSH access to VMs is governed by SSH keys pasted into metadata (hard to audit, never expire) rather than by IAM, with per-user accounts and 2-step verification.',
      remediation: `gcloud compute project-info add-metadata --project=${project} --metadata enable-oslogin=TRUE`,
    });
  }
  if (md.serialPortEnabled) {
    reporter.add({
      provider: 'gcp',
      service: 'compute',
      check: 'gcp-project-serial-port-enabled',
      severity: 'medium',
      action: 'gcp-disable-project-serial-port',
      title: 'Interactive serial-port access is enabled for every VM in the project',
      resource: project,
      description: 'Project metadata sets serial-port-enable=true, so every VM that doesn\'t override it exposes an interactive serial console reachable with IAM alone, bypassing firewall rules.',
      remediation: `gcloud compute project-info add-metadata --project=${project} --metadata serial-port-enable=false`,
    });
  }
}

// ─── Project IAM: audit config, service-account roles ──────────────────

async function runIamExtendedChecks(project, accessToken, reporter, log) {
  let policy;
  try {
    policy = await iam.getProjectIamPolicyFull(project, accessToken);
  } catch (err) {
    log(`  [gcp:iam] getIamPolicy (full) failed: ${err.message}`);
    return;
  }

  // CIS GCP 2.1: data-access audit logs for every service, with no exempted users.
  const all = policy.auditConfigs.find((c) => c.service === 'allServices');
  const logTypes = new Set((all?.auditLogConfigs || []).map((c) => c.logType));
  const missing = ['ADMIN_READ', 'DATA_READ', 'DATA_WRITE'].filter((t) => !logTypes.has(t));
  const exempted = [...new Set((all?.auditLogConfigs || []).flatMap((c) => c.exemptedMembers || []))];
  if (missing.length > 0 || exempted.length > 0) {
    const bits = [];
    if (!all) bits.push('no audit configuration for "allServices" is set on this project');
    else if (missing.length) bits.push(`"allServices" does not log ${missing.join(', ')}`);
    if (exempted.length) bits.push(`these identities are exempted from audit logging: ${exempted.join(', ')}`);
    reporter.add({
      provider: 'gcp',
      service: 'iam',
      check: 'gcp-audit-logging-incomplete',
      severity: 'low',
      action: 'gcp-enable-audit-logging',
      title: 'Cloud Audit Logs are not fully enabled for all services',
      resource: project,
      description: `${bits.join('; ')}. Data-access audit logs are what show who read or changed customer data. This reads the project's own policy only: if the audit configuration is set at the folder or organization level this finding may be a false alarm.`,
      remediation: `gcloud projects get-iam-policy ${project} > policy.yaml, add an auditConfigs entry for service allServices with ADMIN_READ, DATA_READ and DATA_WRITE and no exemptedMembers, then gcloud projects set-iam-policy ${project} policy.yaml`,
    });
  }

  for (const b of policy.bindings) {
    const role = b.role || '';
    const roleName = role.split('/').pop() || '';
    for (const member of b.members || []) {
      if (PUBLIC_MEMBERS.has(member) || isGoogleManagedServiceAccount(member)) continue;

      // CIS GCP 1.5: service accounts shouldn't hold admin-level roles.
      if (member.startsWith('serviceAccount:')) {
        const isOwner = role === 'roles/owner';
        if (isOwner || role === 'roles/editor' || /admin/i.test(roleName)) {
          reporter.add({
            provider: 'gcp',
            service: 'iam',
            check: 'gcp-service-account-admin-role',
            severity: isOwner ? 'high' : 'medium',
            action: 'gcp-iam-reduce-service-account-role',
            title: `Service account holds the broad "${role}" role on the project`,
            resource: `${member.slice('serviceAccount:'.length)} (${role})`,
            description: `${member.slice('serviceAccount:'.length)} is bound to "${role}" on project ${project}. A service account's key or token is easy to leak and has no second factor, so whoever obtains it gets administrator-level control.`,
            remediation: `Replace it with the narrow roles the workload actually needs: gcloud projects remove-iam-policy-binding ${project} --member=${member} --role=${role}`,
          });
        }
      }

      // CIS GCP 1.6: impersonation roles shouldn't be granted project-wide.
      if (role === 'roles/iam.serviceAccountUser' || role === 'roles/iam.serviceAccountTokenCreator') {
        reporter.add({
          provider: 'gcp',
          service: 'iam',
          check: 'gcp-project-sa-impersonation-role',
          severity: 'medium',
          action: 'gcp-iam-scope-impersonation-role',
          title: `"${role}" is granted at project level`,
          resource: `${member} (${role})`,
          description: `${member} holds "${role}" on the whole project, which lets it act as (or mint tokens for) every service account in it -- including any with higher privileges than its own. Grant it on the specific service account instead.`,
          remediation: `gcloud projects remove-iam-policy-binding ${project} --member=${member} --role=${role}, then gcloud iam service-accounts add-iam-policy-binding <sa-email> --member=${member} --role=${role}`,
        });
      }
    }
  }
}

// ─── Service-account keys ───────────────────────────────────────────────

async function runServiceAccountKeyChecks(project, accessToken, reporter, log) {
  let accounts;
  try {
    accounts = await iam.listServiceAccounts(project, accessToken);
  } catch (err) {
    log(`  [gcp:iam] listServiceAccounts failed: ${err.message}`);
    return;
  }
  log(`  [gcp:iam] ${accounts.length} service account(s) found`);

  await mapLimit(accounts, CONCURRENCY, async (sa) => {
    if (sa.disabled) return; // a disabled account's keys can't be used
    let keys;
    try {
      keys = await iam.listUserManagedKeys(project, sa.email, accessToken);
    } catch (err) {
      log(`  [gcp:iam] ${sa.email}: list keys failed: ${err.message}`);
      return;
    }
    for (const key of keys) {
      reporter.add({
        provider: 'gcp',
        service: 'iam',
        check: 'gcp-sa-user-managed-key',
        severity: 'low',
        action: 'gcp-iam-delete-service-account-key',
        title: 'Service account has a user-managed (downloadable) key',
        resource: `${sa.email} / ${key.id}`,
        description: `Service account ${sa.email} has a user-managed key. Such a key is a long-lived password-equivalent file that can be copied, committed or leaked, and is valid from anywhere until it is deleted.`,
        remediation: `Prefer Workload Identity / attached service accounts / short-lived tokens, then: gcloud iam service-accounts keys delete ${key.id} --iam-account=${sa.email}`,
      });
      if (key.validAfterTime) {
        const ageMs = Date.now() - new Date(key.validAfterTime).getTime();
        if (ageMs > NINETY_DAYS_MS) {
          reporter.add({
            provider: 'gcp',
            service: 'iam',
            check: 'gcp-sa-key-not-rotated',
            severity: 'medium',
            action: 'gcp-iam-rotate-service-account-key',
            title: 'Service account key has not been rotated in over 90 days',
            resource: `${sa.email} / ${key.id}`,
            description: `User-managed key created on ${key.validAfterTime} (${Math.floor(ageMs / (24 * 3600 * 1000))} days ago) for ${sa.email}.`,
            remediation: `Create a replacement, switch consumers over, then delete this one: gcloud iam service-accounts keys create new-key.json --iam-account=${sa.email}; gcloud iam service-accounts keys delete ${key.id} --iam-account=${sa.email}`,
          });
        }
      }
    }
  });
}

// ─── Log export sinks ───────────────────────────────────────────────────

async function runLoggingChecks(project, accessToken, reporter, log) {
  let sinks;
  try {
    sinks = await logging.listSinks(project, accessToken);
  } catch (err) {
    log(`  [gcp:logging] listSinks failed: ${err.message}`);
    return;
  }
  log(`  [gcp:logging] ${sinks.length} sink(s) found`);
  if (!sinks.some((s) => s.exportsEverything && !s.disabled)) {
    reporter.add({
      provider: 'gcp',
      service: 'logging',
      check: 'gcp-no-log-export-sink',
      severity: 'low',
      action: 'gcp-create-log-sink',
      title: 'No log sink exports all log entries from the project',
      resource: project,
      description: 'No enabled sink without a filter exists on this project, so logs only live as long as the bucket retention (30 days for _Default) and can be deleted by anyone who can change the project. Organization-level sinks are not visible from here, so this may be a false alarm if one covers this project.',
      remediation: `gcloud logging sinks create all-logs storage.googleapis.com/<bucket> --project=${project} (leave the log filter empty)`,
    });
  }
}

// ─── Cloud DNS ──────────────────────────────────────────────────────────

async function runDnsChecks(project, accessToken, reporter, log) {
  let zones;
  try {
    zones = await dns.listManagedZones(project, accessToken);
  } catch (err) {
    log(`  [gcp:dns] listManagedZones failed: ${err.message}`);
    return;
  }
  log(`  [gcp:dns] ${zones.length} managed zone(s) found`);
  for (const z of zones) {
    if (!z.isPublic || z.dnssecState === 'on') continue;
    reporter.add({
      provider: 'gcp',
      service: 'dns',
      check: 'gcp-dns-zone-dnssec-disabled',
      severity: 'low',
      action: 'gcp-dns-enable-dnssec',
      title: 'Public Cloud DNS zone does not have DNSSEC enabled',
      resource: z.name,
      description: `Public zone "${z.name}" (${z.dnsName}) has DNSSEC state "${z.dnssecState}", so resolvers can't verify that answers for it are authentic (spoofing / cache-poisoning protection).`,
      remediation: `gcloud dns managed-zones update ${z.name} --dnssec-state on, then publish the DS record at your registrar`,
    });
  }
}

// ─── Pub/Sub ────────────────────────────────────────────────────────────

async function runPubSubChecks(project, accessToken, reporter, log) {
  const kinds = [
    { label: 'topic', list: pubsub.listTopics, check: 'pubsub-topic-public-iam', removeCmd: 'topics' },
    { label: 'subscription', list: pubsub.listSubscriptions, check: 'pubsub-subscription-public-iam', removeCmd: 'subscriptions' },
  ];
  for (const kind of kinds) {
    let items;
    try {
      items = await kind.list(project, accessToken);
    } catch (err) {
      log(`  [gcp:pubsub] list ${kind.label}s failed: ${err.message}`);
      continue;
    }
    log(`  [gcp:pubsub] ${items.length} ${kind.label}(s) found`);
    await mapLimit(items, CONCURRENCY, async (item) => {
      try {
        const bindings = await pubsub.getIamPolicy(item.name, accessToken);
        for (const b of bindings) {
          const publicMembers = (b.members || []).filter((m) => PUBLIC_MEMBERS.has(m));
          if (publicMembers.length === 0) continue;
          const isAdmin = /admin|editor|owner/i.test((b.role || '').split('/').pop());
          reporter.add({
            provider: 'gcp',
            service: 'pubsub',
            check: kind.check,
            severity: isAdmin ? 'critical' : 'high',
            action: 'pubsub-remove-public-iam',
            title: `Pub/Sub ${kind.label} grants "${b.role}" to ${publicMembers.join(', ')}`,
            resource: item.displayName,
            description: `${publicMembers.join(', ')} means anyone on the internet (allUsers) or any Google account (allAuthenticatedUsers) holds "${b.role}" on the ${kind.label} "${item.displayName}" -- they can ${/publisher/i.test(b.role) ? 'inject messages into it' : /subscriber|viewer/i.test(b.role) ? 'read its messages or configuration' : 'use and modify it'}.`,
            remediation: `gcloud pubsub ${kind.removeCmd} remove-iam-policy-binding ${item.displayName} --member=${publicMembers[0]} --role=${b.role} --project=${project}`,
          });
        }
      } catch (err) {
        log(`  [gcp:pubsub] ${item.displayName}: getIamPolicy failed: ${err.message}`);
      }
    });
  }
}

async function runGcpExtendedChecks({ project, accessToken }, reporter, log = () => {}) {
  await runNetworkChecks(project, accessToken, reporter, log);
  await runProjectMetadataChecks(project, accessToken, reporter, log);
  await runIamExtendedChecks(project, accessToken, reporter, log);
  await runServiceAccountKeyChecks(project, accessToken, reporter, log);
  await runLoggingChecks(project, accessToken, reporter, log);
  await runDnsChecks(project, accessToken, reporter, log);
  await runPubSubChecks(project, accessToken, reporter, log);
}

export { runGcpExtendedChecks, isGoogleManagedServiceAccount };
