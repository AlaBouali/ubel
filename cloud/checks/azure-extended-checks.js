'use strict';
/**
 * Azure checks for areas azure-checks.js doesn't cover: subscription-level posture
 * (Microsoft Defender for Cloud plans, security contact, Activity Log export,
 * Owner assignments, custom roles with wildcard permissions), managed disks,
 * PostgreSQL / MySQL flexible servers, Cosmos DB and Azure Cache for Redis.
 *
 * Called from the end of runAzureChecks(). Read-only (ARM GETs, which the built-in
 * Reader role covers), per-step try/catch, bounded concurrency, stdlib only.
 */
import * as computeApi from '../providers/azure/compute.js';
import * as monitorApi from '../providers/azure/monitor.js';
import * as securityApi from '../providers/azure/security.js';
import * as authApi from '../providers/azure/authorization.js';
import * as dbApi from '../providers/azure/dbflexible.js';
import * as cosmosApi from '../providers/azure/cosmos.js';
import * as redisApi from '../providers/azure/redis.js';
import { mapLimit } from '../lib/concurrency.js';

const CONCURRENCY = 8;

// Defender for Cloud plans worth having on. `slug` becomes part of the check id so
// each plan can carry its own CIS control. `Free` means off; `Standard` means on.
const DEFENDER_PLANS = {
  VirtualMachines: { slug: 'servers', label: 'Defender for Servers' },
  AppServices: { slug: 'appservices', label: 'Defender for App Service' },
  SqlServers: { slug: 'sqlservers', label: 'Defender for Azure SQL Databases' },
  SqlServerVirtualMachines: { slug: 'sqlservervms', label: 'Defender for SQL servers on machines' },
  StorageAccounts: { slug: 'storage', label: 'Defender for Storage' },
  Containers: { slug: 'containers', label: 'Defender for Containers' },
  KeyVaults: { slug: 'keyvaults', label: 'Defender for Key Vault' },
  Arm: { slug: 'arm', label: 'Defender for Resource Manager' },
};

// ─── Subscription-level posture ─────────────────────────────────────────

async function runSubscriptionChecks(subscriptionId, accessToken, reporter, log) {
  const sub = `/subscriptions/${subscriptionId}`;

  try {
    const plans = await securityApi.listDefenderPlans(subscriptionId, accessToken);
    log(`  [azure:security] ${plans.length} Defender for Cloud plan(s) found`);
    for (const plan of plans) {
      const info = DEFENDER_PLANS[plan.name];
      if (!info || plan.tier === 'Standard') continue;
      reporter.add({
        provider: 'azure',
        service: 'security',
        check: `azure-defender-${info.slug}-not-enabled`,
        severity: 'medium',
        action: 'azure-defender-enable-plan',
        title: `${info.label} is not turned on`,
        resource: `${subscriptionId} / ${plan.name}`,
        description: `The Defender for Cloud plan "${plan.name}" is on the Free tier, so the threat detection, vulnerability assessment and alerting it provides for this resource type is not active. (This is a paid plan; turning it on has a cost.)`,
        remediation: `az security pricing create --name ${plan.name} --tier Standard`,
      });
    }
  } catch (err) {
    log(`  [azure:security] Defender plans failed: ${err.message}`);
  }

  try {
    const contacts = await securityApi.listSecurityContacts(subscriptionId, accessToken);
    if (!contacts.some((c) => c.emails.length > 0)) {
      reporter.add({
        provider: 'azure',
        service: 'security',
        check: 'azure-security-contact-missing',
        severity: 'low',
        action: 'azure-security-set-contact',
        title: 'No security contact email is set for Defender for Cloud alerts',
        resource: subscriptionId,
        description: 'Defender for Cloud has nobody to email about high-severity alerts, so a detected compromise can sit unseen in the portal.',
        remediation: 'az security contact create --name default --email <security-team@example.com> --alert-notifications on --alerts-admins on',
      });
    }
  } catch (err) {
    log(`  [azure:security] security contacts failed: ${err.message}`);
  }

  try {
    const diag = await monitorApi.listDiagnosticSettings(sub, accessToken);
    if (diag.length === 0) {
      reporter.add({
        provider: 'azure',
        service: 'monitor',
        check: 'azure-activity-log-no-diagnostic-setting',
        severity: 'medium',
        action: 'azure-activity-log-export',
        title: 'The subscription Activity Log is not exported anywhere',
        resource: subscriptionId,
        description: 'The Activity Log (who created, changed or deleted which resource) is only kept for 90 days in the portal. With no diagnostic setting, it cannot be retained longer, alerted on, or protected from tampering.',
        remediation: `az monitor diagnostic-settings subscription create --name activity-log --subscription ${subscriptionId} --location global --logs '[{"category":"Administrative","enabled":true},{"category":"Security","enabled":true},{"category":"Policy","enabled":true}]' --workspace <log-analytics-workspace-id>`,
      });
    }
  } catch (err) {
    log(`  [azure:monitor] Activity Log diagnostic settings failed: ${err.message}`);
  }

  try {
    const owners = await authApi.listSubscriptionOwners(subscriptionId, accessToken);
    log(`  [azure:authorization] ${owners.length} subscription-level Owner assignment(s)`);
    if (owners.length > 3) {
      reporter.add({
        provider: 'azure',
        service: 'authorization',
        check: 'azure-subscription-too-many-owners',
        severity: 'low',
        action: 'azure-reduce-owner-assignments',
        title: `Subscription has ${owners.length} Owner role assignments`,
        resource: subscriptionId,
        description: `${owners.length} identities hold Owner directly on the subscription. Owners can grant access to anyone, change every resource and delete the audit trail; the more of them there are, the more accounts an attacker can use to get that power.`,
        remediation: `Review: az role assignment list --scope /subscriptions/${subscriptionId} --role Owner, and replace Owner with narrower roles (Contributor, or a purpose-built role) wherever role management isn't actually needed.`,
      });
    }
  } catch (err) {
    log(`  [azure:authorization] Owner assignments failed: ${err.message}`);
  }

  try {
    const roles = await authApi.listCustomRoles(subscriptionId, accessToken);
    log(`  [azure:authorization] ${roles.length} custom role(s)`);
    for (const role of roles) {
      if (!role.actions.includes('*')) continue;
      reporter.add({
        provider: 'azure',
        service: 'authorization',
        check: 'azure-custom-role-wildcard',
        severity: 'high',
        action: 'azure-custom-role-reduce-permissions',
        title: 'Custom role grants every action ("*")',
        resource: role.name,
        description: `Custom role "${role.name}" has "*" among its allowed actions (assignable at ${role.assignableScopes.join(', ') || 'unknown scopes'}), which is the equivalent of Owner under a name that reviewers won't recognise as Owner.`,
        remediation: `Replace "*" with the specific actions the role needs: az role definition update --role-definition role.json (or delete the role if it's not used).`,
      });
    }
  } catch (err) {
    log(`  [azure:authorization] custom roles failed: ${err.message}`);
  }
}

// ─── Managed disks ──────────────────────────────────────────────────────

async function runDiskChecks(subscriptionId, accessToken, reporter, log) {
  let disks;
  try {
    disks = await computeApi.listDisks(subscriptionId, accessToken);
  } catch (err) {
    log(`  [azure:compute] list disks failed: ${err.message}`);
    return;
  }
  log(`  [azure:compute] ${disks.length} managed disk(s) found`);
  for (const d of disks) {
    if (d.attached || d.diskState !== 'Unattached') continue;
    reporter.add({
      provider: 'azure',
      service: 'compute',
      check: 'azure-disk-unattached',
      severity: 'low',
      action: 'azure-disk-review-unattached',
      title: 'Managed disk is not attached to any VM',
      resource: d.name,
      region: d.location,
      description: `Disk "${d.name}" (${d.sizeGb} GiB) is not attached to a VM. It's still billed, and an orphaned disk (left behind by a deleted VM) can hold data nobody is responsible for protecting anymore.`,
      remediation: `If it's no longer needed: az disk delete --name ${d.name} --resource-group <rg>. If it must be kept, tag it with an owner.`,
    });
  }
}

// ─── PostgreSQL / MySQL flexible servers ────────────────────────────────

async function runFlexibleServerChecks(kind, subscriptionId, accessToken, reporter, log) {
  const label = dbApi.KINDS[kind].label;
  let servers;
  try {
    servers = await dbApi.listFlexibleServers(kind, subscriptionId, accessToken);
  } catch (err) {
    log(`  [azure:${kind}] list failed: ${err.message}`);
    return;
  }
  log(`  [azure:${kind}] ${servers.length} ${label} flexible server(s) found`);

  await mapLimit(servers, CONCURRENCY, async (server) => {
    if (!server.privateOnly) {
      try {
        const rules = await dbApi.listFirewallRules(kind, server.id, accessToken);
        const open = rules.find((r) => r.startIpAddress === '0.0.0.0' && r.endIpAddress === '255.255.255.255');
        if (open) {
          reporter.add({
            provider: 'azure',
            service: kind,
            check: `azure-${kind}-firewall-allow-all`,
            severity: 'critical',
            action: 'azure-db-remove-firewall-rule',
            title: `${label} server firewall allows every IP address on the internet`,
            resource: server.name,
            region: server.location,
            description: `Firewall rule "${open.name}" spans 0.0.0.0-255.255.255.255 on a server with a public endpoint, so the database port is reachable from anywhere (only credentials stand in the way).`,
            remediation: `az ${kind} flexible-server firewall-rule delete --resource-group <rg> --name ${server.name} --rule-name ${open.name} --yes`,
          });
        }
      } catch (err) {
        log(`  [azure:${kind}] ${server.name}: firewall rules failed: ${err.message}`);
      }
    }
    try {
      const secure = await dbApi.getRequireSecureTransport(kind, server.id, accessToken);
      if (!secure) {
        reporter.add({
          provider: 'azure',
          service: kind,
          check: `azure-${kind}-ssl-not-required`,
          severity: 'medium',
          action: 'azure-db-require-secure-transport',
          title: `${label} server accepts unencrypted connections`,
          resource: server.name,
          region: server.location,
          description: `require_secure_transport is OFF on server "${server.name}", so clients can connect (and send credentials and data) without TLS.`,
          remediation: `az ${kind} flexible-server parameter set --resource-group <rg> --server-name ${server.name} --name require_secure_transport --value on`,
        });
      }
    } catch (err) {
      log(`  [azure:${kind}] ${server.name}: require_secure_transport read failed: ${err.message}`);
    }
  });
}

// ─── Cosmos DB ──────────────────────────────────────────────────────────

async function runCosmosChecks(subscriptionId, accessToken, reporter, log) {
  let accounts;
  try {
    accounts = await cosmosApi.listAccounts(subscriptionId, accessToken);
  } catch (err) {
    log(`  [azure:cosmosdb] list failed: ${err.message}`);
    return;
  }
  log(`  [azure:cosmosdb] ${accounts.length} account(s) found`);
  for (const a of accounts) {
    if (a.publicNetworkAccess !== 'Disabled' && !a.vnetFilterEnabled && a.ipRuleCount === 0) {
      reporter.add({
        provider: 'azure',
        service: 'cosmosdb',
        check: 'azure-cosmosdb-public-network-open',
        severity: 'high',
        action: 'azure-cosmosdb-restrict-network',
        title: 'Cosmos DB account is reachable from any network',
        resource: a.name,
        region: a.location,
        description: `Account "${a.name}" allows public network access with no virtual-network filter and no IP rules, so its endpoint accepts connections from the whole internet (the account key or an Entra token is still required).`,
        remediation: `az cosmosdb update --name ${a.name} --resource-group <rg> --public-network-access DISABLED (use a private endpoint), or add --ip-range-filter / --enable-virtual-network with --virtual-network-rules`,
      });
    }
    if (a.localAuthEnabled) {
      reporter.add({
        provider: 'azure',
        service: 'cosmosdb',
        check: 'azure-cosmosdb-local-auth-enabled',
        severity: 'low',
        action: 'azure-cosmosdb-disable-local-auth',
        title: 'Cosmos DB account allows key-based (local) authentication',
        resource: a.name,
        region: a.location,
        description: `Account "${a.name}" still accepts the shared account keys, which are all-powerful, long-lived and can't be attributed to a person, instead of requiring Entra ID RBAC.`,
        remediation: `az resource update --ids ${a.id} --set properties.disableLocalAuth=true`,
      });
    }
  }
}

// ─── Azure Cache for Redis ──────────────────────────────────────────────

async function runRedisChecks(subscriptionId, accessToken, reporter, log) {
  let caches;
  try {
    caches = await redisApi.listCaches(subscriptionId, accessToken);
  } catch (err) {
    log(`  [azure:redis] list failed: ${err.message}`);
    return;
  }
  log(`  [azure:redis] ${caches.length} cache(s) found`);
  for (const c of caches) {
    if (c.nonSslPortEnabled) {
      reporter.add({
        provider: 'azure',
        service: 'redis',
        check: 'azure-redis-non-ssl-port-enabled',
        severity: 'medium',
        action: 'azure-redis-disable-non-ssl-port',
        title: 'Redis cache accepts unencrypted connections on port 6379',
        resource: c.name,
        region: c.location,
        description: `Cache "${c.name}" has the non-TLS port enabled, so clients can connect and send the access key and data in clear text.`,
        remediation: `az redis update --name ${c.name} --resource-group <rg> --set enableNonSslPort=false`,
      });
    }
    if (c.minimumTlsVersion === '' || c.minimumTlsVersion === '1.0' || c.minimumTlsVersion === '1.1') {
      reporter.add({
        provider: 'azure',
        service: 'redis',
        check: 'azure-redis-outdated-tls',
        severity: 'medium',
        action: 'azure-redis-upgrade-tls',
        title: `Redis cache accepts outdated TLS (minimum: ${c.minimumTlsVersion || 'not set'})`,
        resource: c.name,
        region: c.location,
        description: `Cache "${c.name}" does not require TLS 1.2 or newer, so clients can negotiate TLS 1.0/1.1, which have known weaknesses.`,
        remediation: `az redis update --name ${c.name} --resource-group <rg> --set minimumTlsVersion=1.2`,
      });
    }
  }
}

async function runAzureExtendedChecks({ subscriptionId, accessToken }, reporter, log = () => {}) {
  await runSubscriptionChecks(subscriptionId, accessToken, reporter, log);
  await runDiskChecks(subscriptionId, accessToken, reporter, log);
  await runFlexibleServerChecks('postgres', subscriptionId, accessToken, reporter, log);
  await runFlexibleServerChecks('mysql', subscriptionId, accessToken, reporter, log);
  await runCosmosChecks(subscriptionId, accessToken, reporter, log);
  await runRedisChecks(subscriptionId, accessToken, reporter, log);
}

export { runAzureExtendedChecks, DEFENDER_PLANS };
