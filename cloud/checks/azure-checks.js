'use strict';
import * as storageApi from '../providers/azure/storage.js';
import * as networkApi from '../providers/azure/network.js';
import * as sqlApi from '../providers/azure/sql.js';
import * as keyvaultApi from '../providers/azure/keyvault.js';
import * as appServiceApi from '../providers/azure/appservice.js';
import * as acrApi from '../providers/azure/acr.js';
import * as aksApi from '../providers/azure/aks.js';
import * as monitorApi from '../providers/azure/monitor.js';
import { mapLimit } from '../lib/concurrency.js';
import { runAzureExtendedChecks } from './azure-extended-checks.js';

const SENSITIVE_PORTS = {
  22: 'SSH',
  3389: 'RDP',
  1433: 'MSSQL',
  3306: 'MySQL',
  5432: 'PostgreSQL',
  6379: 'Redis',
};
const PUBLIC_SOURCES = new Set(['*', 'Internet', '0.0.0.0/0', 'Any']);
// A /12 (~1M addresses) is generously sized so a real corporate VPN range
// doesn't trip this — see runSqlChecks below for why this is now
// informational rather than a hard "high" (item 6).
const BROAD_RANGE_THRESHOLD = 1048576;
const CONCURRENCY = 8;

function ipToInt(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p))) return null;
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

function destinationTouchesPort(rule, port) {
  const ranges = rule.destinationPortRange ? [rule.destinationPortRange] : rule.destinationPortRanges;
  for (const spec of ranges || []) {
    if (spec === '*') return true;
    const [lo, hi] = spec.includes('-') ? spec.split('-').map(Number) : [Number(spec), Number(spec)];
    if (!Number.isNaN(lo) && !Number.isNaN(hi) && port >= lo && port <= hi) return true;
  }
  return false;
}

function isPublicSource(rule) {
  const sources = rule.sourceAddressPrefix ? [rule.sourceAddressPrefix] : rule.sourceAddressPrefixes;
  return (sources || []).some((s) => PUBLIC_SOURCES.has(s));
}

async function runStorageChecks(subscriptionId, accessToken, reporter, log) {
  let accounts;
  try {
    accounts = await storageApi.listStorageAccounts(subscriptionId, accessToken);
  } catch (err) {
    log(`  [azure:storage] list failed: ${err.message}`);
    return;
  }
  log(`  [azure:storage] ${accounts.length} storage account(s) found`);

  await mapLimit(accounts, CONCURRENCY, async (acc) => {
    if (acc.allowBlobPublicAccess) {
      reporter.add({
        provider: 'azure',
        service: 'storage',
        check: 'azure-storage-public-blob-access',
        severity: 'high',
        action: 'azure-storage-disable-public-blob-access',
        title: 'Storage account permits public blob access',
        resource: acc.name,
        region: acc.location,
        description: 'AllowBlobPublicAccess is enabled at the account level, meaning any container inside it can be made publicly readable.',
        remediation: `az storage account update --name ${acc.name} --allow-blob-public-access false`,
      });
    }
    if (!acc.supportsHttpsTrafficOnly) {
      reporter.add({
        provider: 'azure',
        service: 'storage',
        check: 'azure-storage-http-allowed',
        severity: 'medium',
        action: 'azure-storage-require-https',
        title: 'Storage account allows unencrypted HTTP traffic',
        resource: acc.name,
        region: acc.location,
        description: 'SupportsHttpsTrafficOnly is disabled, so data in transit is not guaranteed to be encrypted.',
        remediation: `az storage account update --name ${acc.name} --https-only true`,
      });
    }
    if (acc.networkDefaultAction === 'Allow' && acc.publicNetworkAccess !== 'Disabled') {
      reporter.add({
        provider: 'azure',
        service: 'storage',
        check: 'azure-storage-network-default-allow',
        severity: 'medium',
        action: 'azure-storage-default-deny-network',
        title: 'Storage account accepts connections from all networks',
        resource: acc.name,
        region: acc.location,
        description: 'The storage firewall default action is Allow, so the account endpoint answers requests from any network on the internet (authentication is still required unless a container is public, but nothing limits where requests come from).',
        remediation: `az storage account update --name ${acc.name} --default-action Deny, then add the networks that need access: az storage account network-rule add ...`,
      });
    }
    try {
      const blob = await storageApi.getBlobServiceProperties(acc.id, accessToken);
      const missing = [!blob.blobSoftDeleteEnabled && 'blobs', !blob.containerSoftDeleteEnabled && 'containers'].filter(Boolean);
      if (missing.length > 0) {
        reporter.add({
          provider: 'azure',
          service: 'storage',
          check: 'azure-storage-soft-delete-disabled',
          severity: 'low',
          action: 'azure-storage-enable-soft-delete',
          title: `Storage account has soft delete turned off for ${missing.join(' and ')}`,
          resource: acc.name,
          region: acc.location,
          description: `Without soft delete for ${missing.join(' and ')}, a deleted or overwritten item (by mistake or by an attacker) is gone immediately and cannot be recovered.`,
          remediation: `az storage account blob-service-properties update --account-name ${acc.name} --enable-delete-retention true --delete-retention-days 7 --enable-container-delete-retention true --container-delete-retention-days 7`,
        });
      }
    } catch (err) {
      log(`  [azure:storage] ${acc.name}: blob service properties failed: ${err.message}`);
    }
    if (acc.minimumTlsVersion !== 'TLS1_2') {
      reporter.add({
        provider: 'azure',
        service: 'storage',
        check: 'azure-storage-outdated-tls',
        severity: 'low',
        action: 'azure-storage-upgrade-tls',
        title: `Storage account allows outdated TLS (minimum: ${acc.minimumTlsVersion})`,
        resource: acc.name,
        region: acc.location,
        description: 'Older TLS versions have known weaknesses and should not be accepted.',
        remediation: `az storage account update --name ${acc.name} --min-tls-version TLS1_2`,
      });
    }

    // item 6: only the account-level allowBlobPublicAccess flag was
    // checked before — a container can be individually set to allow
    // anonymous read regardless of that flag's *current* value (it only
    // gates whether such a container setting is allowed to exist).
    try {
      const containers = await storageApi.listContainers(acc.id, accessToken);
      for (const c of containers) {
        if (c.publicAccess === 'None') continue;
        reporter.add({
          provider: 'azure',
          service: 'storage',
          check: 'azure-storage-container-public-access',
          severity: c.publicAccess === 'Container' ? 'critical' : 'high',
          action: 'azure-storage-container-restrict-access',
          title: `Storage container allows anonymous ${c.publicAccess === 'Container' ? 'read + list' : 'read'} access`,
          resource: `${acc.name} / ${c.name}`,
          region: acc.location,
          description: `Container "${c.name}" has PublicAccess="${c.publicAccess}" — anyone with the URL (or, for "Container", anyone who lists the container) can read its blobs.`,
          remediation: `az storage container set-permission --name ${c.name} --account-name ${acc.name} --public-access off`,
        });
      }
    } catch (err) {
      log(`  [azure:storage] ${acc.name}: listContainers failed: ${err.message}`);
    }
  });
}

async function runNsgChecks(subscriptionId, accessToken, reporter, log) {
  let nsgs;
  try {
    nsgs = await networkApi.listNsgs(subscriptionId, accessToken);
  } catch (err) {
    log(`  [azure:network] list failed: ${err.message}`);
    return;
  }
  log(`  [azure:network] ${nsgs.length} NSG(s) found`);

  for (const nsg of nsgs) {
    // item 6: an NSG with open rules that isn't attached to any subnet or
    // NIC can't actually expose anything — flagging every rule on it as
    // high/critical was a pure false positive. Report it once, as
    // low-severity housekeeping, instead of skipping it silently (an
    // orphaned NSG is still worth cleaning up, just not an active risk).
    const isAssociated = nsg.associatedSubnetIds.length > 0 || nsg.associatedNetworkInterfaceIds.length > 0;
    if (!isAssociated) {
      const hasOpenRule = nsg.securityRules.some(
        (r) => r.direction === 'Inbound' && r.access === 'Allow' && isPublicSource(r)
      );
      if (hasOpenRule) {
        reporter.add({
          provider: 'azure',
          service: 'network',
          check: 'azure-nsg-unassociated-with-open-rule',
          severity: 'low',
          action: 'azure-nsg-cleanup-orphaned',
          title: 'Unattached NSG has open inbound rule(s)',
          resource: nsg.name,
          region: nsg.location,
          description: `NSG "${nsg.name}" has one or more rules open to the internet but is not associated with any subnet or network interface, so it isn't currently enforcing anything either way.`,
          remediation: `Delete it if unused (az network nsg delete --name ${nsg.name}), or attach it to the intended subnet/NIC and re-scan.`,
        });
      }
      continue;
    }

    for (const rule of nsg.securityRules) {
      if (rule.direction !== 'Inbound' || rule.access !== 'Allow') continue;
      if (!isPublicSource(rule)) continue;

      const allPorts =
        rule.destinationPortRange === '*' || (rule.destinationPortRanges || []).includes('*');
      if (allPorts) {
        reporter.add({
          provider: 'azure',
          service: 'network',
          check: 'azure-nsg-open-all-ports',
          severity: 'critical',
          action: 'azure-nsg-restrict-source',
          title: 'NSG rule allows ALL inbound ports from the internet',
          resource: `${nsg.name} / ${rule.name}`,
          region: nsg.location,
          description: `Rule "${rule.name}" allows ${rule.protocol} from a public source to all destination ports.`,
          remediation: `az network nsg rule update --nsg-name ${nsg.name} --name ${rule.name} --source-address-prefixes <restricted-cidr>`,
        });
        continue;
      }

      const hitPorts = Object.keys(SENSITIVE_PORTS)
        .map(Number)
        .filter((p) => destinationTouchesPort(rule, p));
      if (hitPorts.length > 0) {
        for (const port of hitPorts) {
          reporter.add({
            provider: 'azure',
            service: 'network',
            check: 'azure-nsg-open-sensitive-port',
            severity: 'high',
            action: 'azure-nsg-restrict-source',
            title: `NSG rule exposes ${SENSITIVE_PORTS[port]} (port ${port}) to the internet`,
            resource: `${nsg.name} / ${rule.name}`,
            region: nsg.location,
            description: `Rule "${rule.name}" allows ${rule.protocol} port ${port} from a public source.`,
            remediation: `az network nsg rule update --nsg-name ${nsg.name} --name ${rule.name} --source-address-prefixes <restricted-cidr>`,
          });
        }
      } else {
        reporter.add({
          provider: 'azure',
          service: 'network',
          check: 'azure-nsg-open-ingress',
          severity: 'medium',
          action: 'azure-nsg-restrict-source',
          title: 'NSG rule allows inbound access from the internet',
          resource: `${nsg.name} / ${rule.name}`,
          region: nsg.location,
          description: `Rule "${rule.name}" allows ${rule.protocol} to port(s) ${rule.destinationPortRange || (rule.destinationPortRanges || []).join(',')} from a public source.`,
          remediation: 'Narrow the source address prefix to only what needs this access.',
        });
      }
    }
  }
}

async function runSqlChecks(subscriptionId, accessToken, reporter, log) {
  let servers;
  try {
    servers = await sqlApi.listSqlServers(subscriptionId, accessToken);
  } catch (err) {
    log(`  [azure:sql] list failed: ${err.message}`);
    return;
  }
  log(`  [azure:sql] ${servers.length} SQL server(s) found`);

  await mapLimit(servers, CONCURRENCY, async (server) => {
    if (server.minimalTlsVersion === '' || server.minimalTlsVersion === '1.0' || server.minimalTlsVersion === '1.1') {
      reporter.add({
        provider: 'azure',
        service: 'sql',
        check: 'azure-sql-outdated-tls',
        severity: 'medium',
        action: 'azure-sql-upgrade-tls',
        title: `SQL server accepts outdated TLS (minimum: ${server.minimalTlsVersion || 'not set'})`,
        resource: server.name,
        region: server.location,
        description: 'The server does not require TLS 1.2 or newer, so clients can still negotiate TLS 1.0/1.1, which have known weaknesses.',
        remediation: `az sql server update --name ${server.name} --resource-group <rg> --minimal-tls-version 1.2`,
      });
    }
    try {
      const auditing = await sqlApi.getAuditingState(server.id, accessToken);
      if (auditing !== 'Enabled') {
        reporter.add({
          provider: 'azure',
          service: 'sql',
          check: 'azure-sql-auditing-disabled',
          severity: 'medium',
          action: 'azure-sql-enable-auditing',
          title: 'SQL server auditing is turned off',
          resource: server.name,
          region: server.location,
          description: `Auditing on server "${server.name}" is "${auditing}", so database events (logins, queries that change data, permission changes) are not being recorded anywhere.`,
          remediation: `az sql server audit-policy update --name ${server.name} --resource-group <rg> --state Enabled --blob-storage-target-state Enabled --storage-account <account>`,
        });
      }
    } catch (err) {
      log(`  [azure:sql] ${server.name}: auditing settings failed: ${err.message}`);
    }
    try {
      const atp = await sqlApi.getThreatProtectionState(server.id, accessToken);
      if (atp !== 'Enabled') {
        reporter.add({
          provider: 'azure',
          service: 'sql',
          check: 'azure-sql-threat-protection-disabled',
          severity: 'medium',
          action: 'azure-sql-enable-threat-protection',
          title: 'SQL server does not have Microsoft Defender for SQL (threat protection) enabled',
          resource: server.name,
          region: server.location,
          description: `Server "${server.name}" has its security alert policy in state "${atp}", so SQL injection attempts, anomalous logins and unusual data access are not detected or alerted on.`,
          remediation: `az sql server advanced-threat-protection-setting update --resource-group <rg> --server ${server.name} --state Enabled`,
        });
      }
    } catch (err) {
      log(`  [azure:sql] ${server.name}: threat protection policy failed: ${err.message}`);
    }
    try {
      const rules = await sqlApi.listFirewallRules(server.id, accessToken);
      for (const rule of rules) {
        if (rule.startIpAddress === '0.0.0.0' && rule.endIpAddress === '0.0.0.0') continue; // "Allow Azure services" marker rule
        const lo = ipToInt(rule.startIpAddress);
        const hi = ipToInt(rule.endIpAddress);
        if (lo === null || hi === null) continue;
        const rangeSize = hi - lo + 1;

        if (rule.startIpAddress === '0.0.0.0' && rule.endIpAddress === '255.255.255.255') {
          reporter.add({
            provider: 'azure',
            service: 'sql',
            check: 'azure-sql-firewall-allow-all',
            severity: 'critical',
            action: 'azure-sql-remove-firewall-rule',
            title: 'SQL server firewall allows every IP address on the internet',
            resource: server.name,
            region: server.location,
            description: `Firewall rule "${rule.name}" spans 0.0.0.0-255.255.255.255.`,
            remediation: `az sql server firewall-rule delete --server ${server.name} --name ${rule.name}`,
          });
        } else if (rangeSize > BROAD_RANGE_THRESHOLD) {
          // item 6: this used to be a flat "high" at a much smaller
          // (65,536-address) threshold, which flagged plenty of
          // legitimate large-but-bounded ranges (a corporate VPN or
          // office CIDR block, say). It's now informational-severity and
          // says as much, rather than asserting the range is wrong.
          reporter.add({
            provider: 'azure',
            service: 'sql',
            check: 'azure-sql-firewall-broad-range',
            severity: 'low',
            action: 'azure-sql-narrow-firewall-rule',
            title: 'SQL server firewall rule allows an unusually broad IP range',
            resource: server.name,
            region: server.location,
            description: `Firewall rule "${rule.name}" spans ${rule.startIpAddress}-${rule.endIpAddress} (${rangeSize.toLocaleString()} addresses). This may be intentional (e.g. a corporate VPN range) — worth a manual look rather than an automatic fix.`,
            remediation: `If unintentional, narrow it: az sql server firewall-rule update --server ${server.name} --name ${rule.name} --start-ip-address <ip> --end-ip-address <ip>`,
          });
        }
      }
    } catch (err) {
      log(`  [azure:sql] ${server.name}: ${err.message}`);
    }
  });
}

/** item 5: Key Vault had no check before -- public network access and
 * purge protection are two of the most commonly-audited Key Vault
 * settings in a real cloud security review. */
async function runKeyVaultChecks(subscriptionId, accessToken, reporter, log) {
  let vaults;
  try {
    vaults = await keyvaultApi.listVaults(subscriptionId, accessToken);
  } catch (err) {
    log(`  [azure:keyvault] list failed: ${err.message}`);
    return;
  }
  log(`  [azure:keyvault] ${vaults.length} key vault(s) found`);

  for (const vault of vaults) {
    const networkRestricted = vault.publicNetworkAccess === 'Disabled' || vault.networkAclsDefaultAction === 'Deny';
    if (!networkRestricted) {
      reporter.add({
        provider: 'azure',
        service: 'keyvault',
        check: 'azure-keyvault-public-network-access',
        severity: 'high',
        action: 'azure-keyvault-restrict-network-access',
        title: 'Key Vault is reachable from any public network',
        resource: vault.name,
        region: vault.location,
        description: `Vault "${vault.name}" has publicNetworkAccess="${vault.publicNetworkAccess}" and a network ACL default action of "${vault.networkAclsDefaultAction}" — secrets, keys, and certificates can be requested from any network unless access is otherwise restricted (e.g. by Azure AD conditional access).`,
        remediation: `az keyvault update --name ${vault.name} --public-network-access Disabled (or az keyvault network-rule add ... plus --default-action Deny to allow specific networks only)`,
      });
    }
    if (!vault.rbacAuthorization) {
      reporter.add({
        provider: 'azure',
        service: 'keyvault',
        check: 'azure-keyvault-rbac-disabled',
        severity: 'low',
        action: 'azure-keyvault-enable-rbac',
        title: 'Key Vault uses legacy access policies instead of Azure RBAC',
        resource: vault.name,
        region: vault.location,
        description: `Vault "${vault.name}" authorizes with vault access policies, which are managed separately from the rest of Azure access control, can't be scoped to individual secrets, and don't support Privileged Identity Management or conditional access.`,
        remediation: `az keyvault update --name ${vault.name} --enable-rbac-authorization true (first recreate the needed access as role assignments so nothing loses access)`,
      });
    }
    try {
      const diag = await monitorApi.listDiagnosticSettings(vault.id, accessToken);
      if (diag.length === 0) {
        reporter.add({
          provider: 'azure',
          service: 'keyvault',
          check: 'azure-keyvault-no-diagnostic-logging',
          severity: 'low',
          action: 'azure-keyvault-enable-diagnostic-logging',
          title: 'Key Vault has no diagnostic logging',
          resource: vault.name,
          region: vault.location,
          description: `Vault "${vault.name}" has no diagnostic setting, so there is no record of who read, changed or deleted its secrets, keys and certificates.`,
          remediation: `az monitor diagnostic-settings create --name kv-audit --resource ${vault.id} --logs '[{"category":"AuditEvent","enabled":true}]' --workspace <log-analytics-workspace-id>`,
        });
      }
    } catch (err) {
      log(`  [azure:keyvault] ${vault.name}: diagnostic settings failed: ${err.message}`);
    }
    if (!vault.purgeProtectionEnabled) {
      reporter.add({
        provider: 'azure',
        service: 'keyvault',
        check: 'azure-keyvault-purge-protection-disabled',
        severity: 'medium',
        action: 'azure-keyvault-enable-purge-protection',
        title: 'Key Vault does not have purge protection enabled',
        resource: vault.name,
        region: vault.location,
        description: `Vault "${vault.name}" has purge protection off, so a deleted vault (or its secrets/keys) can be permanently purged immediately instead of waiting out the soft-delete retention period — a compromised owner/contributor can destroy key material irrecoverably.`,
        remediation: `az keyvault update --name ${vault.name} --enable-purge-protection true (this is irreversible once enabled — the vault can no longer be purged before its retention period).`,
      });
    }
  }
}

/** item 5: App Service / Function App httpsOnly had no check before. */
async function runAppServiceChecks(subscriptionId, accessToken, reporter, log) {
  let sites;
  try {
    sites = await appServiceApi.listSites(subscriptionId, accessToken);
  } catch (err) {
    log(`  [azure:appservice] list failed: ${err.message}`);
    return;
  }
  log(`  [azure:appservice] ${sites.length} site(s) found`);

  for (const site of sites) {
    try {
      const cfg = await appServiceApi.getSiteConfig(site.id, accessToken);
      const isFn = site.kind.includes('functionapp');
      const label = isFn ? 'Function App' : 'App Service';
      const cliGroup = isFn ? 'functionapp' : 'webapp';
      if (cfg.minTlsVersion === '1.0' || cfg.minTlsVersion === '1.1') {
        reporter.add({
          provider: 'azure',
          service: 'appservice',
          check: 'azure-appservice-outdated-tls',
          severity: 'medium',
          action: 'azure-appservice-upgrade-tls',
          title: `${label} accepts outdated TLS (minimum: ${cfg.minTlsVersion})`,
          resource: site.name,
          region: site.location,
          description: `Site "${site.name}" allows clients to negotiate TLS ${cfg.minTlsVersion}, which has known weaknesses.`,
          remediation: `az ${cliGroup} config set --name ${site.name} --resource-group <rg> --min-tls-version 1.2`,
        });
      }
      if (cfg.ftpsState === 'AllAllowed') {
        reporter.add({
          provider: 'azure',
          service: 'appservice',
          check: 'azure-appservice-ftp-allowed',
          severity: 'medium',
          action: 'azure-appservice-require-ftps',
          title: `${label} accepts unencrypted FTP deployments`,
          resource: site.name,
          region: site.location,
          description: `Site "${site.name}" has FTPS state "AllAllowed", so deployment credentials and site content can cross the network in clear text over plain FTP.`,
          remediation: `az ${cliGroup} config set --name ${site.name} --resource-group <rg> --ftps-state FtpsOnly (or Disabled if FTP isn't used)`,
        });
      }
      if (cfg.remoteDebuggingEnabled) {
        reporter.add({
          provider: 'azure',
          service: 'appservice',
          check: 'azure-appservice-remote-debugging-enabled',
          severity: 'medium',
          action: 'azure-appservice-disable-remote-debugging',
          title: `${label} has remote debugging enabled`,
          resource: site.name,
          region: site.location,
          description: `Site "${site.name}" has remote debugging switched on, which opens extra inbound ports on the app and lets anyone with deployment credentials attach a debugger to production code.`,
          remediation: `az ${cliGroup} config set --name ${site.name} --resource-group <rg> --remote-debugging-enabled false`,
        });
      }
    } catch (err) {
      log(`  [azure:appservice] ${site.name}: site config failed: ${err.message}`);
    }
    if (!site.httpsOnly) {
      const isFunctionApp = site.kind.includes('functionapp');
      reporter.add({
        provider: 'azure',
        service: 'appservice',
        check: 'azure-appservice-https-only-disabled',
        severity: 'medium',
        action: 'azure-appservice-enable-https-only',
        title: `${isFunctionApp ? 'Function App' : 'App Service'} allows unencrypted HTTP traffic`,
        resource: site.name,
        region: site.location,
        description: `Site "${site.name}" has httpsOnly=false, so plain HTTP requests to it are not redirected to HTTPS or rejected.`,
        remediation: `az webapp update --name ${site.name} --https-only true (az functionapp update --name ${site.name} --set httpsOnly=true for a Function App)`,
      });
    }
  }
}

/** item 5: Container Registry admin user / public access had no check
 * before. */
async function runAcrChecks(subscriptionId, accessToken, reporter, log) {
  let registries;
  try {
    registries = await acrApi.listRegistries(subscriptionId, accessToken);
  } catch (err) {
    log(`  [azure:acr] list failed: ${err.message}`);
    return;
  }
  log(`  [azure:acr] ${registries.length} container registr${registries.length === 1 ? 'y' : 'ies'} found`);

  for (const reg of registries) {
    if (reg.adminUserEnabled) {
      reporter.add({
        provider: 'azure',
        service: 'acr',
        check: 'azure-acr-admin-user-enabled',
        severity: 'medium',
        action: 'azure-acr-disable-admin-user',
        title: 'Container Registry admin user is enabled',
        resource: reg.name,
        region: reg.location,
        description: `Registry "${reg.name}" has the admin user enabled — a single shared, non-attributable credential that can pull/push any image, instead of per-identity access via Azure AD/RBAC.`,
        remediation: `az acr update --name ${reg.name} --admin-enabled false`,
      });
    }
    if (reg.anonymousPullEnabled) {
      reporter.add({
        provider: 'azure',
        service: 'acr',
        check: 'azure-acr-anonymous-pull',
        severity: 'high',
        action: 'azure-acr-disable-anonymous-pull',
        title: 'Container Registry allows anonymous image pulls',
        resource: reg.name,
        region: reg.location,
        description: `Registry "${reg.name}" has anonymousPullEnabled=true, so anyone who can reach it can pull every image in it without credentials -- including application code and anything baked into the images.`,
        remediation: `az acr update --name ${reg.name} --anonymous-pull-enabled false`,
      });
    }
    if (reg.publicNetworkAccess !== 'Disabled') {
      reporter.add({
        provider: 'azure',
        service: 'acr',
        check: 'azure-acr-public-network-access',
        severity: 'low',
        action: 'azure-acr-restrict-network-access',
        title: 'Container Registry is reachable from any public network',
        resource: reg.name,
        region: reg.location,
        description: `Registry "${reg.name}" has publicNetworkAccess="${reg.publicNetworkAccess}". Combined with the admin user (or a leaked Azure AD token), this is reachable from anywhere on the internet.`,
        remediation: `az acr update --name ${reg.name} --public-network-enabled false (requires Premium SKU; use private endpoints for network access instead).`,
      });
    }
  }
}

/** item 5: AKS local accounts / RBAC had no check before. */
async function runAksChecks(subscriptionId, accessToken, reporter, log) {
  let clusters;
  try {
    clusters = await aksApi.listClusters(subscriptionId, accessToken);
  } catch (err) {
    log(`  [azure:aks] list failed: ${err.message}`);
    return;
  }
  log(`  [azure:aks] ${clusters.length} cluster(s) found`);

  for (const cluster of clusters) {
    if (!cluster.rbacEnabled) {
      reporter.add({
        provider: 'azure',
        service: 'aks',
        check: 'azure-aks-rbac-disabled',
        severity: 'high',
        action: 'azure-aks-enable-rbac',
        title: 'AKS cluster has Kubernetes RBAC disabled',
        resource: cluster.name,
        region: cluster.location,
        description: `Cluster "${cluster.name}" has enableRBAC=false — authorization falls back to coarse-grained access instead of per-role Kubernetes RBAC.`,
        remediation: 'RBAC cannot be toggled on an existing AKS cluster — recreate it with --enable-rbac (the default for new clusters).',
      });
    }
    if (!cluster.networkPolicy) {
      reporter.add({
        provider: 'azure',
        service: 'aks',
        check: 'azure-aks-network-policy-missing',
        severity: 'low',
        action: 'azure-aks-enable-network-policy',
        title: 'AKS cluster has no network policy engine',
        resource: cluster.name,
        region: cluster.location,
        description: `Cluster "${cluster.name}" has no networkPolicy (Azure, Calico or Cilium), so every pod can reach every other pod and Kubernetes NetworkPolicy objects are not enforced.`,
        remediation: 'The network policy engine is chosen at cluster creation (--network-policy azure|calico|cilium); recreate or migrate the cluster to enable it.',
      });
    }
    if (!cluster.aadIntegrated) {
      reporter.add({
        provider: 'azure',
        service: 'aks',
        check: 'azure-aks-aad-not-integrated',
        severity: 'medium',
        action: 'azure-aks-enable-aad',
        title: 'AKS cluster is not integrated with Microsoft Entra ID',
        resource: cluster.name,
        region: cluster.location,
        description: `Cluster "${cluster.name}" has no Entra ID integration, so users authenticate to the Kubernetes API with static certificate credentials instead of their directory identity (no MFA, no central offboarding, weak audit trail).`,
        remediation: `az aks update --name ${cluster.name} --resource-group <rg> --enable-aad --aad-admin-group-object-ids <group-id>`,
      });
    }
    if (!cluster.monitoringEnabled) {
      reporter.add({
        provider: 'azure',
        service: 'aks',
        check: 'azure-aks-monitoring-disabled',
        severity: 'low',
        action: 'azure-aks-enable-monitoring',
        title: 'AKS cluster has no Azure Monitor (Container insights) enabled',
        resource: cluster.name,
        region: cluster.location,
        description: `Cluster "${cluster.name}" has neither the monitoring add-on nor managed Prometheus enabled, so node and container health and logs are not collected for investigation.`,
        remediation: `az aks enable-addons --name ${cluster.name} --resource-group <rg> --addons monitoring`,
      });
    }
    if (!cluster.localAccountsDisabled) {
      reporter.add({
        provider: 'azure',
        service: 'aks',
        check: 'azure-aks-local-accounts-enabled',
        severity: 'medium',
        action: 'azure-aks-disable-local-accounts',
        title: 'AKS cluster allows local (non-Azure AD) accounts',
        resource: cluster.name,
        region: cluster.location,
        description: `Cluster "${cluster.name}" has disableLocalAccounts=false, so certificate-based local admin credentials (bypassing Azure AD/Entra ID auth and its audit trail) can still be used to authenticate.`,
        remediation: `az aks update --name ${cluster.name} --resource-group <rg> --disable-local-accounts (requires Azure AD integration to already be enabled on the cluster).`,
      });
    }
    if (!cluster.privateCluster && cluster.authorizedIpRanges.length === 0) {
      reporter.add({
        provider: 'azure',
        service: 'aks',
        check: 'azure-aks-public-api-no-authorized-ranges',
        severity: 'medium',
        action: 'azure-aks-restrict-api-access',
        title: 'AKS API server is public with no authorized IP ranges',
        resource: cluster.name,
        region: cluster.location,
        description: `Cluster "${cluster.name}" has a public API server endpoint and no authorizedIPRanges configured, so the Kubernetes API is reachable from any IP (valid credentials are still required, but the attack surface is the entire internet).`,
        remediation: `az aks update --name ${cluster.name} --resource-group <rg> --api-server-authorized-ip-ranges <cidr1,cidr2> (or --enable-private-cluster to remove the public endpoint entirely — requires cluster recreation).`,
      });
    }
  }
}

async function runAzureChecks({ subscriptionId, accessToken }, reporter, log = () => {}) {
  await runStorageChecks(subscriptionId, accessToken, reporter, log);
  await runNsgChecks(subscriptionId, accessToken, reporter, log);
  await runSqlChecks(subscriptionId, accessToken, reporter, log);
  await runKeyVaultChecks(subscriptionId, accessToken, reporter, log);
  await runAppServiceChecks(subscriptionId, accessToken, reporter, log);
  await runAcrChecks(subscriptionId, accessToken, reporter, log);
  await runAksChecks(subscriptionId, accessToken, reporter, log);
  // Subscription-level settings (Defender plans, Activity Log, RBAC), managed disks,
  // PostgreSQL/MySQL flexible servers, Cosmos DB and Redis.
  await runAzureExtendedChecks({ subscriptionId, accessToken }, reporter, log);
}

export { runAzureChecks };
