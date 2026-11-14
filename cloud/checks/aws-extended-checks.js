'use strict';
/**
 * AWS checks for services and account-level settings that checks/aws-checks.js
 * doesn't cover: S3 account-level Block Public Access, public EBS snapshots and
 * AMIs, KMS (key rotation, key-policy exposure), Lambda (resource policy, function
 * URLs, deprecated runtimes, secrets in environment variables), AWS Config,
 * Elastic Load Balancing v2, EFS and Redshift.
 *
 * Called from the end of runAwsChecks(). Same conventions as the rest of the
 * scanner: read-only calls, per-resource try/catch so one failure never aborts
 * the scan, bounded concurrency, stdlib only.
 */
import * as ec2 from '../providers/aws/ec2.js';
import * as kms from '../providers/aws/kms.js';
import * as lambda from '../providers/aws/lambda.js';
import * as awsConfig from '../providers/aws/config.js';
import * as elbv2 from '../providers/aws/elbv2.js';
import * as efs from '../providers/aws/efs.js';
import * as redshift from '../providers/aws/redshift.js';
import * as sts from '../providers/aws/sts.js';
import * as s3control from '../providers/aws/s3control.js';
import { mapLimit } from '../lib/concurrency.js';
import {
  KMS_SAFE_CONDITION_KEYS,
  worstConditionMatch,
  findPublicPrincipalStatements,
  addPublicResourcePolicyFinding,
} from '../lib/aws_policy.js';

const CONCURRENCY = 8;

// ─── S3 account-level Block Public Access ───────────────────────────────

async function runS3AccountChecks(creds, reporter, log) {
  let account;
  try {
    account = await sts.getCallerIdentity(creds);
  } catch (err) {
    log(`  [s3] GetCallerIdentity failed (needed for the account-level S3 settings): ${err.message}`);
    return;
  }
  try {
    const pab = await s3control.getAccountPublicAccessBlock(account.account, creds);
    const off = Object.entries(pab)
      .filter(([, v]) => !v)
      .map(([k]) => k);
    if (off.length > 0) {
      reporter.add({
        provider: 'aws',
        service: 's3',
        check: 's3-account-public-access-block',
        severity: 'medium',
        action: 's3-enable-account-public-access-block',
        title: 'S3 Block Public Access is not fully enabled for the whole account',
        resource: `account ${account.account}`,
        description: `The account-level Block Public Access protections that are OFF: ${off.join(', ')}. Without them, any single bucket whose own settings are loosened (by hand or by an IaC change) can become public; the account-level setting overrides every bucket.`,
        remediation: `aws s3control put-public-access-block --account-id ${account.account} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`,
      });
    }
  } catch (err) {
    log(`  [s3] GetPublicAccessBlock (account) failed: ${err.message}`);
  }
}

// ─── Public EBS snapshots / AMIs ────────────────────────────────────────

async function runPublicSharingChecks(regions, creds, reporter, log) {
  await mapLimit(regions, CONCURRENCY, async (region) => {
    try {
      const snaps = await ec2.describePublicSnapshots(region, creds);
      log(`  [ec2:${region}] ${snaps.length} publicly restorable EBS snapshot(s)`);
      for (const snap of snaps) {
        reporter.add({
          provider: 'aws',
          service: 'ec2',
          check: 'ebs-snapshot-public',
          severity: 'critical',
          action: 'ebs-make-snapshot-private',
          title: 'EBS snapshot is shared publicly',
          resource: snap.snapshotId,
          region,
          description: `Snapshot "${snap.snapshotId}" (${snap.size} GiB, of volume ${snap.volumeId || 'unknown'}) can be restored by any AWS account, which means anyone can copy the disk's contents${snap.encrypted ? ' (it is encrypted, so the copy is only readable if the KMS key is also shared)' : ' -- and it is not encrypted'}.`,
          remediation: `aws ec2 modify-snapshot-attribute --snapshot-id ${snap.snapshotId} --attribute createVolumePermission --operation-type remove --group-names all --region ${region}`,
        });
      }
    } catch (err) {
      log(`  [ec2:${region}] DescribeSnapshots (public) failed: ${err.message}`);
    }

    try {
      const images = await ec2.describePublicImages(region, creds);
      log(`  [ec2:${region}] ${images.length} public AMI(s)`);
      for (const img of images) {
        reporter.add({
          provider: 'aws',
          service: 'ec2',
          check: 'ami-public',
          severity: 'high',
          action: 'ami-make-private',
          title: 'AMI is shared publicly',
          resource: img.imageId,
          region,
          description: `Image "${img.imageId}"${img.name ? ` (${img.name})` : ''} is launchable by any AWS account. An image often carries baked-in configuration, keys or application code that was never meant to leave the account.`,
          remediation: `aws ec2 modify-image-attribute --image-id ${img.imageId} --launch-permission "Remove=[{Group=all}]" --region ${region}`,
        });
      }
    } catch (err) {
      log(`  [ec2:${region}] DescribeImages (public) failed: ${err.message}`);
    }
  });
}

// ─── KMS ────────────────────────────────────────────────────────────────

async function runKmsChecks(regions, creds, reporter, log) {
  await mapLimit(regions, CONCURRENCY, async (region) => {
    let keyIds;
    try {
      keyIds = await kms.listKeyIds(region, creds);
    } catch (err) {
      log(`  [kms:${region}] ListKeys failed: ${err.message}`);
      return;
    }
    log(`  [kms:${region}] ${keyIds.length} key(s) found`);

    await mapLimit(keyIds, CONCURRENCY, async (keyId) => {
      let key;
      try {
        key = await kms.describeKey(keyId, region, creds);
      } catch (err) {
        log(`  [kms:${region}] DescribeKey(${keyId}) failed: ${err.message}`);
        return;
      }
      // AWS-managed keys (aws/s3, aws/ebs, ...) are rotated by AWS and their
      // policies aren't editable, so only customer-managed keys are in scope.
      if (!key.customerManaged) return;
      if (key.state === 'PendingDeletion' || key.state === 'PendingReplicaDeletion') return;

      if (key.rotatable && key.state === 'Enabled') {
        try {
          const rotating = await kms.getKeyRotationEnabled(keyId, region, creds);
          if (!rotating) {
            reporter.add({
              provider: 'aws',
              service: 'kms',
              check: 'kms-key-rotation-disabled',
              severity: 'low',
              action: 'kms-enable-key-rotation',
              title: 'KMS customer-managed key does not have automatic rotation enabled',
              resource: key.arn || keyId,
              region,
              description: `Key "${keyId}" is a symmetric customer-managed key with rotation off, so the same key material protects data for as long as the key exists, which widens the damage of any single key compromise.`,
              remediation: `aws kms enable-key-rotation --key-id ${keyId} --region ${region}`,
            });
          }
        } catch (err) {
          log(`  [kms:${region}] GetKeyRotationStatus(${keyId}) failed: ${err.message}`);
        }
      }

      try {
        const policy = await kms.getKeyPolicy(keyId, region, creds);
        if (!policy) return;
        // `Principal: "*"` guarded only by kms:CallerAccount / kms:ViaService is the
        // pattern AWS itself writes for service-integrated keys (it is scoped to the
        // owning account / one service), so it is not reported.
        const matches = findPublicPrincipalStatements(policy, KMS_SAFE_CONDITION_KEYS).filter(
          (m) => !(m.conditionKeys.length > 0 && m.conditionKeys.every((k) => KMS_SAFE_CONDITION_KEYS.has(k)))
        );
        if (matches.length === 0) return;
        addPublicResourcePolicyFinding(reporter, {
          service: 'kms',
          check: 'kms-key-policy-public',
          resource: key.arn || keyId,
          region,
          resourceLabel: 'KMS key',
          remediation: `Scope the key policy's Principal to specific accounts/roles: aws kms put-key-policy --key-id ${keyId} --policy-name default --policy file://scoped-key-policy.json --region ${region}`,
          match: worstConditionMatch(matches),
        });
      } catch (err) {
        log(`  [kms:${region}] GetKeyPolicy(${keyId}) failed: ${err.message}`);
      }
    });
  });
}

// ─── Lambda ─────────────────────────────────────────────────────────────

// Runtimes AWS Lambda no longer supports (no security patches; creating or
// updating functions on them is blocked). Deliberately limited to runtimes whose
// deprecation is long past so the list never accuses a still-supported runtime;
// it is a point-in-time list and newer deprecations are not in it.
const DEPRECATED_LAMBDA_RUNTIMES = new Set([
  'nodejs', 'nodejs4.3', 'nodejs4.3-edge', 'nodejs6.10', 'nodejs8.10', 'nodejs10.x', 'nodejs12.x', 'nodejs14.x', 'nodejs16.x',
  'python2.7', 'python3.6', 'python3.7', 'python3.8',
  'dotnetcore1.0', 'dotnetcore2.0', 'dotnetcore2.1', 'dotnetcore3.1', 'dotnet5.0', 'dotnet7',
  'ruby2.5', 'ruby2.7',
  'java8', 'go1.x', 'provided',
]);

// Variable-name tokens that mean "this holds a secret"...
const SECRET_NAME_TOKENS = new Set(['PASSWORD', 'PASSWD', 'PWD', 'SECRET', 'SECRETS', 'TOKEN', 'APIKEY', 'PRIVATEKEY']);
// ...unless the name's last token says it is only a *reference* to one
// (SECRET_NAME, DB_PASSWORD_ARN, TOKEN_URL, ...).
const REFERENCE_SUFFIX_TOKENS = new Set([
  'NAME', 'ARN', 'ID', 'URL', 'URI', 'PATH', 'HEADER', 'ENDPOINT', 'FILE', 'REGION', 'PARAMETER', 'PARAM',
  'SSM', 'TTL', 'EXPIRY', 'ENABLED', 'FIELD', 'LENGTH', 'POLICY', 'VERSION', 'STAGE', 'PREFIX', 'BUCKET',
]);
// Value shapes that are secrets whatever the variable is called.
const SECRET_VALUE_PATTERNS = [
  { re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/, kind: 'an AWS access key id', critical: true },
  { re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/, kind: 'a private key', critical: true },
  { re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/, kind: 'a GitHub token', critical: false },
  { re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/, kind: 'a Slack token', critical: false },
];

function nameLooksSecret(name) {
  const tokens = String(name).toUpperCase().split(/[^A-Z0-9]+/).filter(Boolean);
  if (tokens.length === 0) return false;
  if (REFERENCE_SUFFIX_TOKENS.has(tokens[tokens.length - 1])) return false;
  if (tokens.some((t) => SECRET_NAME_TOKENS.has(t))) return true;
  for (let i = 0; i < tokens.length - 1; i++) {
    const pair = `${tokens[i]} ${tokens[i + 1]}`;
    if (['API KEY', 'PRIVATE KEY', 'ACCESS KEY', 'SECRET KEY', 'AUTH KEY', 'CLIENT SECRET'].includes(pair)) return true;
  }
  return false;
}

/** A value that is a pointer to a secret store (or a template placeholder), not a secret. */
function valueLooksLikeReference(value) {
  const v = String(value).trim();
  return (
    v === '' ||
    /^(true|false|null|none|changeme)$/i.test(v) ||
    v.startsWith('arn:') ||
    v.startsWith('/') ||
    /^(ssm|secretsmanager|resolve):/i.test(v) ||
    /^\$\{.*\}$/.test(v) ||
    /^\{\{.*\}\}$/.test(v)
  );
}

/** Names (never values) of environment variables that look like they hold secrets. */
function findSecretEnvVars(envVars) {
  const byName = [];
  let criticalKind = null;
  const byShape = [];
  for (const [name, value] of Object.entries(envVars || {})) {
    if (typeof value !== 'string') continue;
    const shape = SECRET_VALUE_PATTERNS.find((p) => p.re.test(value));
    if (shape) {
      byShape.push({ name, kind: shape.kind });
      if (shape.critical) criticalKind = shape.kind;
      continue;
    }
    if (nameLooksSecret(name) && !valueLooksLikeReference(value)) byName.push(name);
  }
  return { byName, byShape, critical: Boolean(criticalKind) };
}

async function runLambdaChecks(regions, creds, reporter, log) {
  await mapLimit(regions, CONCURRENCY, async (region) => {
    let fns;
    try {
      fns = await lambda.listFunctions(region, creds);
    } catch (err) {
      log(`  [lambda:${region}] ListFunctions failed: ${err.message}`);
      return;
    }
    log(`  [lambda:${region}] ${fns.length} function(s) found`);

    await mapLimit(fns, CONCURRENCY, async (fn) => {
      if (fn.runtime && DEPRECATED_LAMBDA_RUNTIMES.has(fn.runtime)) {
        reporter.add({
          provider: 'aws',
          service: 'lambda',
          check: 'lambda-runtime-deprecated',
          severity: 'medium',
          action: 'lambda-upgrade-runtime',
          title: 'Lambda function uses a runtime AWS no longer supports',
          resource: fn.arn || fn.name,
          region,
          description: `Function "${fn.name}" runs on "${fn.runtime}", which is past its end of support: it receives no security patches and can no longer be updated on that runtime.`,
          remediation: `Move to a supported runtime: aws lambda update-function-configuration --function-name ${fn.name} --runtime <supported-runtime> --region ${region} (test first -- runtime upgrades can change behavior).`,
        });
      }

      const secrets = findSecretEnvVars(fn.envVars);
      if (secrets.byName.length + secrets.byShape.length > 0) {
        const parts = [];
        if (secrets.byShape.length) parts.push(secrets.byShape.map((s) => `${s.name} (holds ${s.kind})`).join(', '));
        if (secrets.byName.length) parts.push(`${secrets.byName.join(', ')} (named like a secret)`);
        reporter.add({
          provider: 'aws',
          service: 'lambda',
          check: 'lambda-env-secrets',
          severity: secrets.critical ? 'critical' : 'high',
          action: 'lambda-move-secrets-to-secrets-manager',
          title: 'Lambda function keeps secrets in plain-text environment variables',
          resource: fn.arn || fn.name,
          region,
          description: `Function "${fn.name}" has environment variable(s) that look like credentials: ${parts.join('; ')}. Anyone who can read the function's configuration (or its IaC state/logs) can read them. Only the variable names are reported here, never the values.`,
          remediation: 'Store the value in AWS Secrets Manager or SSM Parameter Store (SecureString), give the function role read access to just that secret, and fetch it at runtime. Rotate any credential that has been sitting in an environment variable.',
        });
      }

      try {
        const policy = await lambda.getFunctionPolicy(fn.name, region, creds);
        if (policy) {
          const matches = findPublicPrincipalStatements(policy);
          if (matches.length > 0) {
            addPublicResourcePolicyFinding(reporter, {
              service: 'lambda',
              check: 'lambda-function-policy-public',
              resource: fn.arn || fn.name,
              region,
              resourceLabel: 'Lambda function',
              remediation: `Remove or scope the statement: aws lambda remove-permission --function-name ${fn.name} --statement-id <sid> --region ${region}`,
              match: worstConditionMatch(matches),
            });
          }
        }
      } catch (err) {
        log(`  [lambda:${region}] GetPolicy(${fn.name}) failed: ${err.message}`);
      }

      try {
        const urls = await lambda.listFunctionUrls(fn.name, region, creds);
        for (const u of urls) {
          if (u.authType !== 'NONE') continue;
          reporter.add({
            provider: 'aws',
            service: 'lambda',
            check: 'lambda-function-url-no-auth',
            severity: 'medium',
            action: 'lambda-function-url-require-iam',
            title: 'Lambda function URL can be invoked by anyone (AuthType NONE)',
            resource: fn.arn || fn.name,
            region,
            description: `Function "${fn.name}" has a function URL (${u.url}) with AuthType=NONE, so anyone on the internet can invoke it without credentials. That is often intentional for a webhook or public endpoint, but worth confirming, because every invocation runs with the function's role and is billed to you.`,
            remediation: `If it should not be public: aws lambda update-function-url-config --function-name ${fn.name} --auth-type AWS_IAM --region ${region}`,
          });
        }
      } catch (err) {
        log(`  [lambda:${region}] ListFunctionUrlConfigs(${fn.name}) failed: ${err.message}`);
      }
    });
  });
}

// ─── AWS Config ─────────────────────────────────────────────────────────

/**
 * Like the GuardDuty and CloudTrail account-level checks: a recorder that exists
 * but is stopped is reported per region, and the absence of *any* recording
 * recorder across every scanned region is reported once. When no region could be
 * queried at all the account-wide finding is withheld (we don't know).
 */
async function runConfigChecks(regions, creds, reporter, log) {
  let anyRecording = false;
  let anyRegionAnswered = false;
  await mapLimit(regions, CONCURRENCY, async (region) => {
    let recorders;
    try {
      recorders = await awsConfig.describeRecorderStatus(region, creds);
    } catch (err) {
      log(`  [config:${region}] DescribeConfigurationRecorderStatus failed: ${err.message}`);
      return;
    }
    anyRegionAnswered = true;
    log(`  [config:${region}] ${recorders.length} recorder(s) found`);
    for (const rec of recorders) {
      if (rec.recording) {
        anyRecording = true;
        continue;
      }
      reporter.add({
        provider: 'aws',
        service: 'config',
        check: 'config-recorder-stopped',
        severity: 'medium',
        action: 'config-start-recorder',
        title: 'AWS Config recorder exists but is not recording',
        resource: rec.name,
        region,
        description: `Configuration recorder "${rec.name}" in ${region} is stopped${rec.lastStatus ? ` (last status: ${rec.lastStatus})` : ''}, so resource configuration changes there are not being recorded.`,
        remediation: `aws configservice start-configuration-recorder --configuration-recorder-name ${rec.name} --region ${region}`,
      });
    }
  });

  if (anyRegionAnswered && !anyRecording) {
    reporter.add({
      provider: 'aws',
      service: 'config',
      check: 'config-not-enabled',
      severity: 'medium',
      action: 'config-enable',
      title: 'AWS Config is not recording in any scanned region',
      resource: 'account',
      description: 'No scanned region has an active AWS Config recorder, so there is no history of how resources were configured and no basis for configuration-compliance rules or for investigating "what changed" after an incident.',
      remediation: 'aws configservice put-configuration-recorder --configuration-recorder name=default,roleARN=<role-arn> --recording-group allSupported=true,includeGlobalResourceTypes=true, then aws configservice put-delivery-channel ... and aws configservice start-configuration-recorder --configuration-recorder-name default (repeat per region).',
    });
  }
}

// ─── Elastic Load Balancing v2 ──────────────────────────────────────────

// Predefined TLS policies that still accept TLS 1.0 and/or 1.1.
const WEAK_TLS_POLICIES = new Set([
  'ELBSecurityPolicy-2016-08',
  'ELBSecurityPolicy-2015-05',
  'ELBSecurityPolicy-2015-03',
  'ELBSecurityPolicy-2015-02',
  'ELBSecurityPolicy-2014-10',
  'ELBSecurityPolicy-2014-01',
  'ELBSecurityPolicy-2011-08',
  'ELBSecurityPolicy-TLS-1-0-2015-04',
  'ELBSecurityPolicy-TLS-1-1-2017-01',
  'ELBSecurityPolicy-FS-2018-06',
  'ELBSecurityPolicy-FS-1-1-2019-08',
]);

async function runElbChecks(regions, creds, reporter, log) {
  await mapLimit(regions, CONCURRENCY, async (region) => {
    let lbs;
    try {
      lbs = await elbv2.describeLoadBalancers(region, creds);
    } catch (err) {
      log(`  [elbv2:${region}] DescribeLoadBalancers failed: ${err.message}`);
      return;
    }
    log(`  [elbv2:${region}] ${lbs.length} load balancer(s) found`);

    await mapLimit(lbs, CONCURRENCY, async (lb) => {
      if (lb.type === 'gateway') return;
      const internetFacing = lb.scheme === 'internet-facing';

      try {
        const listeners = await elbv2.describeListeners(lb.arn, region, creds);
        for (const l of listeners) {
          if (l.protocol === 'HTTP' && internetFacing && !l.defaultActionTypes.includes('redirect')) {
            reporter.add({
              provider: 'aws',
              service: 'elbv2',
              check: 'elbv2-http-listener-no-redirect',
              severity: 'medium',
              action: 'elbv2-redirect-http-to-https',
              title: 'Internet-facing load balancer serves plain HTTP without redirecting to HTTPS',
              resource: `${lb.name}:${l.port}`,
              region,
              description: `Listener ${l.arn} on "${lb.name}" accepts HTTP on port ${l.port} and its default action is "${l.defaultActionTypes.join(', ') || 'unknown'}", not a redirect to HTTPS, so clients can be served (and credentials or cookies sent) in clear text.`,
              remediation: `aws elbv2 modify-listener --listener-arn ${l.arn} --default-actions Type=redirect,RedirectConfig='{Protocol=HTTPS,Port=443,StatusCode=HTTP_301}' --region ${region}`,
            });
          }
          if ((l.protocol === 'HTTPS' || l.protocol === 'TLS') && l.sslPolicy && WEAK_TLS_POLICIES.has(l.sslPolicy)) {
            reporter.add({
              provider: 'aws',
              service: 'elbv2',
              check: 'elbv2-weak-tls-policy',
              severity: internetFacing ? 'medium' : 'low',
              action: 'elbv2-upgrade-tls-policy',
              title: 'Load balancer listener accepts TLS 1.0/1.1',
              resource: `${lb.name}:${l.port}`,
              region,
              description: `The ${l.protocol} listener on "${lb.name}" port ${l.port} uses the "${l.sslPolicy}" security policy, which still allows TLS 1.0 and/or 1.1 (deprecated, with known weaknesses).`,
              remediation: `aws elbv2 modify-listener --listener-arn ${l.arn} --ssl-policy ELBSecurityPolicy-TLS13-1-2-2021-06 --region ${region}`,
            });
          }
        }
      } catch (err) {
        log(`  [elbv2:${region}] ${lb.name}: DescribeListeners failed: ${err.message}`);
      }

      if (lb.type === 'application') {
        try {
          const attrs = await elbv2.describeLoadBalancerAttributes(lb.arn, region, creds);
          if (attrs['access_logs.s3.enabled'] !== 'true') {
            reporter.add({
              provider: 'aws',
              service: 'elbv2',
              check: 'elbv2-access-logs-disabled',
              severity: 'low',
              action: 'elbv2-enable-access-logs',
              title: 'Application load balancer has access logging disabled',
              resource: lb.name,
              region,
              description: `Load balancer "${lb.name}" does not write access logs, so there is no record of which clients requested what -- the first thing needed when investigating an incident.`,
              remediation: `aws elbv2 modify-load-balancer-attributes --load-balancer-arn ${lb.arn} --attributes Key=access_logs.s3.enabled,Value=true Key=access_logs.s3.bucket,Value=<bucket> --region ${region}`,
            });
          }
        } catch (err) {
          log(`  [elbv2:${region}] ${lb.name}: DescribeLoadBalancerAttributes failed: ${err.message}`);
        }
      }
    });
  });
}

// ─── EFS ────────────────────────────────────────────────────────────────

async function runEfsChecks(regions, creds, reporter, log) {
  await mapLimit(regions, CONCURRENCY, async (region) => {
    let systems;
    try {
      systems = await efs.describeFileSystems(region, creds);
    } catch (err) {
      log(`  [efs:${region}] DescribeFileSystems failed: ${err.message}`);
      return;
    }
    log(`  [efs:${region}] ${systems.length} file system(s) found`);
    for (const fs of systems) {
      if (fs.encrypted) continue;
      reporter.add({
        provider: 'aws',
        service: 'efs',
        check: 'efs-not-encrypted',
        severity: 'medium',
        action: 'efs-encrypt-file-system',
        title: 'EFS file system is not encrypted at rest',
        resource: fs.id,
        region,
        description: `File system "${fs.id}"${fs.name ? ` (${fs.name})` : ''} has Encrypted=false. Encryption can only be chosen when a file system is created, so this one has to be replaced.`,
        remediation: 'Create a new encrypted file system (aws efs create-file-system --encrypted), copy the data across with AWS DataSync or rsync, repoint the mounts, then delete the old one.',
      });
    }
  });
}

// ─── Redshift ───────────────────────────────────────────────────────────

async function runRedshiftChecks(regions, creds, reporter, log) {
  await mapLimit(regions, CONCURRENCY, async (region) => {
    let clusters;
    try {
      clusters = await redshift.describeClusters(region, creds);
    } catch (err) {
      log(`  [redshift:${region}] DescribeClusters failed: ${err.message}`);
      return;
    }
    log(`  [redshift:${region}] ${clusters.length} cluster(s) found`);
    for (const c of clusters) {
      if (c.publiclyAccessible) {
        reporter.add({
          provider: 'aws',
          service: 'redshift',
          check: 'redshift-cluster-public',
          severity: 'high',
          action: 'redshift-disable-public-access',
          title: 'Redshift cluster is publicly accessible',
          resource: c.id,
          region,
          description: `Cluster "${c.id}" has PubliclyAccessible=true, so its endpoint resolves to a public IP address (reachable from the internet wherever its security group allows it).`,
          remediation: `aws redshift modify-cluster --cluster-identifier ${c.id} --no-publicly-accessible --region ${region}`,
        });
      }
      if (!c.encrypted) {
        reporter.add({
          provider: 'aws',
          service: 'redshift',
          check: 'redshift-cluster-not-encrypted',
          severity: 'medium',
          action: 'redshift-enable-encryption',
          title: 'Redshift cluster is not encrypted at rest',
          resource: c.id,
          region,
          description: `Cluster "${c.id}" has Encrypted=false, so its data and snapshots are stored unencrypted.`,
          remediation: `aws redshift modify-cluster --cluster-identifier ${c.id} --encrypted --region ${region} (this triggers a re-encryption migration; plan for a maintenance window)`,
        });
      }
    }
  });
}

async function runAwsExtendedChecks({ creds, regions }, reporter, log = () => {}) {
  await runS3AccountChecks(creds, reporter, log);
  await runPublicSharingChecks(regions, creds, reporter, log);
  await runKmsChecks(regions, creds, reporter, log);
  await runLambdaChecks(regions, creds, reporter, log);
  await runConfigChecks(regions, creds, reporter, log);
  await runElbChecks(regions, creds, reporter, log);
  await runEfsChecks(regions, creds, reporter, log);
  await runRedshiftChecks(regions, creds, reporter, log);
}

// Exported for tests: the secret-detection and runtime lists are pure data/logic.
export { runAwsExtendedChecks, findSecretEnvVars, nameLooksSecret, DEPRECATED_LAMBDA_RUNTIMES, WEAK_TLS_POLICIES };
