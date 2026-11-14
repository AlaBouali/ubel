'use strict';
import * as s3 from '../providers/aws/s3.js';
import * as ec2 from '../providers/aws/ec2.js';
import * as iam from '../providers/aws/iam.js';
import * as rds from '../providers/aws/rds.js';
import * as cloudtrail from '../providers/aws/cloudtrail.js';
import * as guardduty from '../providers/aws/guardduty.js';
import * as sns from '../providers/aws/sns.js';
import * as sqs from '../providers/aws/sqs.js';
import { mapLimit } from '../lib/concurrency.js';
import { runAwsExtendedChecks } from './aws-extended-checks.js';
import {
  toArray,
  isConditionSafelyRestrictive,
  worstConditionMatch,
  principalIsWildcard,
  findPublicPrincipalStatements,
  addPublicResourcePolicyFinding,
} from '../lib/aws_policy.js';

const SENSITIVE_PORTS = {
  22: 'SSH',
  3389: 'RDP',
  3306: 'MySQL',
  5432: 'PostgreSQL',
  1433: 'MSSQL',
  27017: 'MongoDB',
  6379: 'Redis',
  9200: 'Elasticsearch',
  5601: 'Kibana',
  11211: 'Memcached',
  9042: 'Cassandra',
  5984: 'CouchDB',
};
const NINETY_DAYS_MS = 90 * 24 * 60 * 60 * 1000;
const UNUSED_KEY_DAYS = 45; // CIS AWS Foundations 1.12: credentials unused for 45 days or greater
const UNUSED_KEY_MS = UNUSED_KEY_DAYS * 24 * 60 * 60 * 1000;

// item 10: bound how many buckets/users/regions we work on concurrently
// so a large account gets parallelism without turning into a thundering
// herd against AWS's own API throttles (http.js still retries on 429s
// on top of this).
const CONCURRENCY = 8;

function portRangeIncludesAny(fromPort, toPort, ports) {
  if (fromPort === null || toPort === null) return null; // all-ports permission
  return Object.keys(ports)
    .map(Number)
    .filter((p) => p >= fromPort && p <= toPort);
}

// ─── S3 ─────────────────────────────────────────────────────────────────

async function checkBucket(bucket, creds, reporter, log) {
  const region = await s3.getBucketRegion(bucket.name, creds);
  try {
    const [acl, isPublicPolicy, pab, encrypted, versioned, logged] = await Promise.all([
      s3.getBucketAcl(bucket.name, region, creds),
      s3.getBucketPolicyStatus(bucket.name, region, creds),
      s3.getPublicAccessBlock(bucket.name, region, creds),
      s3.getBucketEncryption(bucket.name, region, creds),
      s3.getBucketVersioning(bucket.name, region, creds),
      s3.getBucketLogging(bucket.name, region, creds),
    ]);

    const publicGrant = acl.find((g) => g.granteeUri?.includes('AllUsers'));
    const authGrant = acl.find((g) => g.granteeUri?.includes('AuthenticatedUsers'));

    if (publicGrant) {
      reporter.add({
        provider: 'aws',
        service: 's3',
        check: 's3-acl-public',
        severity: 'critical',
        action: 's3-restrict-acl',
        title: 'S3 bucket ACL grants access to anyone on the internet',
        resource: bucket.name,
        region,
        description: `The bucket ACL grants "${publicGrant.permission}" to the "AllUsers" group, meaning anyone on the internet can access it.`,
        remediation: `Remove the public grant: aws s3api put-bucket-acl --bucket ${bucket.name} --acl private`,
      });
    }
    if (authGrant) {
      reporter.add({
        provider: 'aws',
        service: 's3',
        check: 's3-acl-authenticated-users',
        severity: 'high',
        action: 's3-restrict-acl',
        title: 'S3 bucket ACL grants access to "any authenticated AWS user"',
        resource: bucket.name,
        region,
        description: `The "AuthenticatedUsers" group covers any AWS account, not just your own — this is effectively public.`,
        remediation: `Remove the AuthenticatedUsers grant: aws s3api put-bucket-acl --bucket ${bucket.name} --acl private`,
      });
    }
    if (isPublicPolicy) {
      reporter.add({
        provider: 'aws',
        service: 's3',
        check: 's3-policy-public',
        severity: 'critical',
        action: 's3-remove-public-policy',
        title: 'S3 bucket policy allows public access',
        resource: bucket.name,
        region,
        description: 'AWS itself has flagged this bucket policy as granting public access (GetBucketPolicyStatus.IsPublic=true).',
        remediation: 'Review the bucket policy and remove statements granting Principal "*" without a condition.',
      });
    }
    const offBlocks = Object.entries(pab)
      .filter(([, v]) => !v)
      .map(([k]) => k);
    if (offBlocks.length > 0) {
      reporter.add({
        provider: 'aws',
        service: 's3',
        check: 's3-public-access-block',
        severity: 'medium',
        action: 's3-enable-public-access-block',
        title: 'S3 Block Public Access is not fully enabled',
        resource: bucket.name,
        region,
        description: `The following protections are OFF: ${offBlocks.join(', ')}.`,
        remediation: `aws s3api put-public-access-block --bucket ${bucket.name} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`,
      });
    }
    if (!encrypted) {
      reporter.add({
        provider: 'aws',
        service: 's3',
        check: 's3-encryption-disabled',
        severity: 'medium',
        action: 's3-enable-encryption',
        title: 'S3 bucket has no default encryption configured',
        resource: bucket.name,
        region,
        description: 'Objects written without an explicit encryption header will be stored unencrypted at rest.',
        remediation: `aws s3api put-bucket-encryption --bucket ${bucket.name} --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'`,
      });
    }
    if (!versioned) {
      reporter.add({
        provider: 'aws',
        service: 's3',
        check: 's3-versioning-disabled',
        severity: 'low',
        action: 's3-enable-versioning',
        title: 'S3 bucket versioning is disabled',
        resource: bucket.name,
        region,
        description: 'Without versioning, objects overwritten or deleted (accidentally or via ransomware) cannot be recovered.',
        remediation: `aws s3api put-bucket-versioning --bucket ${bucket.name} --versioning-configuration Status=Enabled`,
      });
    }
    if (!logged) {
      reporter.add({
        provider: 'aws',
        service: 's3',
        check: 's3-logging-disabled',
        severity: 'low',
        action: 's3-enable-logging',
        title: 'S3 server access logging is disabled',
        resource: bucket.name,
        region,
        description: 'Without access logging, there is no audit trail of requests made against this bucket.',
        remediation: 'Enable server access logging to a dedicated log bucket via the console or put-bucket-logging.',
      });
    }

    // item 4: object-level public access — see s3.js for why this is a
    // bounded sample rather than a full-bucket crawl. Only worth
    // sampling if the bucket-level protections above didn't already
    // rule out public ACLs entirely (RestrictPublicBuckets/IgnorePublicAcls
    // both on means individual object ACLs can't make anything public).
    if (!pab.ignorePublicAcls) {
      try {
        const { objects, sampled, coverage } = await s3.listObjectsSample(bucket.name, region, creds);
        const publicKeys = [];
        for (const obj of objects) {
          const objAcl = await s3.getObjectAcl(bucket.name, obj.key, region, creds);
          if (objAcl.some((g) => g.granteeUri?.includes('AllUsers'))) publicKeys.push(obj.key);
        }
        if (publicKeys.length > 0) {
          reporter.add({
            provider: 'aws',
            service: 's3',
            check: 's3-object-acl-public-sample',
            severity: 'high',
            action: 's3-remove-object-public-acl',
            title: 'Sampled objects in this bucket have a public-read ACL',
            resource: bucket.name,
            region,
            // item 1 of the review: expose the sample's honesty as
            // structured fields, not just prose -- a consumer scripting
            // against the JSON output can tell a spot-check from an
            // exhaustive result without parsing the description.
            sampled,
            coverage,
            sampleSize: objects.length,
            description: sampled
              ? `${publicKeys.length} of ${objects.length} sampled object(s) grant read access to "AllUsers" (sampled from multiple points across the key space -- not an exhaustive scan of every object in the bucket): ${publicKeys.slice(0, 5).join(', ')}${publicKeys.length > 5 ? ', ...' : ''}.`
              : `${publicKeys.length} of ${objects.length} object(s) in this bucket grant read access to "AllUsers". The bucket has ${objects.length} object(s) total, so this is a complete scan, not a sample: ${publicKeys.slice(0, 5).join(', ')}${publicKeys.length > 5 ? ', ...' : ''}.`,
            remediation: `Remove public grants per-object, e.g. aws s3api put-object-acl --bucket ${bucket.name} --key <key> --acl private, or enable BlockPublicAcls/RestrictPublicBuckets account-wide.`,
          });
        }
      } catch (err) {
        log(`  [s3] ${bucket.name}: object ACL sample failed: ${err.message}`);
      }
    }
  } catch (err) {
    log(`  [s3] ${bucket.name}: ${err.message}`);
  }
}

async function runS3Checks(creds, reporter, log) {
  let buckets;
  try {
    buckets = await s3.listBuckets(creds);
  } catch (err) {
    log(`  [s3] ListBuckets failed: ${err.message}`);
    return;
  }
  log(`  [s3] ${buckets.length} bucket(s) found`);
  await mapLimit(buckets, CONCURRENCY, (bucket) => checkBucket(bucket, creds, reporter, log));
}

// ─── EC2 ────────────────────────────────────────────────────────────────

function checkSecurityGroupPermissions(sg, region, reporter) {
  for (const perm of sg.ipPermissions) {
    const openToInternet = perm.ipv4Ranges.includes('0.0.0.0/0') || perm.ipv6Ranges.includes('::/0');
    if (!openToInternet) continue;

    if (perm.fromPort === null && perm.toPort === null) {
      reporter.add({
        provider: 'aws',
        service: 'ec2',
        check: 'sg-open-all-ports',
        severity: 'critical',
        action: 'sg-restrict-ingress',
        title: 'Security group allows ALL traffic from the internet',
        resource: `${sg.groupId} (${sg.groupName})`,
        region,
        description: `Protocol "${perm.protocol}" is open to 0.0.0.0/0 or ::/0 with no port restriction.`,
        remediation: `Restrict the rule to specific known source IP ranges and ports: aws ec2 revoke-security-group-ingress --group-id ${sg.groupId} ...`,
      });
      continue;
    }

    const hitSensitive = portRangeIncludesAny(perm.fromPort, perm.toPort, SENSITIVE_PORTS) || [];
    if (hitSensitive.length > 0) {
      for (const port of hitSensitive) {
        reporter.add({
          provider: 'aws',
          service: 'ec2',
          check: 'sg-open-sensitive-port',
          severity: 'high',
          action: 'sg-restrict-ingress',
          title: `Security group exposes ${SENSITIVE_PORTS[port]} (port ${port}) to the internet`,
          resource: `${sg.groupId} (${sg.groupName})`,
          region,
          description: `Inbound rule allows port ${port} (${SENSITIVE_PORTS[port]}) from 0.0.0.0/0 or ::/0.`,
          remediation: `Restrict source to known IPs/VPN/bastion, e.g. aws ec2 revoke-security-group-ingress --group-id ${sg.groupId} --protocol ${perm.protocol} --port ${port} --cidr 0.0.0.0/0`,
        });
      }
    } else {
      reporter.add({
        provider: 'aws',
        service: 'ec2',
        check: 'sg-open-ingress',
        severity: 'medium',
        action: 'sg-restrict-ingress',
        title: 'Security group allows inbound access from the internet',
        resource: `${sg.groupId} (${sg.groupName})`,
        region,
        description: `Inbound rule allows ${perm.protocol} ports ${perm.fromPort}-${perm.toPort} from 0.0.0.0/0 or ::/0.`,
        remediation: 'Narrow the source CIDR to only the ranges that need this access.',
      });
    }
  }
}

async function runEc2ChecksForRegion(region, creds, reporter, log) {
  let groups = [];
  try {
    groups = await ec2.describeSecurityGroups(region, creds);
    log(`  [ec2:${region}] ${groups.length} security group(s) found`);
    for (const sg of groups) checkSecurityGroupPermissions(sg, region, reporter);
  } catch (err) {
    log(`  [ec2:${region}] DescribeSecurityGroups failed: ${err.message}`);
  }

  // item 4: EC2 instances with public IPs weren't checked at all before
  // (only indirectly, via the security group they happen to sit behind).
  try {
    const instances = await ec2.describeInstances(region, creds);
    const publicInstances = instances.filter((i) => i.publicIp);
    log(`  [ec2:${region}] ${instances.length} instance(s) found (${publicInstances.length} with a public IP)`);

    // IMDSv1 (httpTokens=optional) lets any request-forgery bug in the workload read
    // the instance role's credentials -- the classic cloud credential-theft path.
    for (const inst of instances) {
      if (!inst.imdsV1Allowed) continue;
      const exposed = Boolean(inst.publicIp) && inst.hasInstanceProfile;
      reporter.add({
        provider: 'aws',
        service: 'ec2',
        check: 'ec2-instance-imdsv1-allowed',
        severity: exposed ? 'high' : 'medium',
        action: 'ec2-require-imdsv2',
        title: 'EC2 instance still allows IMDSv1 (instance metadata without a session token)',
        resource: inst.instanceId,
        region,
        description: `Instance "${inst.instanceId}" (state: ${inst.state}) has HttpTokens=optional, so the metadata service answers plain GET requests.${inst.hasInstanceProfile ? ' It has an instance profile, so those requests can return role credentials.' : ''}${inst.publicIp ? ` It also has a public IP (${inst.publicIp}).` : ''}`,
        remediation: `aws ec2 modify-instance-metadata-options --instance-id ${inst.instanceId} --http-tokens required --http-endpoint enabled --region ${region}`,
      });
    }

    // The default security group is meant to be left empty; one that instances
    // actually sit in is a group whose rules nobody owns.
    const defaultGroupIds = new Set(groups.filter((g) => g.groupName === 'default').map((g) => g.groupId));
    const usersOfDefault = new Map();
    for (const inst of instances) {
      for (const gid of inst.securityGroupIds) {
        if (defaultGroupIds.has(gid)) usersOfDefault.set(gid, [...(usersOfDefault.get(gid) || []), inst.instanceId]);
      }
    }
    for (const [gid, ids] of usersOfDefault) {
      reporter.add({
        provider: 'aws',
        service: 'ec2',
        check: 'sg-default-in-use',
        severity: 'low',
        action: 'sg-use-dedicated-group',
        title: 'Instances are using the VPC default security group',
        resource: `${gid} (default)`,
        region,
        description: `The default security group ${gid} is attached to ${ids.length} instance(s) (${ids.slice(0, 5).join(', ')}${ids.length > 5 ? ', ...' : ''}). Its rules apply to everything that ever lands in it, including instances launched later without choosing a group.`,
        remediation: `Give each workload its own purpose-built security group, then remove all rules from ${gid}: aws ec2 modify-instance-attribute --instance-id <id> --groups <sg-id>`,
      });
    }
    for (const inst of publicInstances) {
      reporter.add({
        provider: 'aws',
        service: 'ec2',
        check: 'ec2-instance-public-ip',
        severity: 'low',
        action: 'ec2-remove-public-ip',
        title: 'EC2 instance has a public IP address',
        resource: inst.instanceId,
        region,
        description: `Instance "${inst.instanceId}" (state: ${inst.state}) has public IP ${inst.publicIp}. This is informational — pair it with the security-group findings above to see what's actually reachable.`,
        remediation: `If public access isn't required, move the instance to a private subnet behind a NAT gateway/bastion, or release its Elastic IP: aws ec2 disassociate-address ...`,
      });
    }
  } catch (err) {
    log(`  [ec2:${region}] DescribeInstances failed: ${err.message}`);
  }

  // item 4: VPC flow logs weren't checked at all before.
  try {
    const [vpcs, flowLogs] = await Promise.all([ec2.describeVpcs(region, creds), ec2.describeFlowLogs(region, creds)]);
    const vpcsWithLogs = new Set(
      flowLogs.filter((f) => f.flowLogStatus === 'ACTIVE').map((f) => f.resourceId)
    );
    for (const vpc of vpcs) {
      if (vpcsWithLogs.has(vpc.vpcId)) continue;
      reporter.add({
        provider: 'aws',
        service: 'ec2',
        check: 'vpc-flow-logs-disabled',
        severity: 'low',
        action: 'ec2-enable-flow-logs',
        title: 'VPC has no active flow log',
        resource: vpc.vpcId,
        region,
        description: `VPC "${vpc.vpcId}"${vpc.isDefault ? ' (default VPC)' : ''} has no active VPC flow log, so there's no network-traffic audit trail for it.`,
        remediation: `aws ec2 create-flow-logs --resource-type VPC --resource-ids ${vpc.vpcId} --traffic-type ALL --log-destination-type cloud-watch-logs --log-group-name /vpc/flow-logs --deliver-logs-permission-arn <role-arn>`,
      });
    }
  } catch (err) {
    log(`  [ec2:${region}] flow log check failed: ${err.message}`);
  }

  // item 3: EBS default encryption -- one account/region-level call,
  // high signal ("will a volume someone forgets to encrypt explicitly
  // still end up encrypted?").
  try {
    const defaultEncrypted = await ec2.getEbsEncryptionByDefault(region, creds);
    if (!defaultEncrypted) {
      reporter.add({
        provider: 'aws',
        service: 'ec2',
        check: 'ebs-default-encryption-disabled',
        severity: 'medium',
        action: 'ebs-enable-default-encryption',
        title: 'EBS default encryption is not enabled',
        resource: `account (${region})`,
        region,
        description: 'New EBS volumes created in this region are not encrypted by default unless whoever creates them explicitly opts in.',
        remediation: `aws ec2 enable-ebs-encryption-by-default --region ${region}`,
      });
    }
  } catch (err) {
    log(`  [ec2:${region}] GetEbsEncryptionByDefault failed: ${err.message}`);
  }

  // item 3: EBS volumes -- unencrypted and/or unattached volumes weren't
  // checked at all before.
  try {
    const volumes = await ec2.describeVolumes(region, creds);
    log(`  [ec2:${region}] ${volumes.length} EBS volume(s) found`);
    for (const vol of volumes) {
      if (!vol.encrypted) {
        reporter.add({
          provider: 'aws',
          service: 'ec2',
          check: 'ebs-volume-not-encrypted',
          severity: 'medium',
          action: 'ebs-encrypt-volume',
          title: 'EBS volume is not encrypted',
          resource: vol.volumeId,
          region,
          description: `Volume "${vol.volumeId}" (${vol.size} GiB, state: ${vol.state}) has Encrypted=false. This can't be changed in place -- a snapshot/copy-with-encryption/restore is required.`,
          remediation: `Snapshot it, copy the snapshot with --encrypted (aws ec2 copy-snapshot --source-snapshot-id <id> --encrypted), then create a new volume from the encrypted copy and swap it in.`,
        });
      }
      if (vol.attachmentCount === 0 && vol.state === 'available') {
        reporter.add({
          provider: 'aws',
          service: 'ec2',
          check: 'ebs-volume-unattached',
          severity: 'low',
          action: 'ebs-review-unattached-volume',
          title: 'EBS volume is unattached',
          resource: vol.volumeId,
          region,
          description: `Volume "${vol.volumeId}" (${vol.size} GiB) is not attached to any instance. It's still billed, and an orphaned volume (especially an unencrypted one, or one left behind by a decommissioned host) is worth a deliberate keep-or-delete decision rather than sitting around indefinitely.`,
          remediation: `If no longer needed: aws ec2 delete-volume --volume-id ${vol.volumeId}. If it should be kept, tag it so it isn't mistaken for forgotten next scan.`,
        });
      }
    }
  } catch (err) {
    log(`  [ec2:${region}] DescribeVolumes failed: ${err.message}`);
  }
}

async function runEc2Checks(regions, creds, reporter, log) {
  await mapLimit(regions, CONCURRENCY, (region) => runEc2ChecksForRegion(region, creds, reporter, log));
}

// ─── IAM ────────────────────────────────────────────────────────────────

/** Statements that are Allow + Action includes "*" + Resource includes
 * "*". Reports `hasCondition`/`conditionIsSafeAllowlisted` per match so
 * callers can downgrade rather than blanket-flag statements a Condition
 * key actually constrains (item 2, refined by item 6 of the later
 * review: a blanket "any Condition downgrades this" rule has a
 * false-negative problem -- see the shared condition-safety helpers
 * above for the full reasoning). */
function findFullAdminStatements(doc) {
  const statements = toArray(doc?.Statement);
  const matches = [];
  for (const stmt of statements) {
    if (stmt.Effect !== 'Allow') continue;
    const actions = toArray(stmt.Action).map((a) => String(a));
    const resources = toArray(stmt.Resource).map((r) => String(r));
    if (actions.includes('*') && resources.includes('*')) {
      const hasCondition = Boolean(stmt.Condition && Object.keys(stmt.Condition).length > 0);
      matches.push({ hasCondition, conditionIsSafeAllowlisted: hasCondition && isConditionSafelyRestrictive(stmt.Condition) });
    }
  }
  return matches;
}

/** item 6: only downgrade to medium when the Condition is built
 * *entirely* out of keys known to meaningfully restrict access
 * (aws:SourceIp, aws:PrincipalArn, aws:MultiFactorAuthPresent, ...). A
 * Condition present but built from unrecognized/weak keys (e.g.
 * aws:RequestedRegion, which barely restricts anything; or
 * aws:PrincipalTag, whose effect this scanner can't evaluate) keeps the
 * finding at "high" rather than silently downgrading it, with the title
 * and description saying so explicitly so it reads as "review this",
 * not "this is fine". */
function addFullAdminFinding(reporter, { resource, title, description, remediation, hasCondition, conditionIsSafeAllowlisted }) {
  let severity;
  let finalTitle = title;
  let note = '';
  if (!hasCondition) {
    severity = 'high';
  } else if (conditionIsSafeAllowlisted) {
    severity = 'medium';
    note = ' A Condition key restricted to keys known to meaningfully constrain access (source IP/VPC, principal ARN/org/account, MFA) is present, which narrows this grant.';
  } else {
    severity = 'high';
    finalTitle = `${title} — under a Condition (review the condition)`;
    note = " A Condition key is present, but it isn't built entirely from keys known to meaningfully restrict access (e.g. aws:RequestedRegion barely restricts anything, and this scanner can't evaluate tag- or context-dependent keys like aws:PrincipalTag) — treat this as effectively unconditional until the condition is reviewed by hand.";
  }
  reporter.add({
    provider: 'aws',
    service: 'iam',
    check: 'iam-policy-full-admin',
    severity,
    action: 'iam-restrict-policy',
    title: finalTitle,
    resource,
    description: `${description}${note}`,
    remediation,
  });
}

/** Overly broad trust policy: Principal "*" (or an AWS principal list
 * containing "*") means literally anyone can attempt to assume the role
 * (item 4: "IAM roles with overly broad trust policies"). A Principal
 * scoped to a specific service (ec2.amazonaws.com, etc.) or account is
 * normal and is not flagged. */
function hasWildcardTrustPrincipal(trustPolicy) {
  const statements = toArray(trustPolicy?.Statement);
  for (const stmt of statements) {
    if (stmt.Effect !== 'Allow') continue;
    if (principalIsWildcard(stmt.Principal)) return true;
  }
  return false;
}

/** Returns how many inline policies the principal has (0 if they couldn't be read). */
async function reviewPrincipalPolicies(kind, principalName, resourceLabel, creds, reporter, log) {
  let count = 0;
  try {
    const inlineDocs = await iam.listInlinePolicyDocuments(kind, principalName, creds);
    count = inlineDocs.length;
    for (const { policyName, document } of inlineDocs) {
      const matches = findFullAdminStatements(document);
      if (matches.length === 0) continue;
      const worst = worstConditionMatch(matches);
      addFullAdminFinding(reporter, {
        resource: `${resourceLabel} (inline: ${policyName})`,
        title: `IAM inline policy grants "*" action on "*" resource (effectively full admin)`,
        description: `Inline policy "${policyName}" on ${kind} "${principalName}" has an Allow statement with Action:"*" and Resource:"*".`,
        remediation: `Scope the inline policy to only the specific actions/resources it needs, e.g. aws iam ${kind === 'user' ? 'put-user-policy' : kind === 'group' ? 'put-group-policy' : 'put-role-policy'} --policy-name ${policyName} --policy-document file://scoped-policy.json`,
        hasCondition: worst.hasCondition,
        conditionIsSafeAllowlisted: worst.conditionIsSafeAllowlisted,
      });
    }
  } catch (err) {
    log(`  [iam] ${kind} ${principalName}: inline policy review failed: ${err.message}`);
  }
  return count;
}

/** Returns how many managed policies are attached directly (0 if they couldn't be read). */
async function reviewAttachedPolicies(kind, principalName, resourceLabel, creds, reporter, log) {
  let count = 0;
  try {
    const attached = await iam.listAttachedPolicies(kind, principalName, creds);
    count = attached.length;
    for (const p of attached) {
      // AWS-managed policies (arn:aws:iam::aws:policy/...) can't have
      // their document fetched the same way as customer-managed ones
      // without an extra GetPolicy call to resolve the default version —
      // the one AWS-managed policy that's actually full-admin is
      // AdministratorAccess, which is common/intentional enough (and
      // whose ARN is well-known) that it's worth calling out by name
      // without an extra round trip per policy.
      if (p.arn === 'arn:aws:iam::aws:policy/AdministratorAccess') {
        reporter.add({
          provider: 'aws',
          service: 'iam',
          check: 'iam-policy-full-admin',
          severity: 'high',
          action: 'iam-restrict-policy',
          title: 'AWS-managed AdministratorAccess policy is attached',
          resource: `${resourceLabel} (attached: ${p.policyName})`,
          description: `${kind === 'group' ? 'Group' : kind === 'user' ? 'User' : 'Role'} "${principalName}" has the AWS-managed "AdministratorAccess" policy attached, granting Action:"*" on Resource:"*".`,
          remediation: `Detach it if full admin isn't actually required: aws iam detach-${kind}-policy --${kind}-name ${principalName} --policy-arn ${p.arn}`,
        });
      }
    }
  } catch (err) {
    log(`  [iam] ${kind} ${principalName}: attached policy review failed: ${err.message}`);
  }
  return count;
}

/** What's weak about an existing IAM password policy (the raw GetAccountPasswordPolicy
 * object -- every value is a string). Empty array = nothing to report. */
function passwordPolicyWeaknesses(policy) {
  const weaknesses = [];
  const minLength = Number(policy.MinimumPasswordLength || 0);
  if (minLength < 14) weaknesses.push(`requires only ${minLength || 'an unset number of'} characters (14 or more recommended)`);
  const reuse = Number(policy.PasswordReusePrevention || 0);
  if (reuse < 24) weaknesses.push(reuse ? `remembers only the last ${reuse} passwords (24 recommended)` : 'does not prevent password reuse');
  const missing = [
    ['RequireSymbols', 'symbols'],
    ['RequireNumbers', 'numbers'],
    ['RequireUppercaseCharacters', 'uppercase letters'],
    ['RequireLowercaseCharacters', 'lowercase letters'],
  ]
    .filter(([key]) => policy[key] !== 'true')
    .map(([, label]) => label);
  if (missing.length > 0) weaknesses.push(`does not require ${missing.join(', ')}`);
  return weaknesses;
}

/**
 * Root-user posture. No per-user IAM call ever looks at the account's root user,
 * but GetAccountSummary reports whether it has MFA and whether it has access keys.
 * Both are critical: the root user can't be restricted by IAM policy.
 */
async function runIamAccountChecks(creds, reporter, log) {
  let summary;
  try {
    summary = await iam.getAccountSummary(creds);
  } catch (err) {
    log(`  [iam] GetAccountSummary failed: ${err.message}`);
    return;
  }
  if (summary.AccountMFAEnabled === 0) {
    reporter.add({
      provider: 'aws',
      service: 'iam',
      check: 'iam-root-mfa-disabled',
      severity: 'critical',
      action: 'iam-enable-root-mfa',
      title: 'The AWS root user does not have MFA enabled',
      resource: 'account (root)',
      description: 'The root user can do everything in the account and cannot be limited by IAM policy; with only a password protecting it, one phished or reused password is a full account takeover.',
      remediation: 'Sign in as the root user and enable MFA (a hardware key or authenticator app): IAM console → Security credentials → Multi-factor authentication.',
    });
  }
  if (summary.AccountAccessKeysPresent > 0) {
    reporter.add({
      provider: 'aws',
      service: 'iam',
      check: 'iam-root-access-key-present',
      severity: 'critical',
      action: 'iam-delete-root-access-key',
      title: 'The AWS root user has an access key',
      resource: 'account (root)',
      description: `The root user has ${summary.AccountAccessKeysPresent} access key(s). A root access key gives unrestricted programmatic control of the whole account and is the most damaging credential that can leak.`,
      remediation: 'Sign in as the root user and delete the key(s): IAM console → Security credentials → Access keys. Use IAM roles or Identity Center for anything that needs API access.',
    });
  }
}

async function runIamChecks(creds, reporter, log) {
  let users;
  try {
    users = await iam.listUsers(creds);
  } catch (err) {
    log(`  [iam] ListUsers failed: ${err.message}`);
    return;
  }
  log(`  [iam] ${users.length} user(s) found`);

  await mapLimit(users, CONCURRENCY, async (user) => {
    try {
      const [keys, mfaDevices, consoleAccess] = await Promise.all([
        iam.listAccessKeys(user.userName, creds),
        iam.listMfaDevices(user.userName, creds),
        iam.hasConsoleAccess(user.userName, creds),
      ]);

      if (consoleAccess && mfaDevices.length === 0) {
        reporter.add({
          provider: 'aws',
          service: 'iam',
          check: 'iam-console-user-no-mfa',
          severity: 'high',
          action: 'iam-enable-mfa',
          title: 'IAM user has console access without MFA',
          resource: user.userName,
          description: 'This user can sign in to the AWS console with only a password.',
          remediation: `Require MFA: aws iam enable-mfa-device --user-name ${user.userName} ...`,
        });
      }

      const activeKeys = keys.filter((k) => k.status === 'Active');
      if (activeKeys.length > 1) {
        reporter.add({
          provider: 'aws',
          service: 'iam',
          check: 'iam-user-multiple-active-keys',
          severity: 'low',
          action: 'iam-remove-extra-access-key',
          title: 'IAM user has more than one active access key',
          resource: user.userName,
          description: `User "${user.userName}" has ${activeKeys.length} active access keys (${activeKeys.map((k) => k.accessKeyId).join(', ')}). Every extra live key is another credential that can leak, and it usually means a rotation was started and never finished.`,
          remediation: `Keep one key and deactivate the other: aws iam update-access-key --user-name ${user.userName} --access-key-id <old-key-id> --status Inactive (then delete it once nothing uses it).`,
        });
      }

      // Unused keys: a key that hasn't been used for 45+ days (or has never been
      // used since it was created that long ago) is a standing credential with no
      // owner paying attention to it.
      for (const key of activeKeys) {
        try {
          const { lastUsedDate } = await iam.getAccessKeyLastUsed(key.accessKeyId, creds);
          const reference = lastUsedDate || key.createDate;
          if (!reference) continue;
          const idleMs = Date.now() - new Date(reference).getTime();
          if (idleMs > UNUSED_KEY_MS) {
            const idleDays = Math.floor(idleMs / (24 * 3600 * 1000));
            reporter.add({
              provider: 'aws',
              service: 'iam',
              check: 'iam-access-key-unused',
              severity: 'low',
              action: 'iam-disable-unused-access-key',
              title: `IAM access key has been unused for over ${UNUSED_KEY_DAYS} days`,
              resource: `${user.userName} / ${key.accessKeyId}`,
              description: lastUsedDate
                ? `Active access key last used on ${lastUsedDate} (${idleDays} days ago).`
                : `Active access key created on ${key.createDate} (${idleDays} days ago) and never used.`,
              remediation: `Deactivate it, and delete it if nothing breaks: aws iam update-access-key --user-name ${user.userName} --access-key-id ${key.accessKeyId} --status Inactive`,
            });
          }
        } catch (err) {
          log(`  [iam] ${user.userName}: GetAccessKeyLastUsed(${key.accessKeyId}) failed: ${err.message}`);
        }
      }

      for (const key of keys) {
        if (key.status !== 'Active' || !key.createDate) continue;
        const ageMs = Date.now() - new Date(key.createDate).getTime();
        if (ageMs > NINETY_DAYS_MS) {
          reporter.add({
            provider: 'aws',
            service: 'iam',
            check: 'iam-access-key-not-rotated',
            severity: 'medium',
            action: 'iam-rotate-access-key',
            title: 'IAM access key has not been rotated in over 90 days',
            resource: `${user.userName} / ${key.accessKeyId}`,
            description: `Active access key created on ${key.createDate} (${Math.floor(ageMs / (24 * 3600 * 1000))} days ago).`,
            remediation: `Rotate the key: aws iam create-access-key --user-name ${user.userName}, update usage, then aws iam delete-access-key --access-key-id ${key.accessKeyId} --user-name ${user.userName}`,
          });
        }
      }
    } catch (err) {
      log(`  [iam] ${user.userName}: ${err.message}`);
    }

    // item 2: inline policies on users weren't checked at all before.
    const inlineCount = await reviewPrincipalPolicies('user', user.userName, user.userName, creds, reporter, log);
    // Directly attached managed policies (and AdministratorAccess among them) were
    // only ever checked for groups and roles.
    const attachedCount = await reviewAttachedPolicies('user', user.userName, user.userName, creds, reporter, log);
    if (inlineCount + attachedCount > 0) {
      reporter.add({
        provider: 'aws',
        service: 'iam',
        check: 'iam-user-direct-policies',
        severity: 'low',
        action: 'iam-move-permissions-to-group',
        title: 'IAM user receives permissions directly instead of through a group',
        resource: user.userName,
        description: `User "${user.userName}" has ${inlineCount} inline polic${inlineCount === 1 ? 'y' : 'ies'} and ${attachedCount} directly attached managed polic${attachedCount === 1 ? 'y' : 'ies'}. Per-user grants are hard to review and easy to forget when someone changes role or leaves.`,
        remediation: `Put the permissions in a group or role and add the user to it: aws iam add-user-to-group --user-name ${user.userName} --group-name <group>, then detach/delete the per-user policies.`,
      });
    }
  });

  try {
    const policy = await iam.getAccountPasswordPolicy(creds);
    if (!policy) {
      reporter.add({
        provider: 'aws',
        service: 'iam',
        check: 'iam-no-password-policy',
        severity: 'low',
        action: 'iam-set-password-policy',
        title: 'No account password policy is set',
        resource: 'account',
        description: 'The AWS account has no custom IAM password policy, so the (weak) AWS default applies.',
        remediation: 'aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters',
      });
    } else {
      // A policy exists -- but a policy can be set and still be weak.
      const weaknesses = passwordPolicyWeaknesses(policy);
      if (weaknesses.length > 0) {
        reporter.add({
          provider: 'aws',
          service: 'iam',
          check: 'iam-password-policy-weak',
          severity: 'low',
          action: 'iam-set-password-policy',
          title: 'Account password policy is weaker than recommended',
          resource: 'account',
          description: `The IAM password policy ${weaknesses.join('; ')}.`,
          remediation: 'aws iam update-account-password-policy --minimum-password-length 14 --password-reuse-prevention 24 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters',
        });
      }
    }
  } catch (err) {
    log(`  [iam] GetAccountPasswordPolicy failed: ${err.message}`);
  }

  // Customer-managed policies (any of them — attached or not) at their
  // default version, condition-aware now (item 2).
  try {
    const policies = await iam.listCustomerManagedPolicies(creds);
    log(`  [iam] ${policies.length} customer-managed polic${policies.length === 1 ? 'y' : 'ies'} found`);
    for (const p of policies) {
      const doc = await iam.getPolicyDocument(p.arn, p.defaultVersionId, creds);
      const matches = findFullAdminStatements(doc);
      if (matches.length === 0) continue;
      const worst = worstConditionMatch(matches);
      addFullAdminFinding(reporter, {
        resource: p.arn,
        title: 'IAM policy grants "*" action on "*" resource (effectively full admin)',
        description: `Policy "${p.policyName}" has an Allow statement with Action:"*" and Resource:"*".`,
        remediation: 'Scope the policy to only the specific actions and resources it actually needs.',
        hasCondition: worst.hasCondition,
        conditionIsSafeAllowlisted: worst.conditionIsSafeAllowlisted,
      });
    }
  } catch (err) {
    log(`  [iam] policy review failed: ${err.message}`);
  }

  // item 2: groups — inline policies + attached managed policies.
  try {
    const groups = await iam.listGroups(creds);
    log(`  [iam] ${groups.length} group(s) found`);
    await mapLimit(groups, CONCURRENCY, async (group) => {
      await reviewPrincipalPolicies('group', group.groupName, group.groupName, creds, reporter, log);
      await reviewAttachedPolicies('group', group.groupName, group.groupName, creds, reporter, log);
    });
  } catch (err) {
    log(`  [iam] ListGroups failed: ${err.message}`);
  }

  // item 2 + item 4: roles — inline/attached policies, plus the trust
  // policy itself (who can assume this role at all).
  try {
    const roles = await iam.listRoles(creds);
    log(`  [iam] ${roles.length} role(s) found`);
    await mapLimit(roles, CONCURRENCY, async (role) => {
      await reviewPrincipalPolicies('role', role.roleName, role.arn, creds, reporter, log);
      await reviewAttachedPolicies('role', role.roleName, role.arn, creds, reporter, log);
      if (role.trustPolicy && hasWildcardTrustPrincipal(role.trustPolicy)) {
        reporter.add({
          provider: 'aws',
          service: 'iam',
          check: 'iam-role-public-trust-policy',
          severity: 'critical',
          action: 'iam-restrict-trust-policy',
          title: 'IAM role trust policy allows any AWS principal to assume it',
          resource: role.arn,
          description: `Role "${role.roleName}"'s trust policy has an Allow statement with Principal "*" — any AWS account (or an unauthenticated caller, for some actions) can attempt to assume this role.`,
          remediation: `Scope the trust policy's Principal to specific account(s)/role(s)/service(s): aws iam update-assume-role-policy --role-name ${role.roleName} --policy-document file://trust-policy.json`,
        });
      }
    });
  } catch (err) {
    log(`  [iam] ListRoles failed: ${err.message}`);
  }
}

// ─── RDS ────────────────────────────────────────────────────────────────

async function runRdsChecksForRegion(region, creds, reporter, log) {
  try {
    const instances = await rds.describeDBInstances(region, creds);
    log(`  [rds:${region}] ${instances.length} instance(s) found`);
    for (const inst of instances) {
      if (inst.publiclyAccessible) {
        reporter.add({
          provider: 'aws',
          service: 'rds',
          check: 'rds-publicly-accessible',
          severity: 'high',
          action: 'rds-disable-public-access',
          title: 'RDS instance is publicly accessible',
          resource: inst.id,
          region,
          description: `${inst.engine} instance "${inst.id}" has PubliclyAccessible=true.`,
          remediation: `aws rds modify-db-instance --db-instance-identifier ${inst.id} --no-publicly-accessible --apply-immediately`,
        });
      }
      if (!inst.storageEncrypted) {
        reporter.add({
          provider: 'aws',
          service: 'rds',
          check: 'rds-storage-not-encrypted',
          severity: 'medium',
          action: 'rds-enable-encryption',
          title: 'RDS instance storage is not encrypted',
          resource: inst.id,
          region,
          description: `${inst.engine} instance "${inst.id}" has StorageEncrypted=false. This cannot be changed in place — a snapshot/restore-to-encrypted-copy is required.`,
          remediation: 'Snapshot the instance, copy the snapshot with encryption enabled, then restore from the encrypted copy.',
        });
      }
      const clusterManaged = Boolean(inst.clusterId);
      if (!clusterManaged && !inst.isReadReplica && inst.backupRetentionPeriod === 0) {
        reporter.add({
          provider: 'aws',
          service: 'rds',
          check: 'rds-backup-retention-disabled',
          severity: 'medium',
          action: 'rds-enable-automated-backups',
          title: 'RDS instance has automated backups turned off',
          resource: inst.id,
          region,
          description: `${inst.engine} instance "${inst.id}" has BackupRetentionPeriod=0, so there are no automated backups and no point-in-time recovery.`,
          remediation: `aws rds modify-db-instance --db-instance-identifier ${inst.id} --backup-retention-period 7 --apply-immediately`,
        });
      }
      if (!inst.deletionProtection) {
        reporter.add({
          provider: 'aws',
          service: 'rds',
          check: 'rds-deletion-protection-disabled',
          severity: 'low',
          action: 'rds-enable-deletion-protection',
          title: 'RDS instance does not have deletion protection',
          resource: inst.id,
          region,
          description: `${inst.engine} instance "${inst.id}" has DeletionProtection=false, so a single API call (or a mistaken IaC change) can delete the database.`,
          remediation: `aws rds modify-db-instance --db-instance-identifier ${inst.id} --deletion-protection --apply-immediately`,
        });
      }
      if (!inst.autoMinorVersionUpgrade) {
        reporter.add({
          provider: 'aws',
          service: 'rds',
          check: 'rds-auto-minor-upgrade-disabled',
          severity: 'low',
          action: 'rds-enable-auto-minor-upgrade',
          title: 'RDS instance does not apply minor engine upgrades automatically',
          resource: inst.id,
          region,
          description: `${inst.engine} instance "${inst.id}" has AutoMinorVersionUpgrade=false, so security patches released as minor versions are only applied if someone remembers to.`,
          remediation: `aws rds modify-db-instance --db-instance-identifier ${inst.id} --auto-minor-version-upgrade --apply-immediately`,
        });
      }
    }
  } catch (err) {
    log(`  [rds:${region}] DescribeDBInstances failed: ${err.message}`);
  }

  // item 4: RDS snapshots weren't checked at all before.
  try {
    const snapshots = await rds.describeDBSnapshots(region, creds);
    log(`  [rds:${region}] ${snapshots.length} snapshot(s) found`);
    const manual = snapshots.filter((s) => s.snapshotType === 'manual');
    await mapLimit(manual, CONCURRENCY, async (snap) => {
      try {
        const isPublic = await rds.isSnapshotPublic(snap.id, region, creds);
        if (isPublic) {
          reporter.add({
            provider: 'aws',
            service: 'rds',
            check: 'rds-snapshot-public',
            severity: 'critical',
            action: 'rds-make-snapshot-private',
            title: 'RDS snapshot is shared publicly',
            resource: snap.id,
            region,
            description: `Manual snapshot "${snap.id}" (of ${snap.dbInstanceId || 'a deleted instance'}) has its "restore" attribute shared with "all" — anyone can restore a copy of this database.`,
            remediation: `aws rds modify-db-snapshot-attribute --db-snapshot-identifier ${snap.id} --attribute-name restore --values-to-remove all`,
          });
        }
      } catch (err) {
        log(`  [rds:${region}] ${snap.id}: DescribeDBSnapshotAttributes failed: ${err.message}`);
      }
    });
    for (const snap of snapshots) {
      if (!snap.encrypted && snap.status === 'available') {
        reporter.add({
          provider: 'aws',
          service: 'rds',
          check: 'rds-snapshot-not-encrypted',
          severity: 'medium',
          action: 'rds-encrypt-snapshot',
          title: 'RDS snapshot is not encrypted',
          resource: snap.id,
          region,
          description: `${snap.snapshotType} snapshot "${snap.id}" has Encrypted=false.`,
          remediation: `Copy it into an encrypted snapshot: aws rds copy-db-snapshot --source-db-snapshot-identifier ${snap.id} --target-db-snapshot-identifier ${snap.id}-encrypted --kms-key-id <kms-key-arn>`,
        });
      }
    }
  } catch (err) {
    log(`  [rds:${region}] DescribeDBSnapshots failed: ${err.message}`);
  }
}

async function runRdsChecks(regions, creds, reporter, log) {
  await mapLimit(regions, CONCURRENCY, (region) => runRdsChecksForRegion(region, creds, reporter, log));
}

// ─── CloudTrail ─────────────────────────────────────────────────────────

/**
 * item 4: no CloudTrail checks at all before. Runs once per scanned
 * region (each trail surfaces exactly once, in its home region — see
 * cloudtrail.js), then applies both per-trail and account-wide checks
 * (e.g. "is there at least one multi-region trail that's logging").
 */
async function runCloudTrailChecks(regions, creds, reporter, log) {
  const allTrails = [];
  await mapLimit(regions, CONCURRENCY, async (region) => {
    try {
      const trails = await cloudtrail.describeTrails(region, creds);
      allTrails.push(...trails.map((t) => ({ ...t, region })));
    } catch (err) {
      log(`  [cloudtrail:${region}] DescribeTrails failed: ${err.message}`);
    }
  });
  log(`  [cloudtrail] ${allTrails.length} trail(s) found across ${regions.length} region(s)`);

  let anyMultiRegionLogging = false;
  await mapLimit(allTrails, CONCURRENCY, async (trail) => {
    let isLogging = false;
    try {
      const status = await cloudtrail.getTrailStatus(trail.arn, trail.region, creds);
      isLogging = status.isLogging;
    } catch (err) {
      log(`  [cloudtrail:${trail.region}] GetTrailStatus(${trail.name}) failed: ${err.message}`);
    }

    if (trail.isMultiRegionTrail && isLogging) anyMultiRegionLogging = true;

    if (!isLogging) {
      reporter.add({
        provider: 'aws',
        service: 'cloudtrail',
        check: 'cloudtrail-logging-stopped',
        severity: 'high',
        action: 'cloudtrail-enable-logging',
        title: 'CloudTrail trail exists but logging is stopped',
        resource: trail.arn,
        region: trail.homeRegion,
        description: `Trail "${trail.name}" exists but its status shows IsLogging=false.`,
        remediation: `aws cloudtrail start-logging --name ${trail.name} --region ${trail.homeRegion}`,
      });
    }
    if (!trail.kmsKeyId) {
      reporter.add({
        provider: 'aws',
        service: 'cloudtrail',
        check: 'cloudtrail-not-kms-encrypted',
        severity: 'medium',
        action: 'cloudtrail-enable-kms-encryption',
        title: 'CloudTrail trail logs are not encrypted with a KMS key',
        resource: trail.arn,
        region: trail.homeRegion,
        description: `Trail "${trail.name}" has no KmsKeyId set — log files land in S3 with only SSE-S3 (if any), not a customer-managed key.`,
        remediation: `aws cloudtrail update-trail --name ${trail.name} --kms-key-id <kms-key-arn> --region ${trail.homeRegion}`,
      });
    }
    if (!trail.cloudWatchLogsLogGroupArn) {
      reporter.add({
        provider: 'aws',
        service: 'cloudtrail',
        check: 'cloudtrail-no-cloudwatch-logs',
        severity: 'low',
        action: 'cloudtrail-send-to-cloudwatch',
        title: 'CloudTrail trail is not sent to CloudWatch Logs',
        resource: trail.arn,
        region: trail.homeRegion,
        description: `Trail "${trail.name}" has no CloudWatch Logs log group, so nothing can alarm on suspicious API activity (root use, console logins without MFA, IAM or security-group changes) as it happens.`,
        remediation: `aws cloudtrail update-trail --name ${trail.name} --cloud-watch-logs-log-group-arn <log-group-arn> --cloud-watch-logs-role-arn <role-arn> --region ${trail.homeRegion}`,
      });
    }
    if (!trail.logFileValidationEnabled) {
      reporter.add({
        provider: 'aws',
        service: 'cloudtrail',
        check: 'cloudtrail-log-validation-disabled',
        severity: 'low',
        action: 'cloudtrail-enable-log-validation',
        title: 'CloudTrail log file integrity validation is disabled',
        resource: trail.arn,
        region: trail.homeRegion,
        description: `Trail "${trail.name}" has LogFileValidationEnabled=false, so tampering with delivered log files wouldn't be detectable via digest files.`,
        remediation: `aws cloudtrail update-trail --name ${trail.name} --enable-log-file-validation --region ${trail.homeRegion}`,
      });
    }
  });

  if (!anyMultiRegionLogging) {
    reporter.add({
      provider: 'aws',
      service: 'cloudtrail',
      check: 'cloudtrail-no-multiregion-trail',
      severity: 'high',
      action: 'cloudtrail-enable-multiregion',
      title: 'No active multi-region CloudTrail trail found',
      resource: 'account',
      description: allTrails.length === 0
        ? 'No CloudTrail trails were found in any scanned region.'
        : 'None of the trails found are both multi-region and actively logging, so API activity in unmonitored regions may go unrecorded.',
      remediation: 'aws cloudtrail create-trail --name org-trail --is-multi-region-trail --s3-bucket-name <bucket>, then aws cloudtrail start-logging --name org-trail',
    });
  }
}

// ─── GuardDuty ──────────────────────────────────────────────────────────

/**
 * item 3: "is threat detection on?" -- GuardDuty had no check at all
 * before. Runs per scanned region (detectors are regional, like
 * CloudTrail's home-region trails), flags any detector that exists but
 * is administratively disabled, and additionally flags the account-wide
 * absence of *any* enabled detector across every scanned region --
 * parallel to the CloudTrail "no active multi-region trail" check above.
 */
async function runGuardDutyChecks(regions, creds, reporter, log) {
  let anyEnabled = false;
  let anyDetectorSeen = false;
  await mapLimit(regions, CONCURRENCY, async (region) => {
    let detectorIds;
    try {
      detectorIds = await guardduty.listDetectorIds(region, creds);
    } catch (err) {
      log(`  [guardduty:${region}] ListDetectors failed: ${err.message}`);
      return;
    }
    log(`  [guardduty:${region}] ${detectorIds.length} detector(s) found`);
    await mapLimit(detectorIds, CONCURRENCY, async (id) => {
      anyDetectorSeen = true;
      try {
        const detector = await guardduty.getDetector(id, region, creds);
        if (detector.status === 'ENABLED') {
          anyEnabled = true;
        } else {
          reporter.add({
            provider: 'aws',
            service: 'guardduty',
            check: 'guardduty-detector-disabled',
            severity: 'medium',
            action: 'guardduty-enable-detector',
            title: 'GuardDuty detector exists but is disabled',
            resource: id,
            region,
            description: `Detector "${id}" in ${region} exists but Status="${detector.status}" — it isn't actively analyzing findings right now.`,
            remediation: `aws guardduty update-detector --detector-id ${id} --enable --region ${region}`,
          });
        }
      } catch (err) {
        log(`  [guardduty:${region}] GetDetector(${id}) failed: ${err.message}`);
      }
    });
  });

  if (!anyEnabled) {
    reporter.add({
      provider: 'aws',
      service: 'guardduty',
      check: 'guardduty-not-enabled',
      severity: 'high',
      action: 'guardduty-enable',
      title: 'GuardDuty threat detection is not enabled in any scanned region',
      resource: 'account',
      description: anyDetectorSeen
        ? 'GuardDuty detector(s) exist but none are enabled in any scanned region, so there is no automated threat detection (compromised credentials, unusual API activity, C2 traffic, etc.) currently running.'
        : 'No GuardDuty detector was found in any scanned region — threat detection has never been turned on.',
      remediation: 'aws guardduty create-detector --enable --region <region> (repeat per region, or enable via AWS Organizations delegated administration for every account/region at once).',
    });
  }
}

// ─── SNS / SQS resource policies ───────────────────────────────────────

async function runSnsChecks(regions, creds, reporter, log) {
  await mapLimit(regions, CONCURRENCY, async (region) => {
    let topicArns;
    try {
      topicArns = await sns.listTopics(region, creds);
    } catch (err) {
      log(`  [sns:${region}] ListTopics failed: ${err.message}`);
      return;
    }
    log(`  [sns:${region}] ${topicArns.length} topic(s) found`);
    await mapLimit(topicArns, CONCURRENCY, async (arn) => {
      try {
        const { policy, encrypted } = await sns.getTopicDetails(arn, region, creds);
        if (!encrypted) {
          reporter.add({
            provider: 'aws',
            service: 'sns',
            check: 'sns-topic-not-encrypted',
            severity: 'low',
            action: 'sns-enable-encryption',
            title: 'SNS topic is not encrypted at rest',
            resource: arn,
            region,
            description: 'The topic has no KmsMasterKeyId, so messages are stored unencrypted while they wait for delivery.',
            remediation: `aws sns set-topic-attributes --topic-arn ${arn} --attribute-name KmsMasterKeyId --attribute-value alias/aws/sns --region ${region}`,
          });
        }
        if (!policy) return;
        const matches = findPublicPrincipalStatements(policy);
        if (matches.length === 0) return;
        addPublicResourcePolicyFinding(reporter, {
          service: 'sns',
          check: 'sns-topic-policy-public',
          resource: arn,
          region,
          resourceLabel: 'SNS topic',
          remediation: `Review and scope the topic policy's Principal: aws sns set-topic-attributes --topic-arn ${arn} --attribute-name Policy --attribute-value file://scoped-policy.json`,
          match: worstConditionMatch(matches),
        });
      } catch (err) {
        log(`  [sns:${region}] ${arn}: GetTopicAttributes failed: ${err.message}`);
      }
    });
  });
}

async function runSqsChecks(regions, creds, reporter, log) {
  await mapLimit(regions, CONCURRENCY, async (region) => {
    let queueUrls;
    try {
      queueUrls = await sqs.listQueueUrls(region, creds);
    } catch (err) {
      log(`  [sqs:${region}] ListQueues failed: ${err.message}`);
      return;
    }
    log(`  [sqs:${region}] ${queueUrls.length} queue(s) found`);
    await mapLimit(queueUrls, CONCURRENCY, async (url) => {
      try {
        const { policy, arn, encrypted } = await sqs.getQueuePolicy(url, region, creds);
        if (!encrypted) {
          reporter.add({
            provider: 'aws',
            service: 'sqs',
            check: 'sqs-queue-not-encrypted',
            severity: 'low',
            action: 'sqs-enable-encryption',
            title: 'SQS queue is not encrypted at rest',
            resource: arn || url,
            region,
            description: 'The queue has neither a KMS key nor SQS-managed encryption (SqsManagedSseEnabled) turned on, so messages are stored unencrypted.',
            remediation: `aws sqs set-queue-attributes --queue-url ${url} --attributes SqsManagedSseEnabled=true --region ${region}`,
          });
        }
        if (!policy) return;
        const matches = findPublicPrincipalStatements(policy);
        if (matches.length === 0) return;
        addPublicResourcePolicyFinding(reporter, {
          service: 'sqs',
          check: 'sqs-queue-policy-public',
          resource: arn || url,
          region,
          resourceLabel: 'SQS queue',
          remediation: `Review and scope the queue policy's Principal: aws sqs set-queue-attributes --queue-url ${url} --attributes Policy=file://scoped-policy.json`,
          match: worstConditionMatch(matches),
        });
      } catch (err) {
        log(`  [sqs:${region}] ${url}: GetQueueAttributes failed: ${err.message}`);
      }
    });
  });
}

async function runAwsChecks({ creds, regions }, reporter, log = () => {}) {
  await runS3Checks(creds, reporter, log);
  await runEc2Checks(regions, creds, reporter, log);
  await runIamAccountChecks(creds, reporter, log);
  await runIamChecks(creds, reporter, log);
  await runRdsChecks(regions, creds, reporter, log);
  await runCloudTrailChecks(regions, creds, reporter, log);
  await runGuardDutyChecks(regions, creds, reporter, log);
  await runSnsChecks(regions, creds, reporter, log);
  await runSqsChecks(regions, creds, reporter, log);
  // Services and account-level settings the checks above don't cover (Lambda, KMS,
  // Config, load balancers, EFS, Redshift, public snapshots/AMIs, S3 account settings).
  await runAwsExtendedChecks({ creds, regions }, reporter, log);
}

export { runAwsChecks };
