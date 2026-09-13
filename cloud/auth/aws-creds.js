'use strict';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { parseIni } from '../lib/ini.js';

function readIniFile(p) {
  if (!fs.existsSync(p)) return {};
  return parseIni(fs.readFileSync(p, 'utf8'));
}

function credsFilePath() {
  return process.env.AWS_SHARED_CREDENTIALS_FILE || path.join(os.homedir(), '.aws', 'credentials');
}
function configFilePath() {
  return process.env.AWS_CONFIG_FILE || path.join(os.homedir(), '.aws', 'config');
}

/**
 * Resolve one profile's credentials, following role_arn/source_profile
 * chains recursively (item 8: this used to not exist at all — a profile
 * with an assumed role would just silently fail static-key lookup).
 * `credentials` and `config` are the parsed ~/.aws/{credentials,config}
 * files (parseIni already strips the "profile " prefix `~/.aws/config`
 * uses on non-default sections, so both files key by plain profile name).
 */
async function resolveProfileCredentials(profileName, credentials, config, seen = new Set()) {
  if (seen.has(profileName)) {
    throw new Error(`Circular source_profile chain detected involving profile "${profileName}"`);
  }
  seen.add(profileName);

  // config-file values (role_arn, source_profile, region) are overlaid
  // with credentials-file values (static keys take precedence there,
  // matching the AWS CLI's own file precedence for secrets).
  const merged = { ...(config[profileName] || {}), ...(credentials[profileName] || {}) };

  if (merged.aws_access_key_id && merged.aws_secret_access_key) {
    return {
      accessKeyId: merged.aws_access_key_id,
      secretAccessKey: merged.aws_secret_access_key,
      sessionToken: merged.aws_session_token || undefined,
    };
  }

  if (merged.role_arn) {
    if (!merged.source_profile) {
      // credential_source (Ec2InstanceMetadata/EcsContainer/Environment)
      // is a separate, less common mechanism for supplying the *base*
      // credentials behind a role and isn't implemented here — only the
      // source_profile form is.
      throw new Error(
        `Profile "${profileName}" has role_arn but no source_profile (credential_source is not supported)`
      );
    }
    const { assumeRole } = require ('./aws-sts'); // lazy require: avoids a require cycle at module-load time
    const baseCreds = await resolveProfileCredentials(merged.source_profile, credentials, config, seen);
    return assumeRole(
      {
        roleArn: merged.role_arn,
        roleSessionName: merged.role_session_name,
        externalId: merged.external_id,
        durationSeconds: merged.duration_seconds ? Number(merged.duration_seconds) : undefined,
      },
      baseCreds
    );
  }

  throw new Error(`Profile "${profileName}" has neither static keys nor a role_arn`);
}

/**
 * Resolve AWS credentials:
 *   1. AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN env vars
 *   2. [profile] in ~/.aws/credentials or ~/.aws/config (AWS_PROFILE env
 *      var, default "default"), including role_arn + source_profile
 *      chains resolved via STS AssumeRole (item 8)
 */
async function loadAwsCredentials() {
  if (process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY) {
    return {
      accessKeyId: process.env.AWS_ACCESS_KEY_ID,
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
      sessionToken: process.env.AWS_SESSION_TOKEN || undefined,
    };
  }

  const profile = process.env.AWS_PROFILE || 'default';
  const credentials = readIniFile(credsFilePath());
  const config = readIniFile(configFilePath());

  if (!credentials[profile] && !config[profile]) {
    throw new Error(
      `No AWS credentials found. Set AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY, or configure profile "${profile}" in ~/.aws/credentials or ~/.aws/config.`
    );
  }
  return resolveProfileCredentials(profile, credentials, config);
}

/**
 * Region resolution precedence (highest first):
 *   1. --regions CLI flag           (explicit override, handled by the caller)
 *   2. AWS_REGIONS / AWS_REGION / AWS_DEFAULT_REGION env vars
 *   3. `region` in the active ~/.aws/config profile
 *   4. DescribeRegions() auto-discovery of enabled regions (caller's fallback)
 *
 * Resolves tiers 2-3 and reports `null` when nothing is set, so the
 * caller (src/index.js) knows to fall through to auto-discovery instead
 * of silently defaulting to a single hardcoded region.
 */
function loadAwsRegionsFromEnv() {
  if (process.env.AWS_REGIONS) {
    const regions = process.env.AWS_REGIONS.split(',').map((r) => r.trim()).filter(Boolean);
    return regions.length ? regions : null;
  }
  const envRegion = process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION;
  if (envRegion) return [envRegion];

  // item 8: ~/.aws/config was documented as a fallback but never
  // actually read for this.
  const profile = process.env.AWS_PROFILE || 'default';
  const config = readIniFile(configFilePath());
  const configRegion = config[profile]?.region;
  return configRegion ? [configRegion] : null;
}

export { loadAwsCredentials, loadAwsRegionsFromEnv, resolveProfileCredentials };
