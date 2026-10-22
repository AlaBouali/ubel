'use strict';
// Mobile dependency inventory + OSV lookup. Uses the same OSV query/enrichment
// implementation as UBEL SCA; no separate HTTP client or third-party package.

import { submitToOsv, getVulnById } from '../../sca/engine.js';

const MAX_METADATA_BYTES = 8 * 1024 * 1024;
const MAX_DEPENDENCIES = 5000;
const OSV_DETAIL_CONCURRENCY = 40;

// Android libraries sometimes expose their exact version in META-INF/<name>.version
// without retaining Maven's pom.properties. Known aliases and Maven-style group_artifact
// markers are queried; unidentifiable metadata labels remain inventory-only evidence.
const ANDROID_VERSION_COORDINATES = new Map([
  ['okhttp3', ['com.squareup.okhttp3', 'okhttp', 'OkHttp']],
  ['okhttp', ['com.squareup.okhttp3', 'okhttp', 'OkHttp']],
  ['okio', ['com.squareup.okio', 'okio', 'Okio']],
  ['retrofit', ['com.squareup.retrofit2', 'retrofit', 'Retrofit']],
  ['retrofit2', ['com.squareup.retrofit2', 'retrofit', 'Retrofit']],
  ['gson', ['com.google.code.gson', 'gson', 'Gson']],
  ['moshi', ['com.squareup.moshi', 'moshi', 'Moshi']],
  ['guava', ['com.google.guava', 'guava', 'Guava']],
  ['kotlinx_coroutines_core', ['org.jetbrains.kotlinx', 'kotlinx-coroutines-core', 'Kotlinx Coroutines Core']],
  ['kotlinx_coroutines_android', ['org.jetbrains.kotlinx', 'kotlinx-coroutines-android', 'Kotlinx Coroutines Android']],
  ['kotlinx_coroutines_jdk8', ['org.jetbrains.kotlinx', 'kotlinx-coroutines-jdk8', 'Kotlinx Coroutines JDK 8']],
  ['kotlinx_serialization_core', ['org.jetbrains.kotlinx', 'kotlinx-serialization-core', 'Kotlin Serialization Core']],
  ['kotlinx_serialization_json', ['org.jetbrains.kotlinx', 'kotlinx-serialization-json', 'Kotlin Serialization JSON']],
  ['protobuf', ['com.google.protobuf', 'protobuf-javalite', 'Protocol Buffers Java Lite']],
  ['protobuf-java', ['com.google.protobuf', 'protobuf-java', 'Protocol Buffers Java']],
  ['zxing', ['com.google.zxing', 'core', 'ZXing Core']],
]);

// META-INF/*.version names commonly encode Maven coordinates as <groupId>_<artifactId>.
// Normalize aliases consistently (e.g. protobuf-java), then parse the coordinate form.
const ANDROID_VERSION_COORDINATES_NORMALIZED = new Map(
  [...ANDROID_VERSION_COORDINATES.entries()].map(([key, value]) => [key.toLowerCase().replace(/[.-]/g, '_'), value]),
);

function mavenCoordinateFromVersionMarker(fileKey) {
  const normalized = String(fileKey || '').trim().toLowerCase();
  const known = ANDROID_VERSION_COORDINATES_NORMALIZED.get(normalized.replace(/[.-]/g, '_'));
  if (known) return { group: known[0], artifact: known[1], confidence: 'high' };

  const separator = normalized.lastIndexOf('_');
  if (separator <= 0 || separator >= normalized.length - 1) return null;
  const group = normalized.slice(0, separator);
  const artifact = normalized.slice(separator + 1);
  // Avoid treating arbitrary metadata labels as Maven coordinates. Require a dotted
  // group ID and valid coordinate characters; inferred coordinates carry medium confidence.
  if (!/^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/.test(group)) return null;
  if (!/^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$/.test(artifact) || /\.\.|__|--/.test(artifact)) return null;
  return { group, artifact, confidence: 'medium' };
}

const ANDROID_CLASS_COMPONENTS = [
  { re: /^(?:L)?okhttp3\./i, coordinate: 'com.squareup.okhttp3:okhttp', name: 'OkHttp', ecosystem: 'Maven' },
  { re: /^(?:L)?okio\./i, coordinate: 'com.squareup.okio:okio', name: 'Okio', ecosystem: 'Maven' },
  { re: /^(?:L)?com\.google\.gson\./i, coordinate: 'com.google.code.gson:gson', name: 'Gson', ecosystem: 'Maven' },
  { re: /^(?:L)?com\.squareup\.retrofit2\./i, coordinate: 'com.squareup.retrofit2:retrofit', name: 'Retrofit', ecosystem: 'Maven' },
  { re: /^(?:L)?com\.squareup\.moshi\./i, coordinate: 'com.squareup.moshi:moshi', name: 'Moshi', ecosystem: 'Maven' },
  { re: /^(?:L)?kotlinx\.coroutines\./i, coordinate: 'org.jetbrains.kotlinx:kotlinx-coroutines-core', name: 'Kotlinx Coroutines Core', ecosystem: 'Maven' },
  { re: /^(?:L)?com\.facebook\.react\./i, coordinate: 'com.facebook.react:react-android', name: 'React Native Android', ecosystem: 'Maven' },
  { re: /^(?:L)?com\.google\.firebase\./i, coordinate: null, name: 'Firebase Android SDK', ecosystem: 'Maven' },
  { re: /^(?:L)?com\.google\.android\.gms\./i, coordinate: null, name: 'Google Play Services', ecosystem: 'Maven' },
  { re: /^(?:L)?androidx\./i, coordinate: null, name: 'AndroidX libraries', ecosystem: 'Maven' },
  { re: /^(?:L)?org\.bouncycastle\./i, coordinate: null, name: 'Bouncy Castle', ecosystem: 'Maven' },
  { re: /^(?:L)?org\.apache\.commons\./i, coordinate: null, name: 'Apache Commons libraries', ecosystem: 'Maven' },
  { re: /^(?:L)?io\.grpc\./i, coordinate: null, name: 'gRPC Java', ecosystem: 'Maven' },
  { re: /^(?:L)?com\.google\.protobuf\./i, coordinate: null, name: 'Protocol Buffers Java', ecosystem: 'Maven' },
  { re: /^(?:L)?io\.sentry\./i, coordinate: 'io.sentry:sentry-android', name: 'Sentry Android', ecosystem: 'Maven' },
  { re: /^(?:L)?com\.bugsnag\.android\./i, coordinate: 'com.bugsnag:bugsnag-android', name: 'Bugsnag Android', ecosystem: 'Maven' },
];

function isUsableVersion(value) {
  const v = String(value ?? '').trim();
  return !!v && v.length < 128 && !/\s/.test(v) && !/^\$\{.*\}$/.test(v) && !/^(?:unknown|null|unspecified|latest|version)$/i.test(v);
}

function encodePurlPart(value) {
  return encodeURIComponent(String(value)).replace(/[!'()*]/g, c => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

function mavenPurl(groupId, artifactId, version) {
  if (!groupId || !artifactId || !isUsableVersion(version)) return null;
  return `pkg:maven/${String(groupId).trim().toLowerCase()}/${String(artifactId).trim().toLowerCase()}@${encodePurlPart(String(version).trim())}`;
}

function normaliseName(value) {
  return String(value ?? '').trim().toLowerCase().replace(/\\/g, '/').replace(/\s+/g, ' ');
}

function parseProperties(text) {
  const out = {};
  for (const line of String(text || '').split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith('#') || t.startsWith('!')) continue;
    const m = /^([^:=\s]+)\s*[:=]\s*(.*)$/.exec(t);
    if (m) out[m[1].trim()] = m[2].trim();
  }
  return out;
}

function normalizeSwiftRepo(url) {
  if (!url || typeof url !== 'string') return null;
  let u = url.trim();
  if (!u || /^(?:file:|\/|\.{1,2}\/|~)/i.test(u) || /^[a-z]:[\\/]/i.test(u)) return null;
  const scp = u.match(/^(?:[\w.-]+@)?([\w.-]+):(?!\/\/)(.+)$/);
  if (scp && !/^[a-z][a-z0-9+.-]*:\/\//i.test(u)) u = `${scp[1]}/${scp[2]}`;
  else {
    u = u.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
    u = u.replace(/^[^@/]+@/, '');
    u = u.replace(/^([^/:]+):\d+\//, '$1/');
  }
  u = u.replace(/\/+$/, '').replace(/\.git$/i, '');
  const slash = u.indexOf('/');
  if (slash <= 0 || slash === u.length - 1) return null;
  return u.slice(0, slash).toLowerCase() + u.slice(slash);
}

function swiftVersion(value) {
  const s = String(value ?? '').trim();
  if (!s || /^[0-9a-f]{40}$/i.test(s) || /\s/.test(s) || /\$\{/.test(s)) return null;
  const cleaned = s.replace(/^[vV](?=\d)/, '');
  return /^\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?$/.test(cleaned) ? cleaned : null;
}

function swiftPurl(hostPath, version) {
  if (!hostPath || !version) return null;
  return `pkg:swift/${hostPath.split('/').map(encodePurlPart).join('/')}@${encodePurlPart(version)}`;
}

function depRecord({ name, version = null, ecosystem = 'Unknown', purl = null, coordinate = null, platform = 'unknown', source, source_type, confidence = 'medium', identity = null, reason = null }) {
  return {
    name: String(name || coordinate || 'Unknown dependency'),
    version: isUsableVersion(version) ? String(version).trim() : null,
    ecosystem,
    purl,
    coordinate: coordinate || null,
    platform,
    sources: source ? [source] : [],
    source_types: source_type ? [source_type] : [],
    confidence,
    identity: identity || null,
    lookup_status: purl ? 'pending' : 'not_queryable',
    lookup_reason: reason || (purl ? null : 'Package identity and an exact version/PURL could not be established from the app package.'),
    vulnerabilities: [],
    vulnerability_count: 0,
  };
}

function mergeRecord(old, item) {
  if (!old.purl && item.purl) old.purl = item.purl;
  if (!old.version && item.version) old.version = item.version;
  if (!old.coordinate && item.coordinate) old.coordinate = item.coordinate;
  if (item.purl) old.lookup_reason = null;
  if (item.confidence === 'high' || (item.confidence === 'medium' && old.confidence === 'low')) old.confidence = item.confidence;
  for (const src of item.sources || []) if (src && !old.sources.includes(src)) old.sources.push(src);
  for (const src of item.source_types || []) if (src && !old.source_types.includes(src)) old.source_types.push(src);
  if (old.name === 'Unknown dependency' && item.name) old.name = item.name;
}

function mergeDependencies(items) {
  const map = new Map();
  const coordinateBase = item => `${item.platform}:${item.ecosystem}:coord:${normaliseName(item.coordinate)}`;
  for (const item of items) {
    if (!item) continue;
    const base = item.coordinate ? coordinateBase(item) : null;
    // Preserve simultaneous versions of the same coordinate (possible in split APKs).
    // An unversioned DEX namespace is merged with a versioned record below only when that
    // coordinate has exactly one candidate version; otherwise its version remains unknown.
    const key = base
      ? `${base}${item.version ? `@${normaliseName(item.version)}` : ''}`
      : item.purl
        ? `${item.platform}:purl:${item.purl.toLowerCase()}`
        : `${item.platform}:${normaliseName(item.name)}:${normaliseName(item.version || '')}`;
    const old = map.get(key);
    if (!old) { map.set(key, item); continue; }
    mergeRecord(old, item);
  }

  for (const [key, item] of [...map.entries()]) {
    if (!item.coordinate || item.version || item.purl) continue;
    const base = coordinateBase(item);
    const candidates = [...map.entries()].filter(([candidateKey, candidate]) => candidateKey.startsWith(`${base}@`) && candidate.version && candidate.purl);
    if (candidates.length === 1) {
      mergeRecord(candidates[0][1], item);
      map.delete(key);
    }
  }
  return [...map.values()].slice(0, MAX_DEPENDENCIES).sort((a, b) => a.name.localeCompare(b.name) || String(a.version || '').localeCompare(String(b.version || '')));
}

function parseAndroidMetadata(zip, platform, prefix, out, appSummary) {
  for (const entry of zip.find(/^META-INF\/maven\/[^/]+\/[^/]+\/pom\.properties$/i).slice(0, 2000)) {
    const buf = zip.tryRead(entry, 64 * 1024);
    if (!buf) continue;
    const props = parseProperties(buf.toString('utf8'));
    const pathParts = entry.name.split('/');
    const pathGroup = pathParts.length >= 5 ? pathParts[pathParts.length - 3] : '';
    const pathArtifact = pathParts.length >= 5 ? pathParts[pathParts.length - 2] : '';
    const group = props.groupId && !props.groupId.startsWith('$') ? props.groupId : pathGroup;
    const artifact = props.artifactId && !props.artifactId.startsWith('$') ? props.artifactId : pathArtifact;
    const version = props.version;
    if (!group || !artifact) continue;
    const purl = mavenPurl(group, artifact, version);
    out.push(depRecord({
      name: `${group}:${artifact}`, version, ecosystem: 'Maven', purl,
      coordinate: `${group}:${artifact}`, platform, source: `${prefix}${entry.name}`,
      source_type: 'Maven pom.properties', confidence: purl ? 'high' : 'medium',
      reason: purl ? null : 'Maven coordinates were found, but the packaged metadata did not expose a usable exact version.',
    }));
  }

  for (const entry of zip.find(/^META-INF\/[^/]+\.version$/i).slice(0, 1000)) {
    const buf = zip.tryRead(entry, 4096);
    if (!buf) continue;
    const version = buf.toString('utf8').trim().split(/\s+/)[0];
    if (!isUsableVersion(version)) continue;
    const fileKey = entry.name.replace(/^META-INF\//i, '').replace(/\.version$/i, '').toLowerCase().replace(/[^a-z0-9._-]/g, '_');
    const coordinate = mavenCoordinateFromVersionMarker(fileKey);
    if (coordinate) {
      const { group, artifact, confidence } = coordinate;
      const purl = mavenPurl(group, artifact, version);
      out.push(depRecord({
        name: `${group}:${artifact}`, version, ecosystem: 'Maven', purl,
        coordinate: `${group}:${artifact}`, platform, source: `${prefix}${entry.name}`,
        source_type: coordinate.confidence === 'high' ? 'META-INF version file' : 'META-INF version file (Maven coordinate inferred)',
        confidence,
        reason: purl ? null : 'Maven coordinates were inferred, but the version marker did not expose a usable exact version.',
      }));
    } else {
      out.push(depRecord({ name: fileKey, version, ecosystem: 'Android metadata', platform, source: `${prefix}${entry.name}`, source_type: 'META-INF version file', confidence: 'low', reason: 'A version marker exists, but its package coordinates are not known, so it was not sent to OSV.' }));
    }
  }

  // DEX namespace evidence is useful when no version metadata exists. If package
  // metadata recovered concrete members of a broad family, omit the umbrella row so it
  // does not masquerade as one additional dependency.
  const broadFamilies = new Map([
    ['AndroidX libraries', 'androidx.'],
    ['Firebase Android SDK', 'com.google.firebase:'],
    ['Google Play Services', 'com.google.android.gms:'],
    ['Bouncy Castle', 'org.bouncycastle:'],
    ['Apache Commons libraries', 'org.apache.commons:'],
    ['gRPC Java', 'io.grpc:'],
    ['Protocol Buffers Java', 'com.google.protobuf:'],
  ]);
  for (const detected of appSummary?._detected_dependencies || []) {
    const familyPrefix = !detected.coordinate ? broadFamilies.get(detected.name) : null;
    if (familyPrefix && out.some(item => item.coordinate && item.coordinate.toLowerCase().startsWith(familyPrefix))) continue;
    out.push(depRecord({ ...detected, platform, source: `${prefix}${detected.source || 'DEX class namespace'}`, source_type: 'DEX class namespace', confidence: 'medium' }));
  }
}

function parseSwiftResolved(zip, platform, prefix, out) {
  for (const entry of zip.find(/(?:^|\/)Package\.resolved$/i).slice(0, 100)) {
    const buf = zip.tryRead(entry, MAX_METADATA_BYTES);
    if (!buf) continue;
    let doc;
    try { doc = JSON.parse(buf.toString('utf8')); } catch { continue; }
    const pins = Array.isArray(doc?.pins) ? doc.pins : Array.isArray(doc?.object?.pins) ? doc.object.pins : [];
    for (const pin of pins) {
      const kind = pin.kind || 'remoteSourceControl';
      if (kind === 'fileSystem' || kind === 'localSourceControl') continue;
      const url = pin.location || pin.repositoryURL || pin.packageURL || '';
      let hostPath = null;
      if (kind === 'registry' && pin.identity) {
        const [scope, ...rest] = String(pin.identity).split('.');
        if (scope && rest.length) hostPath = `${scope}/${rest.join('.')}`;
      } else hostPath = normalizeSwiftRepo(url);
      if (!hostPath) continue;
      const version = swiftVersion(pin.state?.version || pin.version);
      const purl = swiftPurl(hostPath, version);
      out.push(depRecord({
        name: hostPath, version, ecosystem: 'SwiftURL', purl,
        coordinate: `swift:${hostPath}`, platform, source: `${prefix}${entry.name}`,
        source_type: 'Swift Package.resolved', confidence: purl ? 'high' : 'medium',
        reason: purl ? null : 'The Swift package was pinned to a branch/revision or has no exact release version; OSV version matching was skipped.',
      }));
    }
  }
}

function parseCocoaPodsLock(zip, platform, prefix, out) {
  // CocoaPods has no OSV ecosystem in UBEL's shared engine. Include exact Podfile.lock
  // records when present, but never claim they were checked against an incompatible DB.
  for (const entry of zip.find(/(?:^|\/)Podfile\.lock$/i).slice(0, 50)) {
    const buf = zip.tryRead(entry, MAX_METADATA_BYTES);
    if (!buf) continue;
    const text = buf.toString('utf8');
    const podsPart = text.split(/^DEPENDENCIES:\s*$/m)[0].split(/^PODS:\s*$/m)[1] || '';
    for (const m of podsPart.matchAll(/^  - ([^\s(]+) \(([^)]+)\)\s*$/gm)) {
      const name = m[1], version = m[2];
      out.push(depRecord({ name, version, ecosystem: 'CocoaPods', platform, source: `${prefix}${entry.name}`, source_type: 'Podfile.lock', confidence: 'high', reason: 'UBEL’s shared OSV engine has no CocoaPods ecosystem mapping; the dependency is inventoried but not queried.' }));
      if (out.length >= MAX_DEPENDENCIES) return;
    }
  }
}

/** Extracts candidate third-party components from an APK/IPA ZIP. No network is used here. */
export function extractMobileDependencies(zip, { platform = 'unknown', prefix = '', appSummary = null } = {}) {
  const out = [];
  if (platform === 'android') {
    parseAndroidMetadata(zip, platform, prefix, out, appSummary);
  } else if (platform === 'ios') {
    parseSwiftResolved(zip, platform, prefix, out);
    parseCocoaPodsLock(zip, platform, prefix, out);
  }
  return mergeDependencies(out);
}

function minimalVulnerability(v) {
  return {
    id: v.id || v.vulnerability_id || 'Unknown advisory',
    summary: v.summary || v.title || '',
    details: v.details || '',
    aliases: Array.isArray(v.aliases) ? v.aliases : [],
    severity: String(v.severity || 'unknown').toLowerCase(),
    severity_score: v.severity_score == null ? null : Number(v.severity_score),
    severity_vector: v.severity_vector || null,
    published: v.published || null,
    modified: v.modified || null,
    url: v.url || (v.id ? `https://osv.dev/vulnerability/${encodeURIComponent(v.id)}` : null),
    fixed_versions: Array.isArray(v.fixed_versions) ? v.fixed_versions : [],
    has_fix: Boolean(v.has_fix),
    affected_package_id: v.affected_package_id || null,
    affected_dependency_version: v.affected_dependency_version || null,
    is_infection: Boolean(v.is_infection || String(v.id || '').startsWith('MAL-')),
  };
}

function isNativeDependency(component) {
  const ecosystem = String(component?.ecosystem || '').toLowerCase();
  const rawTypes = component?.source_type || (Array.isArray(component?.source_types) ? component.source_types.join(' ') : component?.source_types) || '';
  const sourceType = String(rawTypes).toLowerCase();
  const sourceEvidence = [component?.source, ...(Array.isArray(component?.sources) ? component.sources : [])].filter(Boolean).join(' ');
  const isNativePath = value => /(?:^|[\/!])[^\/!]+\.(?:so|dylib)$/i.test(value)
    || /(?:^|[\/!])[^\/!]+\.framework(?:[\/!]|$)/i.test(value);
  return ecosystem.includes('native library') || ecosystem === 'ios framework'
    || /(?:elf library path|embedded dylib|embedded framework)/.test(sourceType)
    || isNativePath(String(component?.name || '')) || isNativePath(sourceEvidence);
}

/** Query exact, versioned PURLs through UBEL's shared engine and enrich OSV advisory IDs. */
export async function scanMobileDependencies(components, { log = () => {} } = {}) {
  // Native binaries/frameworks are intentionally outside mobile SCA scope. Their
  // hardening and secret checks remain in the static analyzer, but they are not sent to OSV.
  const dependencies = mergeDependencies((components || []).filter(c => !isNativeDependency(c)).map(c => ({
    ...c,
    sources: Array.isArray(c.sources) ? [...c.sources] : (c.source ? [c.source] : []),
    source_types: Array.isArray(c.source_types) ? [...c.source_types] : (c.source_type ? [c.source_type] : []),
    vulnerabilities: [], vulnerability_count: 0,
  })));
  const purlToDependencies = new Map();
  for (const dep of dependencies) {
    dep.vulnerabilities = [];
    dep.vulnerability_count = 0;
    dep.lookup_status = dep.purl && isUsableVersion(dep.version) ? 'pending' : 'not_queryable';
    if (!dep.purl || !isUsableVersion(dep.version)) {
      dep.lookup_reason ||= 'OSV queries require a supported package identity and exact version; this package only exposed partial metadata.';
      continue;
    }
    if (!purlToDependencies.has(dep.purl)) purlToDependencies.set(dep.purl, []);
    purlToDependencies.get(dep.purl).push(dep);
  }

  const purls = [...purlToDependencies.keys()];
  const markError = (targets, status, message) => {
    for (const dep of targets) {
      dep.lookup_status = status;
      dep.lookup_error = String(message || 'OSV lookup failed').slice(0, 500);
      dep.lookup_reason = 'The dependency could not be conclusively checked against OSV.dev during this scan.';
    }
  };
  if (!purls.length) {
    for (const dep of dependencies) if (dep.lookup_status === 'not_queryable') dep.lookup_reason ||= 'No supported versioned package URL was extracted; no OSV request was made for this component.';
    return { dependencies, summary: summarise(dependencies), lookup_error: null };
  }

  log(`[*] Querying OSV.dev for ${purls.length} versioned mobile dependency PURL(s)...`);
  let advisoryIds;
  try {
    advisoryIds = await submitToOsv(purls);
  } catch (err) {
    const targets = dependencies.filter(d => d.lookup_status === 'pending');
    markError(targets, 'lookup_error', err?.message || err);
    return { dependencies, summary: summarise(dependencies), lookup_error: String(err?.message || err).slice(0, 500) };
  }

  for (let i = 0; i < advisoryIds.length; i += OSV_DETAIL_CONCURRENCY) {
    const batch = advisoryIds.slice(i, i + OSV_DETAIL_CONCURRENCY);
    const settled = await Promise.allSettled(batch.map(item => getVulnById(item)));
    for (let j = 0; j < settled.length; j++) {
      const targetItem = batch[j];
      const targetDeps = purlToDependencies.get(targetItem.purl) || [];
      const item = settled[j];
      if (item.status === 'rejected') {
        markError(targetDeps, 'lookup_incomplete', item.reason?.message || 'OSV advisory details could not be fetched');
        log(`[!] OSV advisory details unavailable for ${targetItem.purl}: ${item.reason?.message || 'unknown error'}`);
        continue;
      }
      if (!item.value) continue;
      const vuln = minimalVulnerability(item.value);
      for (const dep of targetDeps) {
        if (!dep.vulnerabilities.some(v => v.id === vuln.id)) dep.vulnerabilities.push(vuln);
      }
    }
  }

  for (const dep of dependencies) {
    dep.vulnerabilities.sort((a, b) => {
      const rank = { critical: 0, high: 1, medium: 2, moderate: 2, low: 3, info: 4, unknown: 5 };
      return (rank[a.severity] ?? 5) - (rank[b.severity] ?? 5) || String(a.id).localeCompare(String(b.id));
    });
    dep.vulnerability_count = dep.vulnerabilities.length;
    if (dep.lookup_status === 'lookup_incomplete' || dep.lookup_status === 'lookup_error') continue;
    dep.lookup_status = dep.vulnerability_count ? 'vulnerable' : 'clean';
    dep.lookup_reason = dep.vulnerability_count ? null : 'OSV.dev returned Safe for this exact PURL and version at scan time.';
  }
  return { dependencies, summary: summarise(dependencies), lookup_error: null };
}

function summarise(dependencies) {
  const summary = {
    total: dependencies.length,
    queryable: 0,
    vulnerable_dependencies: 0,
    vulnerabilities: 0,
    clean_dependencies: 0,
    not_queryable: 0,
    lookup_errors: 0,
    by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 },
  };
  for (const dep of dependencies) {
    if (dep.purl && isUsableVersion(dep.version)) summary.queryable++;
    if (dep.lookup_status === 'vulnerable') summary.vulnerable_dependencies++;
    else if (dep.lookup_status === 'clean') summary.clean_dependencies++;
    else if (dep.lookup_status === 'not_queryable') summary.not_queryable++;
    else if (dep.lookup_status === 'lookup_error' || dep.lookup_status === 'lookup_incomplete') summary.lookup_errors++;
    summary.vulnerabilities += dep.vulnerability_count || 0;
    for (const v of dep.vulnerabilities || []) {
      const sev = String(v.severity || 'unknown').toLowerCase();
      const key = sev === 'moderate' ? 'medium' : Object.hasOwn(summary.by_severity, sev) ? sev : 'unknown';
      summary.by_severity[key]++;
    }
  }
  return summary;
}
