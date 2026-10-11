// sbom_builder.js — CycloneDX 1.6 SBOM generator (Node.js port of Python version)

import { randomUUID } from "crypto";
import { TOOL_NAME, TOOL_VERSION } from "./info.js";
import { vexAnalysis } from "./vex.js";
import { isNoLicenseValue } from "./license_checker.js";
import { cvssMethodFromVector } from "./cvss_parser.js";

/**
 * Convert UBEL final JSON into a CycloneDX 1.6 SBOM document.
 */
export class CycloneDXBuilder {
  constructor(finalJson) {
    this.data = finalJson;
    this.CYCLONEDX_VERSION = "1.6";
  }

  /** Map severity to CDX severity string. */
  _severityToCdx(sev) {
    const m = { critical: "critical", high: "high", medium: "medium", low: "low" };
    return m[String(sev).toLowerCase()] || "unknown";
  }

  /** Normalise CVSS method to CycloneDX accepted values. */
  _normaliseCvssMethod(method, vector) {
    // cvss_method is set by cvss_parser.js, but records from older reports may lack it; the
    // vector string states its own version ("CVSS:3.1/AV:N/…"), so fall back to that.
    if (!method) method = cvssMethodFromVector(vector);
    if (!method) return "other";
    // Accept "CVSSv3.1", "CVSS_V3", "CVSS:3.1", "cvss31", … alike.
    let m = String(method).replace(/[^A-Za-z0-9]/g, "").toUpperCase().replace(/^CVSSV/, "CVSS");
    if (m.includes("CVSS2")) return "CVSSv2";
    if (m.includes("CVSS31")) return "CVSSv31";
    if (m.includes("CVSS3")) return "CVSSv3";
    if (m.includes("CVSS40")) return "CVSSv4";
    if (m.includes("CVSS4")) return "CVSSv4";
    if (m.includes("SSVC")) return "SSVC";
    return "other";
  }

  /** Suggested fix entry ({version, count}) covering vulnerability `v`, if any. */
  _suggestedFixFor(v) {
    if (!this._invById) {
      this._invById = new Map((this.data.inventory || []).map(i => [i.id, i]));
    }
    const sf = this._invById.get(v.affected_package_id)?.suggested_fixes;
    if (!sf || !Array.isArray(sf.fixes)) return null;
    const hit = sf.fixes.find(f => (f.vulnerabilities || []).some(x => x.id === v.id));
    return hit ? { version: hit.version, count: hit.count } : null;
  }

  /**
   * KEV / EPSS as flat CycloneDX properties. Nothing is emitted when the
   * enrichment never ran; a null (feed unavailable) is written as "unknown"
   * so it is not mistaken for "not listed" / zero.
   */
  _threatIntelProps(v) {
    if (v.is_kev === undefined && v.epss_score === undefined) return [];
    const out = [];
    out.push({ name: "kev.listed", value: v.is_kev === true ? "true" : v.is_kev === false ? "false" : "unknown" });
    if (v.is_kev === true) {
      if (v.kev_added)    out.push({ name: "kev.date_added", value: String(v.kev_added) });
      if (v.kev_deadline) out.push({ name: "kev.due_date",   value: String(v.kev_deadline) });
    }
    if (typeof v.epss_score === "number") {
      out.push({ name: "epss.score", value: String(v.epss_score) });
      if (typeof v.epss_percentile === "number") out.push({ name: "epss.percentile", value: String(v.epss_percentile) });
    } else {
      out.push({ name: "epss.score", value: "unknown" });
    }
    return out;
  }

  /** Build properties array from selected keys. */
  _props(record, keys) {
    const out = [];
    for (const k of keys) {
      if (record[k] !== undefined && record[k] !== null) {
        if (typeof record[k] === "string") {
          out.push({ name: k, value: record[k] });
        } else {
          out.push({ name: k, value: JSON.stringify(record[k]) });
        }
      }
    }
    return out;
  }

  /** Build metadata section. */
  buildMetadata() {
    const toolInfo = this.data.tool_info || {};
    const scanInfo = this.data.scan_info || {};
    const git = this.data.git_metadata || {};
    const runtime = this.data.runtime || {};

    const scanType = scanInfo.type || "health";
    let lifecycle = [];
    /* if (scanType === "health") lifecycle = [{ phase: "operations" }];
    else if (scanType === "check" || scanType === "install") lifecycle = [{ phase: "pre-build" }];
    else lifecycle = [{ phase: "pre-build" }]; */

    return {
      timestamp: this.data.generated_at || new Date().toISOString().replace(/\.\d+Z$/, "Z"),
      tools: [{
        vendor: "Arcane-Spark",
        name: toolInfo.name || TOOL_NAME,
        version: toolInfo.version || TOOL_VERSION,
      }],
      //lifecycles: lifecycle,
      properties: [
        { name: "report_id", value: String(scanInfo.report_id || "") },
        { name: "asset_id", value: String(scanInfo.asset_id || "") },
        { name: "asset_name", value: String(scanInfo.asset_name || "") },
        { name: "asset_type", value: String(scanInfo.asset_type || "") },
        { name: "scan_type", value: scanType },
        { name: "scan_scope", value: scanInfo.scan_scope || "repository" },
        { name: "engine", value: scanInfo.engine || "" },
        { name: "ecosystems", value: JSON.stringify(scanInfo.ecosystems || []) },
        { name: "runtime_env", value: runtime.environment || "" },
        { name: "runtime_ver", value: runtime.version || "" },
        { name: "platform", value: runtime.platform || "" },
        { name: "arch", value: runtime.arch || "" },
        { name: "cwd", value: runtime.cwd || "" },
        { name: "git_branch", value: String(git.branch || "") },
        { name: "git_commit", value: String(git.latest_commit || "") },
        { name: "git_url", value: String(git.url || "") },
      ],
    };
  }

  /**
   * Build the CycloneDX `licenses` array for a component.
   *
   * Prefers the normalized classification from `license_info` (see
   * license_checker.js): a single SPDX id or a full boolean expression
   * ("MIT OR Apache-2.0") is emitted via the `expression` form, which
   * CycloneDX accepts for both a bare id and a compound expression alike.
   * Falls back to the raw, unparsed license string as free-text `license.name`
   * when license_info couldn't resolve a usable SPDX id (e.g. inline license
   * text, or a genuinely missing/"unknown" value with nothing to carry).
   */
  _buildLicenses(item) {
    const info = item.license_info;
    if (info && info.spdx) {
      return [{ expression: info.spdx }];
    }
    // "unknown" / "none" / "n/a" placeholders mean no license information was found — they are
    // not a license name, so nothing is emitted (the component simply has no `licenses`).
    if (isNoLicenseValue(item.license) || (info && info.category === "none")) {
      return [];
    }
    if (item.license && typeof item.license === "string" && item.license.trim()) {
      return [{ license: { name: item.license.trim() } }];
    }
    return [];
  }

  /** Build components from inventory. */
  buildComponents() {
    const components = [];
    for (const item of this.data.inventory || []) {
    const purl = item.id || "";
      const cpe = item.cpe || "";
      const comp = {
        "bom-ref": purl,
        type: item.type || "library",
        name: item.name || "",
        purl: purl,
      };
      // A component whose version could not be determined carries no `version` rather than "".
      if (item.version) comp.version = item.version;
      const licenses = this._buildLicenses(item);
      if (licenses.length) comp.licenses = licenses;
      if (cpe) comp.cpe = cpe;
      // Hashes the lockfile recorded for the artifact ({alg, content} pairs, see item.hashes).
      if (Array.isArray(item.hashes) && item.hashes.length) {
        comp.hashes = item.hashes
          .filter(h => h && h.alg && /^[0-9a-f]+$/i.test(String(h.content || "")))
          .map(h => ({ alg: h.alg, content: String(h.content).toLowerCase() }));
        if (!comp.hashes.length) delete comp.hashes;
      }

      const props = this._props(item, [
        "scopes", "paths", "introduced_by", "parents",
        "state", "is_policy_violation"
      ]);
      // License risk classification (see license_checker.js) as component
      // properties — CycloneDX's `licenses` field has no room for OSI
      // approval / risk metadata, so it travels alongside like reachability
      // does for vulnerabilities below.
      if (item.license_info) {
        props.push(
          { name: "license.osi_approved", value: JSON.stringify(item.license_info.osi_approved) },
          { name: "license.risk",         value: item.license_info.risk || "unknown" },
          { name: "license.category",     value: item.license_info.category || "unrecognized" },
          { name: "license.reason",       value: item.license_info.reason || "" },
        );
      }
      // Suggested upgrade versions that fix vulns in bulk, plus the vulns with
      // no fix (see suggested_fixes.js). Component properties are flat string
      // pairs, so the object travels JSON-encoded like other structured values.
      if (item.suggested_fixes) {
        props.push({ name: "suggested_fixes", value: JSON.stringify(item.suggested_fixes) });
      }
      if (props.length) comp.properties = props;
      components.push(comp);
    }
    return components;
  }

  /** Build flat dependency block. */
  buildDependencies() {
    const deps = [];
    for (const item of this.data.inventory || []) {
        const rawDeps = item.dependencies || [];
        const dependsOnStrings = rawDeps
        .map(dep => {
            if (typeof dep === 'string') return dep;
            if (dep && typeof dep === 'object') {
            return dep.purl || dep.id || null;
            }
            return null;
        })
        .filter(d => d && typeof d === 'string');
        // Deduplicate while preserving order (Set then spread)
        const ref = typeof item.id === 'string' ? item.id : (item.id?.purl || item.id?.id || '');
        // A component never depends on itself.
        const uniqueDependsOn = [...new Set(dependsOnStrings)].filter(d => d !== ref);
        deps.push({
        ref,
        dependsOn: uniqueDependsOn,
        });
    }
    return deps;
    }

  /** Build vulnerabilities + VEX analysis. */
  buildVulnerabilities() {
    const out = [];
    for (const v of this.data.vulnerabilities || []) {
      const vid = v.id || "";
      const isInf = !!v.is_infection;
      const sev = this._severityToCdx(isInf ? "critical" : v.severity);
      const method = this._normaliseCvssMethod(v.cvss_method, v.severity_vector);
      const purl = v.affected_package_id || "";

      let sources = v.source || [];
      if (typeof sources === "string") sources = [sources];
      const sourceName = (sources[0] || "osv").toLowerCase();
      const sourceUrl = sourceName === "osv" || isInf
        ? `https://osv.dev/vulnerability/${vid}`
        : `https://www.cve.org/CVERecord?id=${vid}`;

      const refs = v.references || [];
      const advisories = refs.filter(r => r.url).map(r => ({ url: r.url }));
      // Link the CISA KEV catalog entry when the CVE is listed there.
      if (v.is_kev === true) {
        advisories.push({
          title: "CISA Known Exploited Vulnerabilities Catalog",
          url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        });
      }

      const fixes = v.fixes || [];
      const recommendation = fixes.join("\n");

      // Reachability-aware VEX analysis (shared with the SARIF builder — see vex.js):
      // not_affected only for confident-unreachable findings that are neither infections
      // nor CISA KEV; everything else is exploitable.
      const reach = v.reachability || null;
      const analysis = vexAnalysis(v);

      const rating = { severity: sev, method };
      const score = v.severity_score;
      if (score !== undefined && score !== null) {
        const num = parseFloat(score);
        if (!isNaN(num)) rating.score = num;
      }
      if (v.severity_vector) rating.vector = v.severity_vector;

      const ratings = [rating];
      // EPSS as its own rating: CycloneDX 1.6 has no EPSS method, so it is
      // method "other"; `score` is the raw 0-1 probability of exploitation in the next
      // 30 days — the same scale as the epss.score property (the justification text
      // spells out the percent).
      if (typeof v.epss_score === "number") {
        const pctScore = Math.round(v.epss_score * 10000) / 100;
        ratings.push({
          source: { name: "FIRST EPSS", url: "https://www.first.org/epss/" },
          score: v.epss_score,
          method: "other",
          justification:
            `EPSS: ${pctScore}% estimated probability of exploitation in the next 30 days` +
            (typeof v.epss_percentile === "number" ? ` (percentile ${Math.round(v.epss_percentile * 10000) / 100})` : ""),
        });
      }

      const entry = {
        // Unique per (advisory, package): one advisory affecting several packages is
        // several entries here because each carries its own reachability/VEX analysis.
        "bom-ref": `${vid}|${purl}`,
        id: vid,
        source: { name: sourceName, url: sourceUrl },
        ratings,
        cwes: (v.cwes || []).map(c => {
          const n = typeof c === "number" ? c : parseInt(String(c).replace(/^CWE-/i, ""), 10);
          return isNaN(n) ? null : n;
        }).filter(n => n !== null),
        description: v.description || "",
        advisories,
        affects: purl ? [{ ref: purl }] : [],
        analysis,
        recommendation,
      };
      if (v.published) entry.published = v.published;
      if (v.modified) entry.updated = v.modified;

      // Reachability findings as CycloneDX vulnerability properties.
      if (reach) {
        entry.properties = [
          { name: "reachability.reachable",   value: String(reach.reachable) },
          { name: "reachability.level",        value: String(reach.level || "") },
          { name: "reachability.confidence",   value: String(reach.confidence || "") },
          { name: "reachability.rationale",    value: String(reach.rationale || "") },
          { name: "reachability.tags",         value: JSON.stringify(reach.tags || []) },
          ...(reach.signals ? [
            { name: "reachability.signals.depth",              value: String(reach.signals.depth ?? "") },
            { name: "reachability.signals.attack_vector",      value: String(reach.signals.attack_vector || "") },
            { name: "reachability.signals.scope",              value: String(reach.signals.scope || "") },
            { name: "reachability.signals.is_orphan_tool",     value: String(reach.signals.is_orphan_tool ?? "") },
            { name: "reachability.signals.is_non_library",     value: String(reach.signals.is_non_library ?? "") },
            { name: "reachability.signals.num_paths",          value: String(reach.signals.num_paths ?? "") },
            { name: "reachability.signals.introduced_by_count",value: String(reach.signals.introduced_by_count ?? "") },
          ] : []),
        ];
      }

      // Exploit intelligence (CISA KEV + FIRST EPSS).
      {
        const ti = this._threatIntelProps(v);
        if (ti.length) {
          entry.properties = entry.properties || [];
          entry.properties.push(...ti);
        }
      }

      // Suggested fix version for this vulnerability (omitted when none covers it).
      {
        const sf = this._suggestedFixFor(v);
        if (sf) {
          entry.properties = entry.properties || [];
          entry.properties.push(
            { name: "suggested_fix_version", value: sf.version },
            { name: "suggested_fix_bulk_count", value: String(sf.count) },
          );
        }
      }

      // Indicators of Compromise — populated on OSV malicious-package
      // entries (e.g. MAL-*) only. CycloneDX properties are flat
      // name/value string pairs, so each IOC list is JSON-encoded,
      // matching the reachability.tags/signals convention above.
      if (v.iocs) {
        entry.properties = entry.properties || [];
        entry.properties.push(
          { name: "iocs.urls",    value: JSON.stringify(v.iocs.urls    || []) },
          { name: "iocs.domains", value: JSON.stringify(v.iocs.domains || []) },
          { name: "iocs.ips",     value: JSON.stringify(v.iocs.ips     || []) },
        );
      }

      out.push(entry);
    }
    return out;
  }

  /**
   * Build the secrets-in-source findings block.
   *
   * CycloneDX has no native "secret finding" concept (these aren't
   * component vulnerabilities — they're not tied to a package/purl at
   * all, just a line in a source file). Unlike SARIF, CycloneDX's root
   * schema sets "additionalProperties": false — a bare "x-"-prefixed
   * root key is NOT tolerated by strict schema validation, despite that
   * convention working for other formats. The schema's own documented
   * extension point is the root-level "properties" name/value array
   * (see generate()), so the full secrets payload is serialized as a
   * single JSON-string property value there instead of as a root key.
   */
  buildSecrets() {
    const secrets = this.data.secrets || { enabled: true, count: 0, findings: [], stats: {} };
    return {
      enabled: secrets.enabled !== false,
      count:   secrets.count || 0,
      stats:   secrets.stats || {},
      findings: (secrets.findings || []).map(f => ({
        id:            f.id,
        title:         f.title,
        category:      f.category,
        severity:      f.severity,
        file_path:     f.file_path,
        line:          f.line,
        column_start:  f.column_start,
        column_end:    f.column_end,
        match_preview: f.match_preview,
      })),
    };
  }

  /** Generate full SBOM object. */
  generate() {
    const decision = this.data.decision || {};
    const stats = this.data.stats || {};
    const vulns = this.data.vulnerabilities || [];
    const ti = this.data.threat_intel || null;
    return {
      bomFormat: "CycloneDX",
      specVersion: this.CYCLONEDX_VERSION,
      serialNumber: `urn:uuid:${randomUUID()}`,
      version: 1,
      metadata: this.buildMetadata(),
      components: this.buildComponents(),
      dependencies: this.buildDependencies(),
      vulnerabilities: this.buildVulnerabilities(),
      properties: [
        { name: "policy_allowed", value: JSON.stringify(decision.allowed) },
        { name: "policy_reason", value: String(decision.reason || "") },
        { name: "policy_violations", value: JSON.stringify(decision.policy_violations || []) },
        { name: "inventory_size", value: String(stats.inventory_size || 0) },
        { name: "total_vulns", value: String(stats.total_vulnerabilities || 0) },
        { name: "total_infections", value: String(stats.total_infections || 0) },
        { name: "license_osi_approved", value: String((stats.license_stats || {}).osi_approved || 0) },
        { name: "license_not_osi_approved", value: String((stats.license_stats || {}).not_osi_approved || 0) },
        { name: "license_unknown", value: String((stats.license_stats || {}).unknown || 0) },
        { name: "secrets_found", value: String((this.data.secrets || {}).count || 0) },
        // Exploit intelligence roll-up. Counts are only meaningful when the
        // feed was reachable, so feed status travels with them.
        { name: "kev_vulnerabilities", value: String(vulns.filter(v => v.is_kev === true).length) },
        ...(ti ? [{ name: "ubel:threat_intel", value: JSON.stringify(ti) }] : []),
        // Full secrets payload — CycloneDX's root schema forbids
        // additionalProperties, so this can't be a top-level "x-"
        // key (see buildSecrets() docstring); it has to travel as a
        // JSON-string property value like everything else here.
        { name: "ubel:secrets", value: JSON.stringify(this.buildSecrets()) },
      ],
    };
  }
}