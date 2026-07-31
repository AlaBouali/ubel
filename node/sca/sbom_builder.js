// sbom_builder.js — CycloneDX 1.6 SBOM generator (Node.js port of Python version)

import { TOOL_NAME, TOOL_VERSION } from "./info.js";

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
  _normaliseCvssMethod(method) {
    if (!method) return "other";
    let m = String(method).replace(/\./g, "").toUpperCase();
    if (m.includes("CVSS2")) return "CVSSv2";
    if (m.includes("CVSS31")) return "CVSSv31";
    if (m.includes("CVSS3")) return "CVSSv3";
    if (m.includes("CVSS40")) return "CVSSv4";
    if (m.includes("CVSS4")) return "CVSSv4";
    if (m.includes("SSVC")) return "SSVC";
    return "other";
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
    if (item.license && typeof item.license === "string" && item.license.trim()) {
      return [{ license: { name: item.license } }];
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
        version: item.version || "",
        purl: purl,
        licenses: this._buildLicenses(item),
      };
      if (cpe) comp.cpe = cpe;

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
        const uniqueDependsOn = [...new Set(dependsOnStrings)];
        deps.push({
        ref: typeof item.id === 'string' ? item.id : (item.id?.purl || item.id?.id || ''),
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
      const method = this._normaliseCvssMethod(v.cvss_method);
      const purl = v.affected_package_id || "";

      let sources = v.source || [];
      if (typeof sources === "string") sources = [sources];
      const sourceName = (sources[0] || "osv").toLowerCase();
      const sourceUrl = sourceName === "osv" || isInf
        ? `https://osv.dev/vulnerability/${vid}`
        : `https://www.cve.org/CVERecord?id=${vid}`;

      const refs = v.references || [];
      const advisories = refs.filter(r => r.url).map(r => ({ url: r.url }));

      const fixes = v.fixes || [];
      const recommendation = fixes.join("\n");

      // Reachability-aware VEX analysis state:
      //   confirmed-unreachable (high/medium confidence) -> "not_affected"
      //   reachable + import confirmed                   -> "exploitable"
      //   reachable + low confidence / no data           -> "exploitable" (default)
      const reach = v.reachability || null;
      let analysisState;
      let analysisResponse;
      if (isInf) {
        analysisState    = "exploitable";
        analysisResponse = ["rollback", "can_not_fix"];
      } else if (
        reach &&
        reach.reachable === false &&
        (reach.confidence === "high" || reach.confidence === "medium")
      ) {
        analysisState    = "not_affected";
        analysisResponse = ["will_not_fix"];
      } else {
        analysisState    = "exploitable";
        analysisResponse = ["update"];
      }
      const analysis = {
        state:    analysisState,
        response: analysisResponse,
        ...(reach && reach.rationale ? { detail: reach.rationale } : {}),
      };

      const rating = { severity: sev, method };
      const score = v.severity_score;
      if (score !== undefined && score !== null) {
        const num = parseFloat(score);
        if (!isNaN(num)) rating.score = num;
      }
      if (v.severity_vector) rating.vector = v.severity_vector;

      const entry = {
        id: vid,
        source: { name: sourceName, url: sourceUrl },
        ratings: [rating],
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
    return {
      bomFormat: "CycloneDX",
      specVersion: this.CYCLONEDX_VERSION,
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
        // Full secrets payload — CycloneDX's root schema forbids
        // additionalProperties, so this can't be a top-level "x-"
        // key (see buildSecrets() docstring); it has to travel as a
        // JSON-string property value like everything else here.
        { name: "ubel:secrets", value: JSON.stringify(this.buildSecrets()) },
      ],
    };
  }
}