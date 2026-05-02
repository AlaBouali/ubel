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
        licenses: item.license ? [ { expression: item.license } ] : [],
      };
      if (cpe) comp.cpe = cpe;

      const props = this._props(item, [
        "scopes", "paths", "introduced_by", "parents",
        "state", "is_policy_violation"
      ]);
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
      const purl = v.affected_purl || "";

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

      const analysis = isInf
        ? { state: "exploitable", response: ["rollback", "can_not_fix"] }
        : { state: "exploitable", response: ["update"] };

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
        cwes: v.cwes || [],
        description: v.description || "",
        advisories,
        affects: purl ? [{ ref: purl }] : [],
        analysis,
        recommendation,
      };
      if (v.published) entry.published = v.published;
      if (v.modified) entry.updated = v.modified;
      out.push(entry);
    }
    return out;
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
      ],
    };
  }
}