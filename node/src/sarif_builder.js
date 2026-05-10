// sarif_builder.js — SARIF 2.1.0 generator (fixes SARIF1004)

import path from "path";
import crypto from "crypto";
import { TOOL_NAME, TOOL_VERSION } from "./info.js";

/**
 * Convert UBEL final JSON into a SARIF 2.1.0 document.
 */
export class SarifBuilder {
  constructor(finalJson) {
    this.data = finalJson || {};

    this.SARIF_VERSION = "2.1.0";

    this.SARIF_SCHEMA =
      "https://json.schemastore.org/sarif-2.1.0.json";

    this._purlLocationIndex = null;
  }

  /** Clamp giant advisory texts (reduced to 10k for safety) */
  _truncate(text, max = 10000) {
    const s = String(text || "");

    if (s.length <= max) {
      return s;
    }

    return `${s.slice(0, max)}\n\n[truncated]`;
  }

  /** Map UBEL severity -> SARIF level */
  _severityToLevel(sev, isInfection = false) {
    if (isInfection) {
      return "error";
    }

    const s = String(sev || "")
      .trim()
      .toLowerCase();

    if (s === "critical" || s === "high") {
      return "error";
    }

    if (s === "medium" || s === "moderate") {
      return "warning";
    }

    if (s === "low") {
      return "note";
    }

    return "none";
  }

  /** Normalize URI/path separators (no trailing slash for normal paths) */
  _normalizeUri(uri) {
    if (!uri) {
      return null;
    }

    return String(uri)
      .replace(/\\/g, "/")
      .replace(/\/+/g, "/")
      .replace(/\/$/, ""); // remove trailing slash for non‑base URIs
  }

  /** Convert filesystem path -> file:// URI (without trailing slash) */
  _toFileUri(p) {
    if (!p) {
      return undefined;
    }

    let normalized =
      this._normalizeUri(
        path.resolve(String(p))
      );

    if (!normalized.startsWith("/")) {
      normalized = `/${normalized}`;
    }

    return `file://${normalized}`;
  }

  /**
   * Convert absolute filesystem path
   * into repository-relative SARIF URI
   */
  _toRepoRelativeUri(rawPath) {
    if (!rawPath) {
      return null;
    }

    const normalized =
      this._normalizeUri(rawPath);

    const cwd =
      this._normalizeUri(
        process.cwd()
      );

    const lowerPath =
      normalized.toLowerCase();

    const lowerCwd =
      cwd.toLowerCase();

    // inside repository (case-insensitive for Windows)
    if (
      lowerPath.startsWith(lowerCwd)
    ) {
      let relative =
        normalized.slice(cwd.length);

      relative =
        relative.replace(/^\/+/, "");

      return relative || ".";
    }

    // already relative
    if (
      !/^[a-zA-Z]:\//.test(normalized) &&
      !normalized.startsWith("/")
    ) {
      return normalized;
    }

    // fallback
    return path.basename(normalized);
  }

  /**
   * Build:
   * purl -> installed runtime paths
   */
  _buildPurlLocationIndex() {
    const index = new Map();

    const findings =
      this.data.findings_summary || {};

    for (const finding of Object.values(findings)) {
      const runtimePaths = [];

      // installed locations
      if (Array.isArray(finding.paths)) {
        for (const p of finding.paths) {
          if (
            p &&
            typeof p.text === "string"
          ) {
            const normalized =
              this._normalizeUri(p.text);

            if (normalized) {
              runtimePaths.push(
                normalized
              );
            }
          }
        }
      }

      if (!runtimePaths.length) {
        continue;
      }

      // derive purls from dependency chains
      const sequences =
        Array.isArray(
          finding.affected_dependency_sequences
        )
          ? finding.affected_dependency_sequences
          : [];

      for (const seq of sequences) {
        if (!Array.isArray(seq)) {
          continue;
        }

        for (const purl of seq) {
          if (
            typeof purl !== "string"
          ) {
            continue;
          }

          if (!index.has(purl)) {
            index.set(
              purl,
              new Set()
            );
          }

          const set =
            index.get(purl);

          for (const runtimePath of runtimePaths) {
            set.add(runtimePath);
          }
        }
      }
    }

    return index;
  }

  /**
   * Build SARIF locations
   */
  _buildLocations(v) {
    const locations = [];

    const seen = new Set();

    const addLocation = rawUri => {
      const relativeUri =
        this._toRepoRelativeUri(
          rawUri
        );

      if (
        !relativeUri ||
        seen.has(relativeUri)
      ) {
        return;
      }

      seen.add(relativeUri);

      locations.push({
        physicalLocation: {
          artifactLocation: {
            uri: relativeUri,
            uriBaseId: "%SRCROOT%",
          },

          region: {
            startLine: 1,
            startColumn: 1,
          },
        },
      });
    };

    // lazy init
    if (!this._purlLocationIndex) {
      this._purlLocationIndex =
        this._buildPurlLocationIndex();
    }

    const affectedPurl =
      String(
        v.affected_purl || ""
      ).trim();

    // purl-derived runtime paths
    if (
      affectedPurl &&
      this._purlLocationIndex.has(
        affectedPurl
      )
    ) {
      for (
        const loc of this
          ._purlLocationIndex
          .get(affectedPurl)
      ) {
        addLocation(loc);
      }
    }

    // explicit paths
    if (Array.isArray(v.paths)) {
      for (const p of v.paths) {
        if (typeof p === "string") {
          addLocation(p);
        }
      }
    }

    // explicit file
    if (v.file) {
      addLocation(v.file);
    }

    // GHAS fallback
    if (!locations.length) {
      locations.push({
        physicalLocation: {
          artifactLocation: {
            uri: ".",
            uriBaseId: "%SRCROOT%",
          },

          region: {
            startLine: 1,
            startColumn: 1,
          },
        },
      });
    }

    return locations;
  }

  /** Build help URI */
  _helpUri(v) {
    return v.url;
  }

  /** Deduplicate SARIF rules */
  buildRules() {
    const rulesMap = new Map();

    for (const v of this.data.vulnerabilities || []) {
      const ruleId = this._ruleId(v);

      if (rulesMap.has(ruleId)) {
        continue;
      }

      const advisoryId =
        String(v.id || "UBEL-UNKNOWN");

      const summary =
        v.summary ||
        v.title ||
        advisoryId;

      const description =
        v.description ||
        v.summary ||
        "No description provided.";

      const fixes = Array.isArray(v.fixes)
        ? v.fixes
        : [];

      const remediation =
        v.remediation ||
        (
          fixes.length
            ? fixes.join("\n")
            : "No remediation guidance available."
        );

      rulesMap.set(ruleId, {
        id: ruleId,

        name: this._toPascalCaseRuleName(
          `${advisoryId} ${v.title || v.summary || advisoryId}`
        ),

        shortDescription: {
          text: this._truncate(summary, 300),
        },

        fullDescription: {
          text: this._truncate(
            description,
            10000
          ),
        },

        help: {
          text: this._truncate(
            remediation,
            4000
          ),
        },

        helpUri: this._helpUri(v),

        properties: {
          advisory_id:
            advisoryId,

          severity:
            v.severity || "unknown",

          cvss_score:
            v.severity_score ?? null,

          cvss_vector:
            v.severity_vector || null,

          cvss_method:
            v.cvss_method || null,

          cwes:
            Array.isArray(v.cwes)
              ? v.cwes
              : [],

          affected_purl:
            v.affected_purl || null,

          package:
            v.package || null,

          package_version:
            v.package_version || null,

          is_infection:
            !!v.is_infection,
        },
      });
    }

    return [...rulesMap.values()];
  }

  /** Build SARIF results */
  buildResults() {
    const results = [];

    const rules = this.buildRules();

    const ruleIndexMap = new Map();

    rules.forEach((r, idx) => {
      ruleIndexMap.set(r.id, idx);
    });

    for (const v of this.data.vulnerabilities || []) {
      const ruleId = this._ruleId(v);

      const isInfection =
        !!v.is_infection;

      const message =
        v.summary ||
        v.title ||
        v.description ||
        v.id ||
        "Security issue detected.";

      results.push({
        ruleId,

        ruleIndex:
          ruleIndexMap.get(ruleId),

        level: this._severityToLevel(
          v.severity,
          isInfection
        ),

        message: {
          text: this._truncate(
            message,
            2000
          ),
        },

        locations:
          this._buildLocations(v),

        partialFingerprints: {
          vulnerabilityId:
            String(v.id || ""),

          affectedPurl:
            String(
              v.affected_purl || ""
            ),

          primaryLocationLineHash:
            `${v.id || ""}:${
              v.affected_purl || ""
            }`,
        },

        fingerprints: {
          primary:
            this._uuidFromString(
              `${v.id || ""}:${
                v.affected_purl || ""
              }`
            ),
        },

        properties: {
          advisory_id:
            v.id || null,

          severity:
            v.severity || "unknown",

          score:
            v.severity_score ?? null,

          vector:
            v.severity_vector || null,

          package:
            v.package || null,

          package_version:
            v.package_version || null,

          affected_purl:
            v.affected_purl || null,

          fixed_versions:
            Array.isArray(v.fixes)
              ? v.fixes
              : [],

          cwes:
            Array.isArray(v.cwes)
              ? v.cwes
              : [],

          published:
            v.published || null,

          modified:
            v.modified || null,

          exploitability:
            isInfection
              ? "active-infection"
              : "vulnerable",
        },
      });
    }

    return results;
  }

  /** Build tool metadata */
  buildTool() {
    const toolInfo =
      this.data.tool_info || {};

    return {
      driver: {
        fullName: `${TOOL_NAME} v${TOOL_VERSION}`,

        name:
          toolInfo.name ||
          TOOL_NAME,

        version:
          toolInfo.version ||
          TOOL_VERSION,

        semanticVersion:
          toolInfo.version ||
          TOOL_VERSION,

        informationUri:
          "https://github.com/Arcane-Spark/UBEL",

        rules:
          this.buildRules(),
      },
    };
  }

  /** Build invocation metadata */
  buildInvocations() {
    const runtime =
      this.data.runtime || {};

    const git =
      this.data.git_metadata || {};

    const stats =
      this.data.stats || {};

    const decision =
      this.data.decision || {};

    return [
      {
        executionSuccessful: true,

        properties: {
          runtime_environment:
            runtime.environment || "",

          runtime_version:
            runtime.version || "",

          platform:
            runtime.platform || "",

          architecture:
            runtime.arch || "",

          cwd:
            runtime.cwd || "",

          git_branch:
            git.branch || "",

          git_commit:
            git.latest_commit || "",

          git_url:
            git.url || "",

          inventory_size:
            stats.inventory_size || 0,

          total_vulnerabilities:
            stats.total_vulnerabilities || 0,

          total_infections:
            stats.total_infections || 0,

          policy_allowed:
            decision.allowed !== undefined
              ? decision.allowed
              : null,

          policy_reason:
            decision.reason || "",
        },
      },
    ];
  }

  /** Convert advisory IDs into SARIF-friendly names */
  _toPascalCaseRuleName(input) {
    return String(input || "UnknownRule")
      .replace(/[^a-zA-Z0-9]+/g, " ")
      .split(" ")
      .filter(Boolean)
      .map(
        part =>
          part.charAt(0).toUpperCase() +
          part.slice(1).toLowerCase()
      )
      .join("");
  }

  /**
   * Build SARIF version control provenance
   * (prefer remote git URL over local file URI)
   */
  buildVersionControlProvenance() {
    const git =
      this.data.git_metadata || {};

    const repoUri =
      git.url && git.url !== ""
        ? git.url
        : this._toFileUri(process.cwd());

    const revisionId =
      git.latest_commit ||
      this._uuidFromString(repoUri);

    return [
      {
        repositoryUri: repoUri,

        revisionId,

        branch:
          git.branch || "unknown",

        mappedTo: {
          uriBaseId: "%SRCROOT%",
        },
      },
    ];
  }

  /** Deterministic UUIDv5-like generator */
  _uuidFromString(input) {
    const hash = crypto
      .createHash("sha1")
      .update(String(input))
      .digest("hex");

    return [
      hash.slice(0, 8),
      hash.slice(8, 12),
      `5${hash.slice(13, 16)}`,
      `${(
        (
          parseInt(
            hash.slice(16, 17),
            16
          ) & 0x3
        ) | 0x8
      ).toString(16)}${hash.slice(
        17,
        20
      )}`,
      hash.slice(20, 32),
    ].join("-");
  }

  /** Stable SARIF rule id */
  _ruleId(v) {
    const advisory =
      String(
        v?.id ||
        v?.ghsa ||
        v?.cve ||
        "UBEL-UNKNOWN"
      );

    return this._uuidFromString(
      advisory
    );
  }

  /** Build optional artifacts section (improves some consumers) */
  buildArtifacts() {
    const artifactUris = new Set();
    const results = this.buildResults();

    for (const result of results) {
      for (const loc of result.locations || []) {
        const uri = loc.physicalLocation?.artifactLocation?.uri;
        if (uri && uri !== ".") {
          artifactUris.add(uri);
        }
      }
    }

    return Array.from(artifactUris).map((uri) => ({
      location: {
        uri,
        uriBaseId: "%SRCROOT%",
      },
    }));
  }

  /** Generate full SARIF document */
  generate() {
    const cwd =
      this._normalizeUri(
        process.cwd()
      );

    // SARIF requires base URI to end with a slash
    let baseUri = this._toFileUri(cwd);
    if (!baseUri.endsWith("/")) {
      baseUri += "/";
    }

    return {
      $schema:
        this.SARIF_SCHEMA,

      version:
        this.SARIF_VERSION,

      runs: [
        {
          tool:
            this.buildTool(),

          automationDetails: {
            id: "ubel",
          },

          originalUriBaseIds: {
            "%SRCROOT%": {
              uri: baseUri,
            },
          },

          versionControlProvenance:
            this.buildVersionControlProvenance(),

          invocations:
            this.buildInvocations(),

          results:
            this.buildResults(),

          artifacts:
            this.buildArtifacts(),

          properties: {
            generated_at:
              this.data.generated_at ||
              new Date()
                .toISOString()
                .replace(
                  /\.\d+Z$/,
                  "Z"
                ),

            scan_type:
              this.data.scan_info
                ?.type || "health",

            scan_scope:
              this.data.scan_info
                ?.scan_scope ||
              "repository",

            ecosystems:
              this.data.scan_info
                ?.ecosystems || [],
          },
        },
      ],
    };
  }
}