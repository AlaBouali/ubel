'use strict';
// advisories.js — turns the advisories found for the components inside a binary (Dependencies tab) into report findings, so the summary,
// the risk rating, the severity counts, the Vulnerabilities tab, the compliance mapping and the diff against the previous run all
// count them. Without this step a binary whose only problem is a vulnerable bundled library reads "Low risk / 0 vulnerabilities".
//
// The CI gate is NOT fed from these findings: evaluateGate() already counts dependency advisories itself, and counting both would double every hit.

import { SEVERITY_RANK } from '../../mobile/lib/rules.js';

const sevOf = v => {
  const s = String(v?.severity || '').toLowerCase();
  if (s === 'moderate') return 'medium';
  return s in SEVERITY_RANK ? s : 'info';                    // no rating given: listed, lowest rank (the gate treats it the same way)
};

const clip = (s, n) => { const t = String(s || '').replace(/\s+/g, ' ').trim(); return t.length > n ? `${t.slice(0, n - 1)}…` : t; };

// Dotted-version comparison (1.3.1 < 1.3.2 < 1.10). Non-numeric parts compare as text; good enough to rank fix versions of one component.
function cmpVersion(a, b) {
  const pa = String(a).split(/[.\-+_]/), pb = String(b).split(/[.\-+_]/);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? '0', y = pb[i] ?? '0', nx = /^\d+$/.test(x), ny = /^\d+$/.test(y);
    const d = nx && ny ? Number(x) - Number(y) : String(x).localeCompare(String(y));
    if (d) return d < 0 ? -1 : 1;
  }
  return 0;
}

/** The release that fixes one advisory: the closest fixed version above the one in the file, else the highest listed. */
function fixFor(dep, v) {
  const fixed = (v.fixed_versions || []).filter(Boolean);
  if (!fixed.length) return null;
  const above = dep.version ? fixed.filter(f => cmpVersion(f, dep.version) > 0).sort(cmpVersion) : [];
  return above.length ? above[0] : [...fixed].sort(cmpVersion).pop();
}

/** One remediation per component: the lowest release that fixes every advisory found for it (the same text on each finding, so the summary lists it once). */
function remediationFor(dep) {
  const what = `${dep.name}${dep.version ? ` ${dep.version}` : ''}`;
  const advisories = dep.vulnerabilities || [];
  const fixes = advisories.map(v => fixFor(dep, v));
  const fixable = fixes.filter(Boolean).sort(cmpVersion);
  if (!fixable.length) return `No fixed version is listed for ${what}. Check the vendor advisory, and remove the component or apply a vendor workaround if one exists.`;
  const target = fixable[fixable.length - 1], unfixed = fixes.filter(f => !f).length;
  return `Update ${dep.name} to ${target} or later${advisories.length > 1 ? (unfixed ? ` (fixes ${advisories.length - unfixed} of the ${advisories.length} advisories found for it)` : ` (fixes all ${advisories.length} advisories found for it)`) : ''}, then rebuild the binary: ${what} is compiled into the file, so only a rebuild picks up the fix.${unfixed ? ` ${unfixed} advisor${unfixed === 1 ? 'y has' : 'ies have'} no fixed version listed.` : ''}`;
}

/** Adds one finding per (component, advisory). `minSeverity` is applied by the caller; this adds everything. Returns the added findings. */
export function addAdvisoryFindings(findings, dependencies, { app, ruleFor = null, describe = null } = {}) {
  const added = [];
  for (const dep of dependencies || []) {
    for (const v of dep.vulnerabilities || []) {
      const fixed = (v.fixed_versions || []).filter(Boolean);
      const identity = dep.purl || dep.cpe || dep.coordinate || `${dep.name}@${dep.version}`;
      const evidence = [
        `Component: ${dep.name}${dep.version ? ` ${dep.version}` : ''} (${dep.ecosystem || 'component'})`,
        `Found by: ${(dep.sources || []).slice(0, 2).join('; ') || 'embedded version string'}`,
        v.severity_score != null ? `CVSS ${v.severity_score}${v.severity_vector ? ` · ${v.severity_vector}` : ''}` : null,
        fixed.length ? `Fixed in: ${fixed.slice(0, 6).join(', ')}` : 'No fixed version listed',
        v.url ? `Advisory: ${v.url}` : null,
      ].filter(Boolean);
      const text = clip(v.details || v.summary, 1500) || 'No description was supplied for this advisory.';
      // `ruleFor(dep, advisory)` / `describe(dep, advisory, text)` let another scanner (ubel-package) file the same advisories under its own rules and wording
      const custom = describe ? describe(dep, v, text) : null;
      const f = findings.add(ruleFor ? ruleFor(dep, v) : 'binary.component.vulnerable', {
        app, artifact: `${dep.name}${dep.version ? ` ${dep.version}` : ''}`, key: `${v.id}|${identity}`,
        title: custom?.title || `${v.id} in ${dep.name}${dep.version ? ` ${dep.version}` : ''}`,
        description: custom?.description || `${text} The component's version was read from the file; the vulnerable code is present, which does not prove the affected function is reachable.`,
        evidence: custom?.evidence || evidence, severity: custom?.severity || sevOf(v), confidence: 'medium', confidenceCap: false,
        remediation: custom?.remediation || remediationFor(dep),
      });
      if (!f) continue;
      const cwe = (v.cwes || []).find(n => Number.isFinite(Number(n)));
      if (cwe != null) f.cwe = `CWE-${Number(cwe)}`;
      f.component = { name: dep.name, version: dep.version || null, ecosystem: dep.ecosystem || null, identity, advisory: v.id };
      added.push(f);
    }
  }
  return added;
}
