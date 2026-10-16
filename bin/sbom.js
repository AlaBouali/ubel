#!/usr/bin/env node
import { runAssetCommand } from "../sca/asset_cli.js";
// asset-id / set-asset-id / version are commands of every ubel CLI, and --asset-id <id> is a flag of every one;
// handle them before anything else. (ubel-sbom writes no report, so it never files anything under an asset.)
const assetCmd = runAssetCommand(process.argv.slice(2), { cli: "ubel-sbom" });
if (assetCmd !== null) process.exit(assetCmd);

const USAGE = `Usage: ubel-sbom <sbom.cdx.json> [-o <file>]

Fill the "vulnerabilities" of a CycloneDX JSON SBOM with the known vulnerabilities of its
components, each enriched with CISA KEV and FIRST EPSS. Only "vulnerabilities" is written —
no reachability, no policy, no report files.

Each component is looked up by its purl (OSV). Only a component with no purl OSV can be
asked about — none, no version, a VCS / download / file source, or an unsupported type —
falls back to its CPE (NVD).

Options:
  -o, --output <file>  write the SBOM with the vulnerabilities to <file>; the input is left untouched
  -h, --help           show this help

Without -o the SBOM is rewritten in place (atomically, and only once every lookup succeeded).
A "vulnerabilities" array already in the file is replaced.

Exit codes: 0 done, 1 bad command line, 2 not done (unreadable / non-CycloneDX / pre-1.4 SBOM,
incomplete OSV / NVD lookup — the file is then left as it was). DEBUG=1 prints the stack trace.`;

function parseArgs(args) {
  const out = { sbom: null, output: null };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "-h" || a === "--help") return { help: true };
    if (a === "-o" || a === "--output" || a.startsWith("--output=")) {
      const v = a.startsWith("--output=") ? a.slice("--output=".length) : args[++i];
      if (!v) return { error: `${a.split("=")[0]} needs a file name` };
      out.output = v;
      continue;
    }
    if (a.startsWith("-") && a.length > 1) return { error: `unknown option: ${a}` };
    if (out.sbom) return { error: `more than one SBOM given (${out.sbom}, ${a}) — ubel-sbom takes exactly one` };
    out.sbom = a;
  }
  if (!out.sbom) return { error: "no SBOM path given" };
  return out;
}

async function run() {
  const parsed = parseArgs(process.argv.slice(2));
  if (parsed.help) { console.log(USAGE); return 0; }
  if (parsed.error) { console.error(`[!] ${parsed.error}\n\n${USAGE}`); return 1; }

  try {
    const { sbomVulnsScan } = await import("../sca/sbom_vulns.js");
    const { file, replaced, summary } = await sbomVulnsScan({ sbom: parsed.sbom, output: parsed.output });

    for (const [reason, n] of Object.entries(summary.not_looked_up)) {
      console.warn(`[!] ${n} component${n === 1 ? "" : "s"} not looked up: ${reason}`);
    }
    if (summary.components_without_bom_ref) {
      console.warn(`[!] ${summary.components_without_bom_ref} component${summary.components_without_bom_ref === 1 ? " has" : "s have"} no bom-ref, so the findings on ${summary.components_without_bom_ref === 1 ? "it point" : "them point"} at its purl / CPE instead (components are not modified).`);
    }
    for (const w of summary.threat_intel.warnings) console.warn(`[!] ${w}`);

    const sev = Object.entries(summary.by_severity).filter(([, n]) => n).map(([s, n]) => `${n} ${s}`);
    if (summary.infections) sev.unshift(`${summary.infections} malicious`);
    console.log(`[*] ${summary.vulnerabilities} vulnerabilit${summary.vulnerabilities === 1 ? "y" : "ies"}` +
      (sev.length ? ` (${sev.join(", ")})` : "") +
      ` — ${summary.kev} in CISA KEV, ${summary.epss_scored} with an EPSS score.`);
    if (replaced) console.log(`[*] Replaced the ${replaced} vulnerabilit${replaced === 1 ? "y" : "ies"} the SBOM already had.`);
    console.log(`[+] Wrote ${file}`);
    return 0;
  } catch (err) {
    console.error(`[!] ubel-sbom failed: ${err.message}`);
    if (process.env.DEBUG) console.error(err.stack);
    return 2;
  }
}

process.exit(await run());
