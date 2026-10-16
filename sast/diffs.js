// diffs.js — comparison of a SAST / malware scan with the previous report of the same
// asset and type (the "Diffs" tab of the HTML report, and the `diffs` block of the JSON).
//
// The previous report is read from the newest earlier <timestamp>.<tag>.zip in the same
// history folder (its report.<tag>.json entry). Compared, like the SCA report does:
//   - chunks       the code units analysed (matched by chunk id: file + function)
//   - vulns        findings (matched by vuln class + chunk, counted per occurrence)
//   - compliance   per framework, the findings mapped to it that are new / existing / resolved
//
// Findings the verification pass dismissed as false positives are not counted, so a
// finding being cleared shows up as "fixed" rather than lingering.

import fs   from 'fs';
import path from 'path';
import zlib from 'zlib';
import { reportFileName } from '../sca/report_naming.js';

// ─── zip reading ─────────────────────────────────────────────────────────────

/** Reads one entry of a zip (stored or deflate) into a Buffer; null when absent / unsupported. */
function readZipEntry(zipFile, entryName) {
  const buf = fs.readFileSync(zipFile);
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 22 - 65535); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) return null;
  const total = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16);
  for (let n = 0; n < total; n++) {
    if (p + 46 > buf.length || buf.readUInt32LE(p) !== 0x02014b50) return null;
    const method     = buf.readUInt16LE(p + 10);
    const csize      = buf.readUInt32LE(p + 20);
    const nameLen    = buf.readUInt16LE(p + 28);
    const extraLen   = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const localOff   = buf.readUInt32LE(p + 42);
    const name       = buf.toString('utf8', p + 46, p + 46 + nameLen);
    if (name === entryName) {
      const dataStart = localOff + 30 + buf.readUInt16LE(localOff + 26) + buf.readUInt16LE(localOff + 28);
      const raw = buf.subarray(dataStart, dataStart + csize);
      if (method === 0) return Buffer.from(raw);
      if (method === 8) return zlib.inflateRawSync(raw);
      return null;
    }
    p += 46 + nameLen + extraLen + commentLen;
  }
  return null;
}

/**
 * The newest report of the same tag that precedes `zipPath` in the same history folder.
 * Returns { file, report } or null (first report of this asset/type, or none readable).
 */
export function loadPreviousSastReport(zipPath, reportTag) {
  const dir     = path.dirname(zipPath);
  const current = path.basename(zipPath);
  const suffix  = `.${reportTag}.zip`;
  let names;
  try { names = fs.readdirSync(dir); } catch { return null; }
  const earlier = names.filter(n => n.endsWith(suffix) && n < current).sort().reverse();
  const entry   = reportFileName('report', reportTag, 'json');
  for (const n of earlier) {
    try {
      const data = readZipEntry(path.join(dir, n), entry);
      if (data) {
        const report = JSON.parse(data.toString('utf8'));
        if (report && Array.isArray(report.results)) return { file: n, report };
      }
    } catch { /* unreadable bundle: try the next older one */ }
  }
  return null;
}

// ─── extraction ──────────────────────────────────────────────────────────────

const relFile = (f) => String(f || '').replace(/\\/g, '/');

function chunkLabel(chunk) {
  return chunk.class ? `${chunk.class}.${chunk.name}` : (chunk.name || '');
}

// chunk id -> entry
function diffChunks(results) {
  const out = new Map();
  for (const c of results || []) {
    if (!c || c.id == null || out.has(c.id)) continue;
    out.set(c.id, {
      id: c.id, file: relFile(c.file), name: chunkLabel(c),
      type: c.type || null, language: c.language || null,
    });
  }
  return out;
}

// Live findings: real (not a parse error) and not dismissed as a false positive.
function liveFindings(results) {
  const out = [];
  for (const chunk of results || []) {
    for (const f of (chunk.findings || [])) {
      if (!f || f._parse_error || f.is_valid === false) continue;
      out.push({ chunk, f });
    }
  }
  return out;
}

const vulnClassOf = (f) =>
  String(f.vuln_class || f.vuln_name || 'unknown').replace(/\s*\(CWE[^)]*\)\s*$/i, '').trim();

// Same class in the same chunk twice gets #2, #3 ... so occurrences are counted, not merged.
// Not keyed on line or snippet: those move whenever the file is edited.
function keyedFindings(results) {
  const seen = new Map();
  const out  = new Map();
  for (const { chunk, f } of liveFindings(results)) {
    const cls  = vulnClassOf(f);
    const base = `${cls}::${chunk.id}`;
    const n    = (seen.get(base) || 0) + 1;
    seen.set(base, n);
    out.set(n === 1 ? base : `${base}#${n}`, {
      id: cls,
      title: f.title || '',
      severity: f.severity || 'unknown',
      file: relFile(chunk.file),
      name: chunkLabel(chunk),
      line: f.line || chunk.startLine || null,
      exploitable: f.taint?.exploitable === true,
      frameworks: f.compliance?.frameworks || [],
    });
  }
  return out;
}

// ─── compliance ──────────────────────────────────────────────────────────────

function diffCompliance(curItems, oldItems) {
  const fwMeta = new Map();
  const perFw = (items) => {
    const m = new Map();
    for (const [key, it] of items) {
      for (const fw of it.frameworks) {
        const fid = fw.id || fw.name;
        if (!fwMeta.has(fid)) fwMeta.set(fid, { id: fid, name: fw.name, version: fw.version ?? null });
        if (!m.has(fid)) m.set(fid, new Map());
        m.get(fid).set(key, {
          id: it.id, title: it.title, severity: it.severity,
          where: `${it.file}${it.line != null ? ':' + it.line : ''}${it.name ? ' (' + it.name + ')' : ''}`,
          controls: (fw.controls || []).map(c => c.id).join(', '),
        });
      }
    }
    return m;
  };
  const curFw = perFw(curItems), oldFw = perFw(oldItems);
  const sortBy = (a, b) => String(a.id).localeCompare(String(b.id)) || String(a.where).localeCompare(String(b.where));
  const rows = [];
  for (const meta of fwMeta.values()) {
    const c = curFw.get(meta.id) || new Map(), o = oldFw.get(meta.id) || new Map();
    rows.push({
      ...meta,
      new:       [...c].filter(([k]) => !o.has(k)).map(([, e]) => e).sort(sortBy),
      unchanged: [...c].filter(([k]) =>  o.has(k)).map(([, e]) => e).sort(sortBy),
      removed:   [...o].filter(([k]) => !c.has(k)).map(([, e]) => e).sort(sortBy),
    });
  }
  rows.sort((a, b) => String(a.name).localeCompare(String(b.name)));
  return { frameworks: rows };
}

// ─── main ────────────────────────────────────────────────────────────────────

/**
 * @param {object[]} results   current scan results (compliance already attached to findings)
 * @param {object}   meta      current meta (scan_options, scan_stats)
 * @param {{file:string, report:object}|null} previous  from loadPreviousSastReport()
 */
export function buildSastDiffs(results, meta, previous) {
  const empty = { new: [], unchanged: [], removed: [] };
  if (!previous) {
    return { enabled: true, previous: null, counts: null, scope_note: null, chunks: empty,
             vulns: { new: [], existing: [], fixed: [] }, compliance: null };
  }
  const prev = previous.report;

  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };
  const chunkSort = (a, b) => a.file.localeCompare(b.file) || a.name.localeCompare(b.name);
  const vulnSort  = (a, b) =>
    (sevOrder[String(a.severity).toLowerCase()] ?? 4) - (sevOrder[String(b.severity).toLowerCase()] ?? 4)
    || a.id.localeCompare(b.id) || a.file.localeCompare(b.file) || a.name.localeCompare(b.name);
  const split = (cur, old, sorter) => ({
    added:   [...cur].filter(([k]) => !old.has(k)).map(([, e]) => e).sort(sorter),
    kept:    [...cur].filter(([k]) =>  old.has(k)).map(([, e]) => e).sort(sorter),
    dropped: [...old].filter(([k]) => !cur.has(k)).map(([, e]) => e).sort(sorter),
  });

  const ch = split(diffChunks(results), diffChunks(prev.results), chunkSort);
  const curVulns = keyedFindings(results), oldVulns = keyedFindings(prev.results);
  const v  = split(curVulns, oldVulns, vulnSort);

  // Chunk (and so finding) sets are only comparable when both runs covered the same ground.
  const limited = (o) => !!(o && (o.only_diff || (o.chunks_dropped_by_cap || 0) > 0));
  const curOpts = meta && meta.scan_options, oldOpts = prev.meta && prev.meta.scan_options;
  const scopeNote = (limited(curOpts) || limited(oldOpts))
    ? 'One of the two scans did not cover every chunk (diff-only mode, or chunks beyond the --max-chunks cap), so "new" and "removed" items may reflect scan scope rather than code changes.'
    : null;

  // An older report with no compliance mapping must not read as "everything is new".
  const hasCompliance = !!(prev.meta && prev.meta.compliance_summary);

  return {
    enabled: true,
    previous: {
      report_id: prev.meta?.report_id ?? null,
      generated_at: prev.generated_at ?? null,
      bundle: previous.file,
    },
    counts: {
      new_chunks: ch.added.length, unchanged_chunks: ch.kept.length, removed_chunks: ch.dropped.length,
      new_vulns: v.added.length, existing_vulns: v.kept.length, fixed_vulns: v.dropped.length,
    },
    scope_note: scopeNote,
    chunks: { new: ch.added, unchanged: ch.kept, removed: ch.dropped },
    vulns:  { new: v.added, existing: v.kept, fixed: v.dropped },
    compliance: hasCompliance ? diffCompliance(curVulns, oldVulns) : null,
  };
}