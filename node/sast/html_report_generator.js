// sast_html_report.js — HTML report generator for ubel-sast results
//
// Input:  { results, meta }
//   results — array from sast_results.json written by analyzeSast()
//   meta    — { workingDir, model, provider, gitMetadata, osMetadata,
//               generated_at, tool_version }
//
// Output: HTML string (caller writes to disk)

import { TOOL_NAME, TOOL_VERSION } from './info.js';

const SAST_TOOL = '@arcane-spark/ubel-sast';

// ─── escaping ────────────────────────────────────────────────────────────────

function escapeHTML(str) {
  if (!str || typeof str !== 'string') return '';
  return str.replace(/[&<>"']/g, m => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[m]));
}

function escapeForScript(obj) {
  return JSON.stringify(obj)
    .replace(/</g, '\\u003c')
    .replace(/`/g, '\\u0060');
}

// ─── severity helpers ────────────────────────────────────────────────────────

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };

function sevColor(sev) {
  const s = (sev || 'unknown').toLowerCase();
  if (s === 'critical') return 'text-red-500 border-red-500';
  if (s === 'high')     return 'text-red-400 border-red-400';
  if (s === 'medium')   return 'text-orange-400 border-orange-400';
  if (s === 'low')      return 'text-blue-400 border-blue-400';
  return 'text-neutral-400 border-neutral-400';
}

function confColor(conf) {
  if (conf === 'high')   return 'text-green-400 border-green-400';
  if (conf === 'medium') return 'text-yellow-400 border-yellow-400';
  return 'text-neutral-500 border-neutral-500';
}

// ─── stats builder ───────────────────────────────────────────────────────────

function buildStats(results) {
  let totalChunks    = results.length;
  let chunksWithFindings = 0;
  let totalFindings  = 0;
  let parseErrors    = 0;
  const sevCounts    = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  const confCounts   = { high: 0, medium: 0, low: 0 };
  let verified       = 0;
  let verifiedValid  = 0;
  let verifiedFalsePositive = 0;
  let taintTraced    = 0;
  let exploitable    = 0;
  let sanitized      = 0;
  const classCount   = {};
  const fileCount    = {};
  const langCount    = {};

  for (const chunk of results) {
    const realFindings = (chunk.findings || []).filter(f => !f._parse_error);
    const errors       = (chunk.findings || []).filter(f =>  f._parse_error);
    parseErrors += errors.length;

    if (realFindings.length) chunksWithFindings++;

    for (const f of realFindings) {
      totalFindings++;

      // Normalise vuln_class — the LLM writes vuln_name; strip any CWE suffix
      if (!f.vuln_class && f.vuln_name) {
        f.vuln_class = f.vuln_name.replace(/\s*\(CWE[^)]*\)\s*$/i, '').trim();
      } else if (f.vuln_class) {
        f.vuln_class = f.vuln_class.replace(/\s*\(CWE[^)]*\)\s*$/i, '').trim();
      }

      const sev  = (f.severity  || 'unknown').toLowerCase();
      const conf = (f.confidence || 'low').toLowerCase();

      if (sev  in sevCounts)  sevCounts[sev]++;
      else                     sevCounts.unknown++;
      if (conf in confCounts) confCounts[conf]++;

      const vc = f.vuln_class || 'unknown';
      classCount[vc] = (classCount[vc] || 0) + 1;

      if (chunk.file) {
        const rel = chunk.file.replace(/\\/g, '/');
        fileCount[rel] = (fileCount[rel] || 0) + 1;
      }

      if (chunk.language) {
        langCount[chunk.language] = (langCount[chunk.language] || 0) + 1;
      }

      if (f.is_valid === true || f.is_valid === false) {
        verified++;
        if (f.is_valid === true)  verifiedValid++;
        else                       verifiedFalsePositive++;
      }

      if (f.taint) {
        taintTraced++;
        if (f.taint.exploitable === true)  exploitable++;
        if (f.taint.sanitized   === true)  sanitized++;
      }
    }
  }

  return {
    totalChunks,
    chunksWithFindings,
    totalFindings,
    parseErrors,
    sevCounts,
    confCounts,
    verified,
    verifiedValid,
    verifiedFalsePositive,
    unverified: totalFindings - verified,
    taintTraced,
    exploitable,
    sanitized,
    classCount,
    fileCount,
    langCount,
  };
}

// ─── flat findings list ──────────────────────────────────────────────────────

function flatFindings(results) {
  const out = [];
  for (const chunk of results) {
    for (const f of (chunk.findings || [])) {
      if (f._parse_error) continue;
      // Normalise vuln_class — the LLM writes vuln_name; strip any CWE suffix
      if (!f.vuln_class && f.vuln_name) {
        f.vuln_class = f.vuln_name.replace(/\s*\(CWE[^)]*\)\s*$/i, '').trim();
      } else if (f.vuln_class) {
        f.vuln_class = f.vuln_class.replace(/\s*\(CWE[^)]*\)\s*$/i, '').trim();
      }
      out.push({ chunk, finding: f });
    }
  }
  // Sort: exploitable first, then by severity, then confidence
  out.sort((a, b) => {
    const ae = a.finding.taint?.exploitable === true ? 0 : 1;
    const be = b.finding.taint?.exploitable === true ? 0 : 1;
    if (ae !== be) return ae - be;
    const as = SEV_ORDER[(a.finding.severity || 'unknown').toLowerCase()] ?? 4;
    const bs = SEV_ORDER[(b.finding.severity || 'unknown').toLowerCase()] ?? 4;
    if (as !== bs) return as - bs;
    const ac = { high: 0, medium: 1, low: 2 }[(a.finding.confidence || 'low').toLowerCase()] ?? 2;
    const bc = { high: 0, medium: 1, low: 2 }[(b.finding.confidence || 'low').toLowerCase()] ?? 2;
    return ac - bc;
  });
  return out;
}

// ─── client-side script ──────────────────────────────────────────────────────

function buildClientScript(safeJson) {
  return `
// ── DATA ──────────────────────────────────────────────────────────────────────
const reportData = ${safeJson};

// ── HELPERS ───────────────────────────────────────────────────────────────────

function escH(s) {
  if (!s) return '';
  return String(s).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
}

function sevClass(s) {
  const m = {critical:'severity-critical',high:'severity-high',medium:'severity-medium',low:'severity-low'};
  return m[(s||'').toLowerCase()] || 'severity-unknown';
}
function confClass(c) {
  return {high:'conf-high',medium:'conf-medium',low:'conf-low'}[(c||'').toLowerCase()] || 'conf-low';
}

function taintBadge(taint) {
  if (!taint) return '<span class="text-neutral-600 text-[10px]">—</span>';
  if (taint.exploitable === true)  return '<span class="px-1.5 py-0.5 rounded border text-[10px] font-bold text-red-400 border-red-400">EXPLOITABLE</span>';
  if (taint.reachable   === false) return '<span class="px-1.5 py-0.5 rounded border text-[10px] font-bold text-green-400 border-green-400">UNREACHABLE</span>';
  if (taint.sanitized   === true)  return '<span class="px-1.5 py-0.5 rounded border text-[10px] font-bold text-blue-400 border-blue-400">SANITIZED</span>';
  if (taint.exploitable === false) return '<span class="px-1.5 py-0.5 rounded border text-[10px] font-bold text-yellow-400 border-yellow-400">NOT EXPLOITABLE</span>';
  if (taint.inconclusive_reason === 'orphan_no_callers') return '<span class="px-1.5 py-0.5 rounded border text-[10px] font-bold text-purple-400 border-purple-400">ORPHAN</span>';
  if (taint.error)                 return '<span class="px-1.5 py-0.5 rounded border text-[10px] font-bold text-neutral-500 border-neutral-700">TAINT ERROR</span>';
  return '<span class="px-1.5 py-0.5 rounded border text-[10px] font-bold text-neutral-500 border-neutral-600">TRACED</span>';
}

function validBadge(isValid) {
  if (isValid === true)  return '<span class="px-1.5 py-0.5 rounded border text-[10px] font-bold text-green-400 border-green-400">VALID</span>';
  if (isValid === false) return '<span class="px-1.5 py-0.5 rounded border text-[10px] font-bold text-neutral-500 border-neutral-600 line-through">FALSE POS.</span>';
  return '<span class="px-1.5 py-0.5 rounded border text-[10px] text-neutral-600 border-neutral-700">UNVERIFIED</span>';
}

// ── TAB SWITCHING ─────────────────────────────────────────────────────────────

function switchTab(id) {
  document.querySelectorAll('nav button').forEach(b => b.classList.remove('tab-active'));
  document.getElementById('tab-' + id).classList.add('tab-active');
  document.querySelectorAll('main section').forEach(s => s.classList.add('hidden'));
  document.getElementById('section-' + id).classList.remove('hidden');
}

// ── MODAL ─────────────────────────────────────────────────────────────────────

function closeModal() {
  document.getElementById('modal-overlay').style.display = 'none';
  document.body.style.overflow = 'auto';
}
function openModal(html) {
  document.getElementById('modal-body').innerHTML = html;
  document.getElementById('modal-overlay').style.display = 'flex';
  document.body.style.overflow = 'hidden';
}

// Tracks which chunk the inventory modal is currently showing, so the
// per-finding click handler below can reference it as a real JS value
// instead of re-embedding chunk.id into an onclick="..." attribute string.
// chunk.id is built from the scanned repo's own file paths and function
// names, which are attacker-influenceable (a crafted filename in a
// scanned PR, for example) — HTML-escaping it and interpolating it into
// an inline event-handler attribute is NOT sufficient, because browsers
// HTML-decode attribute values before compiling them as JS, which silently
// undoes the very quote-escaping meant to protect the JS-string context
// (\`onclick="...==='\${escH(chunkId)}'..."\` — a chunkId containing a
// literal quote survives the decode and breaks out of the string literal).
// Keeping chunkId as a real variable and finding index as a plain integer
// data attribute sidesteps the whole class of bug: nothing attacker-
// influenceable is ever re-serialized into a string that gets re-parsed
// as code.
let _currentModalChunkId = null;

// Single delegated listener on the stable #modal-body container — it
// persists across every openModal() call (which only replaces the
// container's innerHTML), so this only needs to run once at load time.
document.addEventListener('DOMContentLoaded', () => {
  const modalBody = document.getElementById('modal-body');
  if (!modalBody) return;
  modalBody.addEventListener('click', (event) => {
    const row = event.target.closest('[data-finding-index]');
    if (!row || !modalBody.contains(row)) return;
    event.stopPropagation();
    const chunkId = _currentModalChunkId;
    const fi = parseInt(row.dataset.findingIndex, 10);
    closeModal();
    setTimeout(() => {
      window._filteredFindings = null;
      renderFindings();
      const chunk = reportData.chunks.find(c => c.id === chunkId);
      if (!chunk) return;
      _renderFindingModal({ chunk, finding: chunk.findings.filter(f => !f._parse_error)[fi] });
    }, 60);
  });
});

// ── DASHBOARD ─────────────────────────────────────────────────────────────────

function renderDashboard() {
  const s = reportData.stats;
  document.getElementById('report-id').textContent = 'GENERATED_AT: ' + reportData.generated_at;
  document.getElementById('stat-findings').textContent    = s.totalFindings;
  document.getElementById('stat-exploitable').textContent = s.exploitable;
  document.getElementById('stat-valid').textContent       = s.verifiedValid;
  document.getElementById('stat-chunks').textContent      = s.chunksWithFindings + ' / ' + s.totalChunks;

  // Severity bar chart
  const sevCtx = document.getElementById('severityChart').getContext('2d');
  new Chart(sevCtx, {
    type: 'bar',
    data: {
      labels: ['Critical','High','Medium','Low','Unknown'],
      datasets: [{ label: 'Findings',
        data: [s.sevCounts.critical, s.sevCounts.high, s.sevCounts.medium, s.sevCounts.low, s.sevCounts.unknown],
        backgroundColor: ['#ef4444','#f87171','#fb923c','#60a5fa','#a3a3a3'],
        borderRadius: 4 }]
    },
    options: { responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        y: { beginAtZero: true, grid: { color: '#262626' }, ticks: { color: '#737373' } },
        x: { grid: { display: false }, ticks: { color: '#737373' } } } }
  });

  // Verification pie
  const verCtx = document.getElementById('verificationChart').getContext('2d');
  new Chart(verCtx, {
    type: 'doughnut',
    data: {
      labels: ['Valid','False Positive','Unverified'],
      datasets: [{ data: [s.verifiedValid, s.verifiedFalsePositive, s.unverified],
        backgroundColor: ['#10b981','#6b7280','#3b82f6'], borderWidth: 0 }]
    },
    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } }
  });

  // Top vuln classes
  const classes = Object.entries(s.classCount)
    .sort((a,b) => b[1]-a[1]).slice(0, 8);
  const ccCtx = document.getElementById('classChart').getContext('2d');
  new Chart(ccCtx, {
    type: 'bar',
    data: {
      labels: classes.map(([k]) => k.length > 26 ? k.slice(0,24)+'…' : k),
      datasets: [{ data: classes.map(([,v]) => v),
        backgroundColor: '#ef4444aa', borderRadius: 4 }]
    },
    options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { beginAtZero: true, grid: { color: '#262626' }, ticks: { color: '#737373' } },
        y: { grid: { display: false }, ticks: { color: '#a3a3a3', font: { size: 10 } } } } }
  });
}

// ── FINDINGS TABLE ────────────────────────────────────────────────────────────

let _allFindings = null;

function getAllFindings() {
  if (_allFindings) return _allFindings;
  const out = [];
  for (const chunk of reportData.chunks) {
    for (const f of (chunk.findings || [])) {
      if (f._parse_error) continue;
      out.push({ chunk, finding: f });
    }
  }
  _allFindings = out;
  return out;
}

function renderFindings(search='', sev='all', conf='all', status='all') {
  const tbody = document.getElementById('findings-table-body');
  tbody.innerHTML = '';
  const q = search.trim().toLowerCase();

  const SEV_ORD = {critical:0,high:1,medium:2,low:3,unknown:4};

  const filtered = getAllFindings().filter(({chunk,finding: f}) => {
    if (q && !(
      (f.vuln_class||'').toLowerCase().includes(q) ||
      (f.title||'').toLowerCase().includes(q) ||
      (chunk.file||'').toLowerCase().includes(q) ||
      (chunk.name||'').toLowerCase().includes(q)
    )) return false;
    if (sev  !== 'all' && (f.severity||'').toLowerCase() !== sev)  return false;
    if (conf !== 'all' && (f.confidence||'').toLowerCase() !== conf) return false;
    if (status === 'exploitable' && f.taint?.exploitable !== true) return false;
    if (status === 'valid'       && f.is_valid !== true) return false;
    if (status === 'fp'          && f.is_valid !== false) return false;
    if (status === 'orphan'      && f.taint?.inconclusive_reason !== 'orphan_no_callers') return false;
    if (status === 'unverified'  && f.is_valid !== undefined && f.is_valid !== null) return false;
    return true;
  });

  filtered.sort((a,b)=>{
    const ae = a.finding.taint?.exploitable===true?0:1;
    const be = b.finding.taint?.exploitable===true?0:1;
    if(ae!==be) return ae-be;
    return (SEV_ORD[(a.finding.severity||'unknown').toLowerCase()]??4)-(SEV_ORD[(b.finding.severity||'unknown').toLowerCase()]??4);
  });

  if (!filtered.length) {
    tbody.innerHTML = '<tr><td colspan="8" class="px-6 py-12 text-center text-neutral-500 italic">No findings match the current filters.</td></tr>';
    return;
  }

  filtered.forEach(({chunk, finding: f}, idx) => {
    const row = document.createElement('tr');
    row.className = 'hover:bg-neutral-800/30 transition-colors cursor-pointer';
    row.onclick = () => openFindingModal(chunk.id, idx);

    const relFile = (chunk.file||'').replace(/\\\\/g,'/').split('/').pop();

    row.innerHTML = \`
      <td class="px-4 py-3">
        <span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold \${sevClass(f.severity)}">\${escH(f.severity||'?')}</span>
      </td>
      <td class="px-4 py-3 text-sm font-medium text-white">\${escH(f.vuln_class||'unknown')}</td>
      <td class="px-4 py-3 text-xs text-neutral-300">\${escH(f.title||'—')}</td>
      <td class="px-4 py-3 mono text-[11px] text-neutral-400">\${escH(relFile)}<span class="text-neutral-600">:\${f.line||chunk.startLine||'?'}</span></td>
      <td class="px-4 py-3 mono text-[11px] text-neutral-300">\${escH(chunk.class ? chunk.class+'.'+chunk.name : chunk.name)}</td>
      <td class="px-4 py-3"><span class="px-1.5 py-0.5 rounded border text-[10px] \${confClass(f.confidence)}">\${escH(f.confidence||'?')}</span></td>
      <td class="px-4 py-3">\${validBadge(f.is_valid)}</td>
      <td class="px-4 py-3">\${taintBadge(f.taint)}</td>
    \`;
    tbody.appendChild(row);
  });

  // Store filtered for modal navigation
  window._filteredFindings = filtered;
}

function openFindingModal(chunkId, idx) {
  const list = window._filteredFindings || getAllFindings();
  const item = list[idx];
  if (!item) {
    // fallback: find by chunkId
    const match = getAllFindings().find(x => x.chunk.id === chunkId);
    if (!match) return;
    _renderFindingModal(match);
  } else {
    _renderFindingModal(item);
  }
}

function _renderFindingModal({chunk, finding: f}) {
  const relFile = (chunk.file||'').replace(/\\\\/g,'/');
  const qual    = chunk.class ? chunk.class + '.' + chunk.name : chunk.name;

  const taint = f.taint || {};
  const taintHtml = f.taint ? \`
    <div class="space-y-3">
      <div class="flex flex-wrap gap-4 items-center">
        \${taintBadge(f.taint)}
        \${taint.reachable   != null ? '<span class="text-xs text-neutral-400">Reachable: <span class="font-semibold '+(taint.reachable?'text-red-400':'text-green-400')+'">'+(taint.reachable?'YES':'NO')+'</span></span>' : ''}
        \${taint.sanitized   === true ? '<span class="text-xs text-neutral-400">Sanitized: <span class="font-semibold text-blue-400">YES</span></span>' : ''}
        \${taint.exploitable != null ? '<span class="text-xs text-neutral-400">Exploitable: <span class="font-semibold '+(taint.exploitable?'text-red-500':'text-green-400')+'">'+(taint.exploitable?'YES':'NO')+'</span></span>' : ''}
      </div>
      \${taint.flow_path ? '<div class="bg-neutral-900 border border-neutral-800 rounded-lg p-3"><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Flow Path</p><p class="mono text-xs text-neutral-300 leading-relaxed">'+escH(taint.flow_path)+'</p></div>' : ''}
      \${taint.rationale  ? '<p class="text-xs text-neutral-400 italic bg-neutral-900/50 px-3 py-2 rounded border border-neutral-800">'+escH(taint.rationale)+'</p>' : ''}
      \${taint.error      ? '<p class="text-xs text-red-400 bg-red-500/5 px-3 py-2 rounded border border-red-500/20">Taint error: '+escH(JSON.stringify(taint.error)  )+'</p>' : ''}
    </div>
  \` : '<p class="text-xs text-neutral-500 italic">Taint trace was not run or produced no output.</p>';

  const verifyHtml = f.is_valid != null ? \`
    <div class="flex items-start gap-3">
      \${validBadge(f.is_valid)}
      \${f.reason ? '<p class="text-xs text-neutral-400 italic">'+escH(f.reason)+'</p>' : ''}
    </div>
  \` : '<p class="text-xs text-neutral-500 italic">Finding was not verified (verify pass skipped or did not run).</p>';

  const snippetHtml = f.code_snippet ? \`
    <pre class="bg-neutral-950 border border-neutral-800 rounded-lg p-4 text-[11px] mono text-neutral-200 overflow-x-auto whitespace-pre-wrap break-words">\${escH(f.code_snippet)}</pre>
  \` : '<p class="text-xs text-neutral-500 italic">No code snippet captured.</p>';

  openModal(\`
    <div class="space-y-6">

      <div class="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <div class="flex items-center gap-3 mb-1 flex-wrap">
            <span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold \${sevClass(f.severity)}">\${escH(f.severity||'?')}</span>
            <h2 class="text-xl font-bold">\${escH(f.vuln_class||'Unknown')}</h2>
          </div>
          <p class="text-neutral-300 text-sm">\${escH(f.title||'')}</p>
        </div>
        <div class="text-right shrink-0">
          <p class="text-[10px] uppercase text-neutral-500 font-bold tracking-widest mb-1">Confidence</p>
          <span class="px-2 py-0.5 rounded border text-sm font-bold \${confClass(f.confidence)}">\${escH(f.confidence||'?')}</span>
        </div>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-3 gap-4 py-4 border-y border-neutral-800">
        <div>
          <p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">File</p>
          <p class="mono text-xs text-neutral-300 break-all">\${escH(relFile)}</p>
        </div>
        <div>
          <p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Function / Method</p>
          <p class="mono text-xs text-neutral-300">\${escH(qual)}</p>
        </div>
        <div>
          <p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Line</p>
          <p class="mono text-xs text-neutral-300">\${f.line || chunk.startLine || '—'}</p>
        </div>
      </div>

      <div>
        <h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-2">Description</h4>
        <p class="text-sm text-neutral-300 leading-relaxed bg-neutral-900/50 p-4 rounded-lg border border-neutral-800">\${escH(f.description||'No description provided.')}</p>
      </div>

      <div>
        <h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-2">Vulnerable Code Snippet</h4>
        \${snippetHtml}
      </div>

      \${f.fix ? \`
      <div>
        <h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-2">Recommended Fix</h4>
        <p class="text-sm text-green-300 leading-relaxed bg-neutral-900/50 p-4 rounded-lg border border-green-900">\${escH(f.fix)}</p>
      </div>\` : ''}

      <div>
        <h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-2">Verification Pass</h4>
        \${verifyHtml}
      </div>

      <div>
        <h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-2">Taint Trace</h4>
        \${taintHtml}
      </div>

      <div class="border-t border-neutral-800 pt-4">
        <h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Chunk Context</h4>
        <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
          <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800"><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Type</p><p class="mono text-xs">\${escH(chunk.type||'—')}</p></div>
          <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800"><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Language</p><p class="mono text-xs">\${escH(chunk.language||'—')}</p></div>
          <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800"><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Start Line</p><p class="mono text-xs">\${chunk.startLine||'—'}</p></div>
          <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800"><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">End Line</p><p class="mono text-xs">\${chunk.endLine||'—'}</p></div>
        </div>
      </div>

      \${f.verification_error ? '<div class="bg-red-500/5 border border-red-500/20 rounded-lg p-3"><p class="text-[10px] uppercase text-red-400 font-bold mb-1">Verification Error</p><p class="mono text-xs text-red-300">'+escH(JSON.stringify(f.verification_error))+'</p></div>' : ''}

    </div>
  \`);
}

// ── INVENTORY (chunks) ────────────────────────────────────────────────────────

function renderInventory(search='', lang='all', type='all') {
  const tbody = document.getElementById('inv-table-body');
  tbody.innerHTML = '';
  const q = search.trim().toLowerCase();

  const filtered = reportData.chunks.filter(chunk => {
    if (q && !(
      (chunk.file||'').toLowerCase().includes(q) ||
      (chunk.name||'').toLowerCase().includes(q) ||
      (chunk.class||'').toLowerCase().includes(q)
    )) return false;
    if (lang !== 'all' && (chunk.language||'') !== lang) return false;
    if (type !== 'all' && (chunk.type||'') !== type)     return false;
    return true;
  });

  if (!filtered.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="px-6 py-12 text-center text-neutral-500 italic">No chunks match the current filters.</td></tr>';
    return;
  }

  filtered.forEach(chunk => {
    const findings = (chunk.findings||[]).filter(f=>!f._parse_error);
    const relFile  = (chunk.file||'').replace(/\\\\/g,'/').split('/').pop();
    const hasFindings = findings.length > 0;
    const exploitable = findings.some(f => f.taint?.exploitable === true);

    const badge = exploitable
      ? '<span class="px-1.5 py-0.5 rounded border text-[10px] font-bold text-red-400 border-red-400">EXPLOITABLE</span>'
      : hasFindings
        ? '<span class="px-1.5 py-0.5 rounded border text-[10px] font-bold text-orange-400 border-orange-400">'+findings.length+' FINDING'+(findings.length>1?'S':'')+'</span>'
        : '<span class="text-[10px] text-neutral-600">clean</span>';

    const row = document.createElement('tr');
    row.className = 'hover:bg-neutral-800/30 transition-colors cursor-pointer';
    row.onclick   = () => openInvModal(chunk.id);
    row.innerHTML = \`
      <td class="px-4 py-3 mono text-[11px] text-neutral-300 break-all">\${escH(relFile)}</td>
      <td class="px-4 py-3 font-medium text-sm">\${escH(chunk.class ? chunk.class+'.'+chunk.name : chunk.name)}</td>
      <td class="px-4 py-3"><span class="text-xs text-neutral-400">\${escH(chunk.type||'—')}</span></td>
      <td class="px-4 py-3"><span class="text-xs text-neutral-400">\${escH(chunk.language||'—')}</span></td>
      <td class="px-4 py-3 mono text-xs text-neutral-500">\${chunk.startLine||'—'}–\${chunk.endLine||'—'}</td>
      <td class="px-4 py-3">\${badge}</td>
    \`;
    tbody.appendChild(row);
  });
}

function openInvModal(chunkId) {
  const chunk = reportData.chunks.find(c => c.id === chunkId);
  if (!chunk) return;
  _currentModalChunkId = chunkId;

  const findings = (chunk.findings||[]).filter(f=>!f._parse_error);
  const errors   = (chunk.findings||[]).filter(f=> f._parse_error);
  const relFile  = (chunk.file||'').replace(/\\\\/g,'/');

  const findingRows = findings.length ? findings.map((f, fi) => \`
    <div class="flex items-center justify-between py-2.5 border-b border-neutral-800 last:border-0 cursor-pointer hover:bg-neutral-800/40 px-2 rounded transition-colors"
         data-finding-index="\${fi}">
      <div class="flex items-center gap-3">
        <span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold \${sevClass(f.severity)}">\${escH(f.severity||'?')}</span>
        <span class="text-sm font-medium">\${escH(f.vuln_class||'unknown')}</span>
        <span class="text-xs text-neutral-500">\${escH(f.title||'')}</span>
      </div>
      <div class="flex items-center gap-2">
        \${validBadge(f.is_valid)}
        \${taintBadge(f.taint)}
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-neutral-500"><polyline points="9 18 15 12 9 6"></polyline></svg>
      </div>
    </div>
  \`).join('') : '<p class="text-sm text-neutral-500 italic py-2">No findings in this chunk.</p>';

  const decorators = (chunk.decorators || []);
  const decHtml = decorators.length
    ? decorators.map(d=>\`<span class="mono text-[10px] bg-neutral-800 px-2 py-1 rounded border border-neutral-700 text-blue-300">\${escH(d)}</span>\`).join('')
    : '<span class="text-neutral-500 text-xs italic">None</span>';

  openModal(\`
    <div class="space-y-6">
      <div class="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <div class="flex items-center gap-3 mb-1 flex-wrap">
            <span class="text-[10px] uppercase font-bold \${findings.length ? 'text-orange-400 border-orange-400' : 'text-green-400 border-green-400'} border px-2 py-0.5 rounded">\${findings.length ? findings.length+' finding'+(findings.length>1?'s':'') : 'clean'}</span>
            <h2 class="text-xl font-bold">\${escH(chunk.class ? chunk.class+'.'+chunk.name : chunk.name)}</h2>
          </div>
          <p class="mono text-[11px] text-neutral-500 break-all">\${escH(chunk.id)}</p>
        </div>
        <div class="text-right shrink-0">
          <p class="text-[10px] uppercase text-neutral-500 font-bold tracking-widest mb-1">Language</p>
          <p class="mono text-sm">\${escH(chunk.language||'—')}</p>
        </div>
      </div>

      <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800"><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Type</p><p class="mono text-xs">\${escH(chunk.type||'—')}</p></div>
        <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800"><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Class</p><p class="mono text-xs">\${escH(chunk.class||'—')}</p></div>
        <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800"><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Start Line</p><p class="mono text-xs">\${chunk.startLine||'—'}</p></div>
        <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800"><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">End Line</p><p class="mono text-xs">\${chunk.endLine||'—'}</p></div>
      </div>

      <div>
        <h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-2">File</h4>
        <p class="mono text-[11px] text-neutral-400 bg-neutral-900 px-3 py-2 rounded border border-neutral-800 break-all">\${escH(relFile)}</p>
      </div>

      <div>
        <h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-2">Decorators / Annotations</h4>
        <div class="flex flex-wrap gap-2">\${decHtml}</div>
      </div>

      <div>
        <h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Findings (\${findings.length})</h4>
        <div class="space-y-0">\${findingRows}</div>
      </div>

      \${errors.length ? \`<div class="bg-red-500/5 border border-red-500/20 rounded-lg p-3"><p class="text-[10px] uppercase text-red-400 font-bold mb-1">Parse Errors (\${errors.length})</p><p class="text-xs text-neutral-500">This chunk produced \${errors.length} parse error(s) during the scan pass. The raw LLM output could not be decoded as valid JSON findings.</p></div>\` : ''}
    </div>
  \`);
}

// ── STATS ─────────────────────────────────────────────────────────────────────

function renderStats() {
  const s = reportData.stats;

  document.getElementById('stats-total').textContent          = s.totalFindings;
  document.getElementById('stats-exploitable').textContent    = s.exploitable;
  document.getElementById('stats-valid').textContent          = s.verifiedValid;
  document.getElementById('stats-fp').textContent             = s.verifiedFalsePositive;
  document.getElementById('stats-unverified').textContent     = s.unverified;
  document.getElementById('stats-taint-traced').textContent   = s.taintTraced;
  document.getElementById('stats-sanitized').textContent      = s.sanitized;
  document.getElementById('stats-parse-errors').textContent   = s.parseErrors;
  document.getElementById('stats-chunks-total').textContent   = s.totalChunks;
  document.getElementById('stats-chunks-hit').textContent     = s.chunksWithFindings;

  // Confidence doughnut
  new Chart(document.getElementById('confChart'), {
    type: 'doughnut',
    data: {
      labels: ['High','Medium','Low'],
      datasets:[{
        data: [s.confCounts.high, s.confCounts.medium, s.confCounts.low],
        backgroundColor: ['#10b981','#f59e0b','#6b7280'], borderWidth: 0
      }]
    },
    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } }
  });

  // Language bar chart
  const langs = Object.entries(s.langCount).sort((a,b)=>b[1]-a[1]);
  new Chart(document.getElementById('langChart'), {
    type: 'bar',
    data: {
      labels: langs.map(([k])=>k),
      datasets:[{ data: langs.map(([,v])=>v), backgroundColor:'#3b82f6aa', borderRadius:4 }]
    },
    options: { responsive: true, maintainAspectRatio: false,
      plugins:{ legend:{ display:false } },
      scales:{
        y:{ beginAtZero:true, grid:{ color:'#262626' }, ticks:{ color:'#737373' } },
        x:{ grid:{ display:false }, ticks:{ color:'#a3a3a3' } }
      }
    }
  });

  // Hot files
  const files = Object.entries(s.fileCount).sort((a,b)=>b[1]-a[1]).slice(0,10);
  const hotFilesEl = document.getElementById('hot-files');
  hotFilesEl.innerHTML = files.length ? files.map(([f,n])=>\`
    <div class="flex items-center justify-between py-1.5 border-b border-neutral-800 last:border-0">
      <span class="mono text-xs text-neutral-300 truncate max-w-[70%]">\${escH(f.split('/').pop())}</span>
      <span class="text-xs font-bold text-orange-400">\${n}</span>
    </div>
  \`).join('') : '<p class="text-xs text-neutral-500 italic">No findings.</p>';
}

// ── SYSTEM ─────────────────────────────────────────────────────────────────────

function renderSystem() {
  const m   = reportData.meta;
  const git = m.gitMetadata  || {};
  const os  = m.osMetadata   || {};

  const s = (id, val) => { const el = document.getElementById(id); if(el) el.textContent = val||'N/A'; };

  s('sys-tool',     SAST_TOOL_NAME);
  s('sys-version',  m.tool_version||'—');
  s('sys-provider', m.provider||'—');
  s('sys-model',    m.model||'—');
  s('sys-dir',      m.workingDir||'—');
  s('sys-platform', m.platform||'—');
  s('sys-arch',     m.arch||'—');
  s('sys-node',     m.runtime_version||'—');

  s('git-branch',  git.branch||'N/A');
  s('git-commit',  git.latest_commit||'N/A');
  s('git-url',     git.url||'N/A');
  s('git-version', git.version||'N/A');

  s('os-id',      os.os_id||'N/A');
  s('os-name',    os.os_name||'N/A');
  s('os-version', os.os_version||'N/A');
}

// ── FILTERS & DROPDOWNS ──────────────────────────────────────────────────────

function setupFilters() {
  const gf = () => [
    document.getElementById('f-search').value,
    document.getElementById('f-sev').value,
    document.getElementById('f-conf').value,
    document.getElementById('f-status').value,
  ];
  ['f-search','f-sev','f-conf','f-status'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener(el.tagName==='INPUT'?'input':'change', ()=>renderFindings(...gf()));
  });

  // Inventory filters
  const gi = () => [
    document.getElementById('i-search').value,
    document.getElementById('i-lang').value,
    document.getElementById('i-type').value,
  ];
  ['i-search','i-lang','i-type'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener(el.tagName==='INPUT'?'input':'change', ()=>renderInventory(...gi()));
  });

  // Populate language dropdown
  const langs = Object.keys(reportData.stats.langCount).sort();
  const langSel = document.getElementById('i-lang');
  langs.forEach(l => {
    const o = document.createElement('option'); o.value=l; o.textContent=l; langSel.appendChild(o);
  });
}

// ── INIT ──────────────────────────────────────────────────────────────────────

const SAST_TOOL_NAME = '${SAST_TOOL}';

function init() {
  closeModal();
  renderDashboard();
  renderFindings();
  renderInventory();
  renderStats();
  renderSystem();
  setupFilters();
}

window.addEventListener('keydown', e => { if (e.key==='Escape') closeModal(); });
document.getElementById('modal-overlay').addEventListener('click', e => { if (e.target.id==='modal-overlay') closeModal(); });

init();
`;
}

// ─── main generator ──────────────────────────────────────────────────────────

export function generateSastHTMLReport(results, meta = {}) {
  const stats = buildStats(results);

  // Inventory: chunks stripped of code (no source in report)
  const inventory = results.map(chunk => ({
    id:         chunk.id,
    file:       chunk.file,
    type:       chunk.type,
    class:      chunk.class  || null,
    name:       chunk.name,
    language:   chunk.language,
    startLine:  chunk.startLine,
    endLine:    chunk.endLine,
    // Decorators/annotations prepended to chunks by the chunker
    // are the leading lines before the def/fn/fun signature.
    // We extract them by scanning lines that start with @, #[, etc.
    decorators: _extractDecorators(chunk),
    findings:   (chunk.findings || []).map(f => ({
      vuln_class:         f.vuln_class         || null,
      title:              f.title              || null,
      description:        f.description        || null,
      code_snippet:       f.code_snippet       || null,
      confidence:         f.confidence         || null,
      severity:           f.severity           || null,
      line:               f.line               || null,
      is_valid:           f.is_valid           ?? null,
      reason:             f.reason             || null,
      verification_error: f.verification_error || null,
      taint:              f.taint || null,
      _parse_error:       f._parse_error       || false,
    })),
  }));

  const reportPayload = {
    generated_at: meta.generated_at || new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
    stats,
    meta: {
      tool_version:    TOOL_VERSION,
      provider:        meta.provider        || null,
      model:           meta.model           || null,
      workingDir:      meta.workingDir      || null,
      platform:        process.platform,
      arch:            process.arch,
      runtime_version: process.version.replace(/^v/,''),
      gitMetadata:     meta.gitMetadata     || null,
      osMetadata:      meta.osMetadata      || null,
    },
    chunks: inventory,
  };

  const safeJson     = escapeForScript(reportPayload);
  const clientScript = buildClientScript(safeJson);

  return `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>UBEL SAST — Security Report</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    :root { --bg: #0a0a0a; --card: #141414; --border: #262626; --accent: #ef4444; }
    body { font-family: 'Inter', sans-serif; background-color: var(--bg); color: #e5e5e5; }
    .mono { font-family: 'JetBrains Mono', monospace; }
    .glass { background: rgba(20,20,20,0.8); backdrop-filter: blur(12px); border: 1px solid var(--border); }
    .severity-critical { color: #ef4444; border-color: #ef4444; font-weight: bold; }
    .severity-high     { color: #f87171; border-color: #f87171; }
    .severity-medium   { color: #fb923c; border-color: #fb923c; }
    .severity-low      { color: #60a5fa; border-color: #60a5fa; }
    .severity-unknown  { color: #a3a3a3; border-color: #a3a3a3; }
    .conf-high   { color: #10b981; border-color: #10b981; }
    .conf-medium { color: #f59e0b; border-color: #f59e0b; }
    .conf-low    { color: #6b7280; border-color: #6b7280; }
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: var(--bg); }
    ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 10px; }
    .tab-active { border-bottom: 2px solid var(--accent); color: white; }
    .modal-overlay { display: none; position: fixed; top:0; left:0; width:100%; height:100%;
                     background: rgba(0,0,0,0.85); z-index:50; backdrop-filter: blur(4px); }
    .modal-content { max-height: 90vh; overflow-y: auto; }
  </style>
</head>
<body class="min-h-screen flex flex-col">

  <!-- ── HEADER ─────────────────────────────────────────────────────────── -->
  <header class="border-b border-neutral-800 bg-neutral-900/50 sticky top-0 z-40 backdrop-blur-md">
    <div class="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
      <div class="flex items-center gap-3">
        <div class="w-8 h-8 bg-red-600 rounded flex items-center justify-center font-bold text-white text-sm">S</div>
        <div>
          <h1 class="text-lg font-semibold tracking-tight">SAST Security Report</h1>
          <p class="text-xs text-neutral-500 mono" id="report-id">GENERATED_AT: ...</p>
        </div>
      </div>
      <span class="px-3 py-1 rounded-full text-xs font-medium uppercase tracking-wider bg-red-500/20 text-red-400 border border-red-500/50">
        ${SAST_TOOL} v${TOOL_VERSION}
      </span>
    </div>
  </header>

  <!-- ── NAV ───────────────────────────────────────────────────────────── -->
  <nav class="border-b border-neutral-800 bg-neutral-900/30">
    <div class="max-w-7xl mx-auto px-4 flex gap-8 overflow-x-auto">
      <button onclick="switchTab('dashboard')"      id="tab-dashboard"      class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors tab-active">Dashboard</button>
      <button onclick="switchTab('findings')"       id="tab-findings"       class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Findings</button>
      <button onclick="switchTab('inventory')"      id="tab-inventory"      class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Chunk Inventory</button>
      <button onclick="switchTab('stats')"          id="tab-stats"          class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Detailed Stats</button>
      <button onclick="switchTab('system')"         id="tab-system"         class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">System Info</button>
    </div>
  </nav>

  <!-- ── MAIN ──────────────────────────────────────────────────────────── -->
  <main class="flex-1 max-w-7xl mx-auto w-full p-4 md:p-8">

    <!-- Dashboard -->
    <section id="section-dashboard" class="space-y-8">
      <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div class="glass p-6 rounded-xl border-l-4 border-l-red-500">
          <p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Total Findings</p>
          <p class="text-3xl font-bold text-red-400" id="stat-findings">0</p>
        </div>
        <div class="glass p-6 rounded-xl border-l-4 border-l-orange-500">
          <p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Exploitable</p>
          <p class="text-3xl font-bold text-orange-400" id="stat-exploitable">0</p>
        </div>
        <div class="glass p-6 rounded-xl border-l-4 border-l-green-500">
          <p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Verified Valid</p>
          <p class="text-3xl font-bold text-green-400" id="stat-valid">0</p>
        </div>
        <div class="glass p-6 rounded-xl">
          <p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Chunks Hit / Total</p>
          <p class="text-3xl font-bold" id="stat-chunks">0</p>
        </div>
      </div>

      <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <div class="glass p-6 rounded-xl lg:col-span-1">
          <h3 class="text-sm font-semibold mb-4 uppercase tracking-widest text-neutral-400">Severity Distribution</h3>
          <div class="h-56"><canvas id="severityChart"></canvas></div>
        </div>
        <div class="glass p-6 rounded-xl">
          <h3 class="text-sm font-semibold mb-4 uppercase tracking-widest text-neutral-400">Verification</h3>
          <div class="h-40"><canvas id="verificationChart"></canvas></div>
          <div class="mt-4 space-y-1 text-xs">
            <div class="flex items-center gap-2"><div class="w-2 h-2 rounded-full bg-green-500"></div><span class="text-neutral-400">Valid</span></div>
            <div class="flex items-center gap-2"><div class="w-2 h-2 rounded-full bg-neutral-500"></div><span class="text-neutral-400">False Positive</span></div>
            <div class="flex items-center gap-2"><div class="w-2 h-2 rounded-full bg-blue-500"></div><span class="text-neutral-400">Unverified</span></div>
          </div>
        </div>
        <div class="glass p-6 rounded-xl">
          <h3 class="text-sm font-semibold mb-4 uppercase tracking-widest text-neutral-400">Top Vulnerability Classes</h3>
          <div class="h-56"><canvas id="classChart"></canvas></div>
        </div>
      </div>
    </section>

    <!-- Findings -->
    <section id="section-findings" class="hidden space-y-6">
      <div class="flex flex-col md:flex-row gap-4 justify-between items-start md:items-center">
        <h2 class="text-xl font-bold">Findings</h2>
        <div class="flex flex-wrap gap-2 w-full md:w-auto">
          <input type="text" id="f-search" placeholder="Search vuln class, title, file…"
            class="bg-neutral-800 border border-neutral-700 rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-red-500 w-full md:w-56">
          <select id="f-sev"    class="bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none">
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="unknown">Unknown</option>
          </select>
          <select id="f-conf"   class="bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none">
            <option value="all">All Confidence</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select id="f-status" class="bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none">
            <option value="all">All Statuses</option>
            <option value="exploitable">Exploitable</option>
            <option value="valid">Verified Valid</option>
            <option value="fp">False Positive</option>
            <option value="orphan">Orphan (No Callers)</option>
            <option value="unverified">Unverified</option>
          </select>
        </div>
      </div>
      <div class="glass rounded-xl overflow-x-auto">
        <table class="w-full text-left text-sm">
          <thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest">
            <tr>
              <th class="px-4 py-3">Severity</th>
              <th class="px-4 py-3">Vuln Class</th>
              <th class="px-4 py-3">Title</th>
              <th class="px-4 py-3">File:Line</th>
              <th class="px-4 py-3">Function</th>
              <th class="px-4 py-3">Confidence</th>
              <th class="px-4 py-3">Verified</th>
              <th class="px-4 py-3">Taint</th>
            </tr>
          </thead>
          <tbody id="findings-table-body" class="divide-y divide-neutral-800"></tbody>
        </table>
      </div>
    </section>

    <!-- Chunk Inventory -->
    <section id="section-inventory" class="hidden space-y-6">
      <div class="flex flex-col md:flex-row gap-4 justify-between items-start md:items-center">
        <h2 class="text-xl font-bold">Chunk Inventory</h2>
        <div class="flex flex-wrap gap-2 w-full md:w-auto">
          <input type="text" id="i-search" placeholder="Search file, name, class…"
            class="bg-neutral-800 border border-neutral-700 rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 w-full md:w-56">
          <select id="i-lang" class="bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none">
            <option value="all">All Languages</option>
          </select>
          <select id="i-type" class="bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none">
            <option value="all">All Types</option>
            <option value="function">Function</option>
            <option value="method">Method</option>
            <option value="struct">Struct</option>
            <option value="module_level">Module Level</option>
          </select>
        </div>
      </div>
      <div class="glass rounded-xl overflow-x-auto">
        <table class="w-full text-left text-sm">
          <thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest">
            <tr>
              <th class="px-4 py-3">File</th>
              <th class="px-4 py-3">Function / Method</th>
              <th class="px-4 py-3">Type</th>
              <th class="px-4 py-3">Language</th>
              <th class="px-4 py-3">Lines</th>
              <th class="px-4 py-3">Status</th>
            </tr>
          </thead>
          <tbody id="inv-table-body" class="divide-y divide-neutral-800"></tbody>
        </table>
      </div>
    </section>

    <!-- Detailed Stats -->
    <section id="section-stats" class="hidden space-y-8">
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">

        <div class="glass p-6 rounded-xl space-y-4">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Finding Counts</h3>
          <div class="space-y-2 text-sm">
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500">Total</span><span class="mono" id="stats-total">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-red-400">Exploitable</span><span class="mono text-red-400" id="stats-exploitable">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-green-400">Verified Valid</span><span class="mono text-green-400" id="stats-valid">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500">False Positives</span><span class="mono" id="stats-fp">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-blue-400">Unverified</span><span class="mono text-blue-400" id="stats-unverified">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500">Taint Traced</span><span class="mono" id="stats-taint-traced">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500">Sanitized</span><span class="mono" id="stats-sanitized">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500">Parse Errors</span><span class="mono" id="stats-parse-errors">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500">Chunks Analyzed</span><span class="mono" id="stats-chunks-total">0</span></div>
            <div class="flex justify-between"><span class="text-neutral-500">Chunks With Findings</span><span class="mono" id="stats-chunks-hit">0</span></div>
          </div>
        </div>

        <div class="glass p-6 rounded-xl space-y-4">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Confidence Distribution</h3>
          <div class="h-40"><canvas id="confChart"></canvas></div>
          <div class="space-y-1 text-xs">
            <div class="flex items-center gap-2"><div class="w-2 h-2 rounded-full bg-green-500"></div><span class="text-neutral-400">High</span></div>
            <div class="flex items-center gap-2"><div class="w-2 h-2 rounded-full bg-yellow-500"></div><span class="text-neutral-400">Medium</span></div>
            <div class="flex items-center gap-2"><div class="w-2 h-2 rounded-full bg-neutral-500"></div><span class="text-neutral-400">Low</span></div>
          </div>
        </div>

        <div class="glass p-6 rounded-xl space-y-4">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Findings by Language</h3>
          <div class="h-48"><canvas id="langChart"></canvas></div>
        </div>

        <div class="glass p-6 rounded-xl space-y-3 md:col-span-2 lg:col-span-3">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Hottest Files (by finding count)</h3>
          <div id="hot-files" class="space-y-0"></div>
        </div>

      </div>
    </section>

    <!-- System Info -->
    <section id="section-system" class="hidden space-y-8">
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">

        <div class="glass p-6 rounded-xl space-y-4">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400 flex items-center gap-2">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>
            Tool &amp; Runtime
          </h3>
          <div class="space-y-3 text-sm">
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">Tool</span><span class="mono text-xs" id="sys-tool">—</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">Version</span><span class="mono text-xs" id="sys-version">—</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">Provider</span><span class="mono text-xs" id="sys-provider">—</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">Model</span><span class="mono text-xs" id="sys-model">—</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">Platform</span><span class="mono text-xs" id="sys-platform">—</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">Arch</span><span class="mono text-xs" id="sys-arch">—</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">Node</span><span class="mono text-xs" id="sys-node">—</span></div>
            <div class="flex flex-col gap-1"><span class="text-neutral-500 text-xs">Working Dir</span><span class="mono text-[10px] break-all bg-neutral-900 p-2 rounded" id="sys-dir">—</span></div>
          </div>
        </div>

        <div class="glass p-6 rounded-xl space-y-4">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400 flex items-center gap-2">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="18" cy="18" r="3"/><circle cx="6" cy="6" r="3"/><path d="M13 6h3a2 2 0 0 1 2 2v7"/><line x1="6" y1="9" x2="6" y2="21"/></svg>
            Git Metadata
          </h3>
          <div class="space-y-3 text-sm">
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">Version</span><span class="mono text-xs" id="git-version">—</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">Branch</span><span class="mono text-xs" id="git-branch">—</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">Commit</span><span class="mono text-xs" id="git-commit">—</span></div>
            <div class="flex flex-col gap-1"><span class="text-neutral-500 text-xs">Remote URL</span><span class="mono text-[10px] break-all bg-neutral-900 p-2 rounded" id="git-url">—</span></div>
          </div>
        </div>

        <div class="glass p-6 rounded-xl space-y-4">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400 flex items-center gap-2">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
            OS Metadata
          </h3>
          <div class="space-y-3 text-sm">
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">OS ID</span><span class="mono text-xs" id="os-id">—</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">OS Name</span><span class="mono text-xs" id="os-name">—</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">OS Version</span><span class="mono text-xs" id="os-version">—</span></div>
          </div>
        </div>

      </div>
    </section>

  </main>

  <!-- ── FOOTER ─────────────────────────────────────────────────────────── -->
  <footer class="border-t border-neutral-800 p-6 bg-neutral-900/50">
    <div class="max-w-7xl mx-auto flex flex-col md:flex-row justify-between items-center gap-4">
      <p class="text-xs text-neutral-500">Powered by <span class="text-neutral-300 font-semibold">${SAST_TOOL}</span></p>
    </div>
  </footer>

  <!-- ── MODAL ──────────────────────────────────────────────────────────── -->
  <div id="modal-overlay" class="modal-overlay items-center justify-center p-4" style="display:none;">
    <div class="modal-content glass w-full max-w-3xl rounded-2xl shadow-2xl relative">
      <button onclick="closeModal()" class="absolute top-6 right-6 text-neutral-500 hover:text-white transition-colors">
        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
      </button>
      <div id="modal-body" class="p-8"></div>
    </div>
  </div>

  <script>${clientScript}</script>
</body>
</html>`;
}

// ─── decorator extractor ─────────────────────────────────────────────────────

function _extractDecorators(chunk) {
  // Decorators/annotations were prepended by the chunker as leading lines
  // before the def/fn/fun/function signature. We extract them from the
  // chunk's code so the inventory modal can surface them without exposing
  // the full source body.
  if (!chunk.code || typeof chunk.code !== 'string') return [];
  const lines = chunk.code.split('\n');
  const out   = [];
  for (const line of lines) {
    const t = line.trim();
    // Python / JS/TS / Kotlin decorators
    if (/^@[A-Za-z_][\w.]*/.test(t)) { out.push(t); continue; }
    // Rust / PHP attributes
    if (/^#!?\[/.test(t))             { out.push(t); continue; }
    // Ruby macros (bare method call before def)
    if (/^[a-z_]\w*[\s(]/.test(t) && !/^def\b|^end\b|^class\b|^module\b/.test(t)) {
      // Only collect if it appears before any function signature line
      if (!out.length && /^(before_action|after_action|around_action|skip_before_action|validates?|attr_|belongs_to|has_many|has_one|scope|let!?|subject|memoize|authorize|authenticate|throttle|cache|deprecated)\b/.test(t)) {
        out.push(t);
      }
      continue;
    }
    // Stop at the function/method declaration line
    if (/^(def|fn\s|fun\s|function\s|async\s|public\s|private\s|protected\s|static\s|export\s)/.test(t)) break;
  }
  return out;
}