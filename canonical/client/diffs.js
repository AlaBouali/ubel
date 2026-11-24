/* canonical/client/diffs.js — the severity view of the Diffs tab, shared by every canonical report family.
 *
 * Each family's client (appscan / cloud / easm / posture / sast / sca) turns the module's own diff data into three plain lists,
 *   { new: [...], existing: [...], fixed: [...] }   with entries { title, type, severity }
 * and hands them to UBEL_DIFFS.sectionHtml(). The helper splits them by severity level (critical → info) and draws one card per
 * level with New / Existing / Fixed counts. A count opens a modal holding a small table (Title, Type) with a search box and
 * pagination. The per-framework compliance diffs are NOT handled here: they stay in each family's own code, unchanged.
 *
 * Self-contained on purpose (own escaping, own click handling, no dependency on a family's helpers), loaded before the family bundle. */
(function () {
  'use strict';

  var PAGE_SIZE = 10;
  var LEVELS = [['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low'], ['info', 'Info']];
  var EXTRA_LEVELS = [['infection', 'Infection'], ['unknown', 'Unknown']];   // drawn only when something falls into them
  var LISTS = [['new', 'New', 'text-red-400'], ['existing', 'Existing', 'text-yellow-400'], ['fixed', 'Fixed', 'text-green-400']];
  var COLORS = { critical: '#ef4444', high: '#f87171', medium: '#fb923c', low: '#60a5fa', info: '#a3a3a3', infection: '#c084fc', unknown: '#737373' };

  var state = { lists: null, modal: null, bound: false };

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; });
  }

  // one vocabulary for every module: moderate → medium, informational → info, anything unrecognised → unknown
  function sevKey(s) {
    s = String(s == null ? '' : s).trim().toLowerCase();
    if (s === 'moderate') s = 'medium';
    else if (s === 'informational' || s === 'none') s = 'info';
    return COLORS[s] ? s : 'unknown';
  }

  function label(key) {
    var all = LEVELS.concat(EXTRA_LEVELS);
    for (var i = 0; i < all.length; i++) if (all[i][0] === key) return all[i][1];
    return key;
  }

  function badge(key) {
    return '<span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold" style="color:' + COLORS[key] + ';border-color:' + COLORS[key] + '">' + esc(label(key)) + '</span>';
  }

  // { severity: { new: [], existing: [], fixed: [] } }
  function bucketize(lists) {
    var out = {};
    Object.keys(COLORS).forEach(function (k) { out[k] = { 'new': [], existing: [], fixed: [] }; });
    LISTS.forEach(function (l) {
      ((lists && lists[l[0]]) || []).forEach(function (e) {
        if (!e) return;
        out[sevKey(e.severity)][l[0]].push({ title: String(e.title == null || e.title === '' ? 'Untitled' : e.title), type: String(e.type == null || e.type === '' ? '—' : e.type) });
      });
    });
    return out;
  }

  // The "By severity" block: one card per level, each with three count buttons.
  function sectionHtml(lists, opts) {
    opts = opts || {};
    var buckets = bucketize(lists);
    state.lists = buckets;
    var levels = LEVELS.slice();
    EXTRA_LEVELS.forEach(function (x) {
      var b = buckets[x[0]];
      if (b['new'].length || b.existing.length || b.fixed.length) levels.push(x);
    });
    var html = '<div class="space-y-3"><div><h3 class="text-lg font-bold">By severity</h3>' +
      '<p class="text-xs text-neutral-500">' + esc(opts.hint || 'Findings compared with the previous report, split by severity level. Select a count to list them.') + '</p></div>' +
      '<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">';
    levels.forEach(function (lv) {
      html += '<div class="glass rounded-xl p-5 space-y-3"><div>' + badge(lv[0]) + '</div><div class="grid grid-cols-3 gap-2">';
      LISTS.forEach(function (l) {
        var n = buckets[lv[0]][l[0]].length;
        html += '<button type="button" data-sevdiff-sev="' + lv[0] + '" data-sevdiff-list="' + l[0] + '"' + (n ? '' : ' disabled') +
          ' class="bg-neutral-900 border border-neutral-800 rounded-lg p-3 text-left transition-colors ' + (n ? 'hover:border-neutral-500' : 'opacity-40 cursor-default') + '">' +
          '<span class="block text-[9px] uppercase tracking-widest text-neutral-500 font-bold">' + l[1] + '</span>' +
          '<span class="block text-2xl font-bold mono ' + l[2] + '">' + n + '</span></button>';
      });
      html += '</div></div>';
    });
    return html + '</div></div>';
  }

  // ── the modal: Title | Type, searchable, paginated ──

  function open(sev, list) {
    var items = state.lists && state.lists[sev] && state.lists[sev][list];
    if (!items || !items.length) return;
    var listLabel = (LISTS.filter(function (l) { return l[0] === list; })[0] || [0, list])[1];
    state.modal = { items: items, filtered: items, page: 0, q: '' };
    document.getElementById('modal-body').innerHTML =
      '<div class="space-y-3">' +
        '<div class="flex items-center gap-3 pr-8">' + badge(sev) + '<h3 class="text-lg font-bold">' + esc(listLabel) + ' findings</h3></div>' +
        '<p class="text-xs text-neutral-500" data-sd-count></p>' +
        '<input type="search" data-sd-search autocomplete="off" placeholder="Search title or type…" aria-label="Search findings" ' +
          'class="w-full bg-neutral-900 border border-neutral-800 focus:border-neutral-500 outline-none rounded-lg px-3 py-2 text-xs text-neutral-200 placeholder-neutral-600">' +
        '<div class="overflow-x-auto"><table class="w-full text-left text-xs"><thead class="text-neutral-500 uppercase text-[10px] tracking-widest"><tr>' +
          '<th class="pb-2 pr-4 font-bold">Title</th><th class="pb-2 font-bold whitespace-nowrap">Type</th></tr></thead>' +
          '<tbody class="divide-y divide-neutral-800" data-sd-rows></tbody></table></div>' +
        '<div class="flex items-center justify-between gap-3 pt-1 text-[11px] text-neutral-500" data-sd-pager></div>' +
      '</div>';
    document.getElementById('modal-overlay').style.display = 'flex';
    document.body.style.overflow = 'hidden';
    paint();
  }

  function paint() {
    var m = state.modal;
    var body = document.getElementById('modal-body');
    if (!m || !body) return;
    var rowsEl = body.querySelector('[data-sd-rows]');
    if (!rowsEl) return;
    var pages = Math.max(1, Math.ceil(m.filtered.length / PAGE_SIZE));
    if (m.page >= pages) m.page = pages - 1;
    if (m.page < 0) m.page = 0;
    var from = m.page * PAGE_SIZE, slice = m.filtered.slice(from, from + PAGE_SIZE);

    rowsEl.innerHTML = slice.length ? slice.map(function (e) {
      return '<tr><td class="py-2 pr-4 font-medium text-neutral-200 break-words">' + esc(e.title) + '</td>' +
        '<td class="py-2 text-neutral-400 mono whitespace-nowrap">' + esc(e.type) + '</td></tr>';
    }).join('') : '<tr><td colspan="2" class="py-6 text-center text-neutral-500 italic">No matches.</td></tr>';

    body.querySelector('[data-sd-count]').textContent = m.q
      ? m.filtered.length + ' of ' + m.items.length + ' item(s)'
      : m.items.length + ' item(s)';

    var pager = body.querySelector('[data-sd-pager]');
    if (m.filtered.length <= PAGE_SIZE) { pager.innerHTML = ''; return; }
    var btn = 'px-3 py-1 rounded border border-neutral-800 text-neutral-300 transition-colors ';
    pager.innerHTML =
      '<span class="mono">' + (from + 1) + '–' + (from + slice.length) + ' of ' + m.filtered.length + '</span>' +
      '<div class="flex items-center gap-2">' +
        '<button type="button" data-sd-page="prev" class="' + btn + (m.page === 0 ? 'opacity-40 cursor-default' : 'hover:border-neutral-500') + '"' + (m.page === 0 ? ' disabled' : '') + '>Prev</button>' +
        '<span class="mono">Page ' + (m.page + 1) + ' / ' + pages + '</span>' +
        '<button type="button" data-sd-page="next" class="' + btn + (m.page >= pages - 1 ? 'opacity-40 cursor-default' : 'hover:border-neutral-500') + '"' + (m.page >= pages - 1 ? ' disabled' : '') + '>Next</button>' +
      '</div>';
  }

  function applyQuery(q) {
    var m = state.modal;
    if (!m) return;
    m.q = q;
    var terms = q.toLowerCase().split(/\s+/).filter(Boolean);
    m.filtered = terms.length ? m.items.filter(function (e) {
      var hay = (e.title + ' ' + e.type).toLowerCase();
      return terms.every(function (t) { return hay.indexOf(t) !== -1; });
    }) : m.items;
    m.page = 0;
    paint();
  }

  function bind() {
    if (state.bound) return;
    state.bound = true;
    document.addEventListener('click', function (e) {
      var t = e.target && e.target.closest ? e.target : null;
      if (!t) return;
      var tile = t.closest('[data-sevdiff-sev]');
      if (tile && !tile.disabled) { open(tile.getAttribute('data-sevdiff-sev'), tile.getAttribute('data-sevdiff-list')); return; }
      var pg = t.closest('[data-sd-page]');
      if (pg && state.modal && !pg.disabled) {
        state.modal.page += pg.getAttribute('data-sd-page') === 'next' ? 1 : -1;
        paint();
      }
    });
    document.addEventListener('input', function (e) {
      if (e.target && e.target.matches && e.target.matches('[data-sd-search]')) applyQuery(e.target.value);
    });
  }
  bind();

  window.UBEL_DIFFS = { sectionHtml: sectionHtml, sevKey: sevKey };
})();
