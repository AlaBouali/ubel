'use strict';
// defs.js — reads what a server tells the model: tool, resource and prompt definitions and the `instructions` of the initialize reply.
// A client shows a user the tool NAME and perhaps a short description; the model reads all of it, including every string in the input schema.
// This module looks for text that is addressed to the model, text that is hidden from the person, look-alike names, tools that can run commands
// or change data, annotations that lie, and definitions that changed since the previous scan. It only reads; it never calls a tool.

import crypto from 'node:crypto';

const sha = s => crypto.createHash('sha256').update(s).digest('hex');
export function canonical(v) {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v && typeof v === 'object') return `{${Object.keys(v).sort().map(k => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`;
  return JSON.stringify(v) ?? 'null';
}
export const hashes = tool => ({
  hash: sha(canonical(tool)).slice(0, 32),
  description_hash: sha(String(tool.description ?? '')).slice(0, 32),
  schema_hash: sha(canonical(tool.inputSchema ?? null)).slice(0, 32),
});

/** Every string in a value, with its path (so evidence says where: tools.add.inputSchema.properties.a.description). */
export function collectStrings(v, p = '', out = [], depth = 0) {
  if (depth > 12 || out.length > 2000) return out;
  if (typeof v === 'string') out.push({ path: p, text: v });
  else if (Array.isArray(v)) v.forEach((x, i) => collectStrings(x, `${p}[${i}]`, out, depth + 1));
  else if (v && typeof v === 'object') for (const [k, x] of Object.entries(v)) { out.push({ path: `${p}.${k}`, text: k, isKey: true }); collectStrings(x, `${p}.${k}`, out, depth + 1); }
  return out;
}

// ── hidden characters ────────────────────────────────────────────────────────────────────────────────────────────────────────
const EMOJI_ZWJ = /(?<=\p{Extended_Pictographic}\uFE0F?)\u200D(?=\p{Extended_Pictographic})/gu;
const HIDDEN = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u00AD\u061C\u115F\u1160\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u206F\u3164\uFE00-\uFE0D\uFEFF\uFFA0]|[\u{E0000}-\u{E007F}]|[\u{E0100}-\u{E01EF}]/gu;
const TAGS = /[\u{E0020}-\u{E007E}]/gu;
export function hiddenChars(text) {
  const s = text.replace(EMOJI_ZWJ, '');
  const found = s.match(HIDDEN);
  if (!found) return null;
  const decoded = [...(s.match(TAGS) || [])].map(c => String.fromCharCode(c.codePointAt(0) - 0xE0000)).join('');
  const kinds = new Set(found.map(c => { const cp = c.codePointAt(0); return cp >= 0xE0000 && cp <= 0xE007F ? 'Unicode tag characters' : cp >= 0xE0100 ? 'variation selectors' : (cp >= 0x202A && cp <= 0x202E) || (cp >= 0x2066 && cp <= 0x2069) || cp === 0x061C ? 'bidirectional controls' : cp < 0x20 || (cp >= 0x7F && cp <= 0x9F) ? 'control characters' : 'zero-width / invisible characters'; }));
  return { count: found.length, kinds: [...kinds], decoded };
}
const visible = s => String(s).replace(HIDDEN, '·').replace(/\s+/g, ' ').trim();
const snip = (s, n = 180) => { const t = visible(s); return t.length > n ? `${t.slice(0, n - 1)}…` : t; };

// ── text addressed to the model ──────────────────────────────────────────────────────────────────────────────────────────────
// strong = 4, medium = 2, weak = 1. A single strong signal is a finding; weak signals alone never are (legitimate descriptions are imperative).
const PATTERNS = [
  ['override instructions', 4, /\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(?:previous|prior|above|earlier|all|any|system|safety)\b[^.\n]{0,30}\b(?:instructions?|rules?|prompts?|guidelines?|constraints?|policies|restrictions?)\b/i],
  ['conceals from the user', 4, /\b(?:do not|don'?t|never|without)\b[^.\n]{0,40}\b(?:tell|inform|notify|mention|reveal|show|alert|let|warn)\b[^.\n]{0,30}\b(?:the )?(?:user|human|person)\b|\b(?:user|human)\b[^.\n]{0,20}\b(?:must not|should not|shouldn'?t|cannot|can'?t)\b[^.\n]{0,20}\b(?:know|see|notice|find out)\b/i],
  ['pseudo-system tag', 4, /<\s*\/?\s*(?:important|system|instructions?|admin|override|secret|hidden|assistant|sudo)\s*>|\[\s*(?:system|admin|important)\s*(?:message|note|instruction)?\s*\]|<<\s*(?:sys|system)\s*>>/i],
  ['credential or system file', 4, /(?:~|\$HOME|%USERPROFILE%|\/home\/[\w.-]+|\/Users\/[\w.-]+|C:\\Users\\[\w.-]+)?[\\/]?\.(?:ssh|aws|gnupg|kube|docker\/config|npmrc|netrc|git-credentials)\b|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|\bmcp\.json\b|\bclaude_desktop_config\b|\/etc\/(?:passwd|shadow)\b|\.env\b(?![.\w-])|\bcredentials?\.json\b|\bprivate[_ ]key\b/i],
  ['secrecy wording', 2, /\b(?:secretly|silently|covertly|quietly|discreetly|stealthily|in the background without)\b/i],
  ['data to a URL', 2, /\b(?:send|post|upload|forward|transmit|exfiltrate|leak|submit|include|append|attach)\b[^.\n]{0,80}\b(?:to|at|via|into)\b[^.\n]{0,25}(?:https?:\/\/|[a-z0-9.-]+\.[a-z]{2,}\/)/i],
  ['markdown image to a URL', 2, /!\[[^\]]*\]\(\s*https?:\/\/[^)\s]+\)/i],
  ['redirects other tools', 2, /\b(?:instead of|rather than|in place of)\b[^.\n]{0,40}\b(?:using|calling|the)\b[^.\n]{0,40}\btool\b|\b(?:before|prior to)\b[^.\n]{0,25}\b(?:using|calling|any|every|other)\b[^.\n]{0,30}\btool\b|\b(?:always|first)\b[^.\n]{0,20}\bcall (?:this|the)\b[^.\n]{0,20}\b(?:tool|function)\b|\b(?:after|when)\b[^.\n]{0,15}\b(?:every|any|each)\b[^.\n]{0,25}\b(?:tool|request|message|response)\b/i],
  ['collects conversation or secrets', 2, /\b(?:read|cat|open|load|retrieve|collect|gather|include|append|attach|pass)\b[^.\n]{0,60}\b(?:conversation|chat history|system prompt|previous messages|all (?:the )?(?:files|messages)|environment variables?|api keys?|tokens?|passwords?|secrets?|credentials?)\b/i],
  ['encoded blob', 2, /\b[A-Za-z0-9+/]{120,}={0,2}\b|\b(?:[0-9a-f]{2}){60,}\b/],
  ['imperative at the model', 1, /\byou (?:must|should|need to|have to|are required to|will)\b|\b(?:it is|this is) (?:very |extremely |absolutely )?(?:important|critical|essential|mandatory) (?:that|to)\b|\bmandatory\b/i],
];

// Hostile input is bounded three ways so that scoring stays linear: whitespace runs are collapsed first (so padding cannot push text out of the
// window, and is itself reported), a string longer than 2 × 20,000 characters is read at its head and tail, and one scan has a total budget.
const SCAN_CHARS = 20000;
const BUDGET_CHARS = 3_000_000;

function squeeze(text) {
  let padded = false;
  const out = text.replace(/[ \t\r\n\u00A0]{90,}/g, (m, off) => { if (off + m.length < text.length) padded = true; return ' '; });   // no look-ahead: linear
  return { out, padded };
}
function htmlComment(text) {
  const i = text.indexOf('<!--');
  if (i < 0) return null;
  const j = text.indexOf('-->', i + 4);
  return j >= 0 && j - i >= 8 ? snip(text.slice(i, j + 3), 140) : null;
}

function scoreText(full, budget) {
  const { out, padded } = squeeze(full);
  let text = out, partial = false;
  if (text.length > 2 * SCAN_CHARS) { text = `${text.slice(0, SCAN_CHARS)}\n${text.slice(-SCAN_CHARS)}`; partial = true; }
  if (budget.left < text.length) { budget.exhausted = true; return { hits: [], score: 0, partial: true }; }
  budget.left -= text.length;
  const hits = [];
  for (const [label, weight, re] of PATTERNS) { const m = text.match(re); if (m) hits.push({ label, weight, snippet: snip(m[0], 140) }); }
  const c = htmlComment(text);
  if (c) hits.push({ label: 'hidden HTML comment', weight: 2, snippet: c });
  if (padded) hits.push({ label: 'whitespace padding', weight: 2, snippet: 'a run of 90 or more blank characters before more text' });
  return { hits, score: hits.reduce((a, h) => a + h.weight, 0), partial };
}
const severityOf = score => (score >= 8 ? 'critical' : score >= 4 ? 'high' : score >= 3 ? 'medium' : score >= 2 ? 'low' : null);

// ── capability classification ────────────────────────────────────────────────────────────────────────────────────────────────
const CAPS = [
  ['exec', 'run commands or code', /\b(?:exec(?:ute)?|run (?:command|shell|script|code|bash|cmd|python|js|javascript)|shell|bash|powershell|terminal|subprocess|system command|eval(?:uate)?|code interpreter|spawn|run process)\b/i],
  ['file_write', 'write, move or delete files', /\b(?:write|edit|create|delete|remove|move|rename|overwrite|append|save|modify|chmod|mkdir|rm)\s+(?:a\s+)?(?:file|files|directory|dir|folder|path)\b|\b(?:file|files)\s+(?:write|delete|edit|move)\b|\bwrite file\b/i],
  ['sql', 'run database queries', /\b(?:sql|run query|execute query|query database|database query)\b/i],
  ['secrets', 'read secrets or credentials', /\b(?:get|read|list|fetch|retrieve)\s+(?:a\s+)?(?:secret|secrets|credential|credentials|token|password|api key)\b/i],
  ['network', 'request arbitrary URLs', /\b(?:fetch (?:a )?url|http request|curl|download|browse|scrape|web request|navigate to)\b/i],
  ['messaging', 'send messages or email', /\b(?:send|post)\s+(?:an?\s+)?(?:email|message|sms|tweet|slack|webhook|notification)\b/i],
  ['file_read', 'read files', /\b(?:read|list|search|get|open)\s+(?:a\s+)?(?:file|files|directory|dir|folder)\b|\bdirectory tree\b/i],
];
export function classify(tool) {
  const name = String(tool.name || '').replace(/[_.-]+/g, ' ').replace(/([a-z])([A-Z])/g, '$1 $2');
  const text = `${name}. ${String(tool.description || '').slice(0, 400)}`;
  const props = Object.keys(tool.inputSchema?.properties || {}).join(' ').toLowerCase();
  const caps = [];
  for (const [id, , re] of CAPS) if (re.test(text) || (id === 'exec' && /\b(?:command|cmd|script|shell)\b/.test(props) && /\b(?:run|exec|execute)\b/i.test(name))) caps.push(id);
  return caps;
}
const IDENTITY_PARAM = /^(?:on_?behalf_?of|impersonat\w*|as_?user|run_?as(?:_\w+)?|act_?as|sudo(?:_user)?|su_?to|switch_?user|override_?user|effective_?user|proxy_?user|delegate(?:_to)?|masquerade\w*|login_?as|spoof\w*)$/i;
const PATH_PARAM = /^(?:path|file|filename|filepath|file_path|dir|directory|folder)$/i;
const SINK_PARAM = /^(?:command|cmd|script|code|shell|sql|query|expression|eval|path|file|filename|filepath|file_path|dir|directory|url|uri|endpoint|host)$/i;
const DANGEROUS_PARAM = /^(?:command|cmd|script|code|shell|sql|expression|eval)$/i;
const SENSITIVE_URI = /(?:\/\.(?:ssh|aws|gnupg|kube|docker|config)\b|\/etc\/(?:passwd|shadow|sudoers)|\bid_(?:rsa|ed25519)\b|\.env(?:\.|$)|\/proc\/|credentials?\b|\.pem$|\.key$)/i;
const SENSITIVE_NAME = /(?:credential|secret|passw(?:or)?d|private[_ -]?key|api[_ -]?key|access[_ -]?token|auth[_ -]?token|\btokens?\b)/i;   // a resource of any scheme whose address or name says it is a secret

/**
 * @param {object} d  {server, tools, resources, resourceTemplates, prompts, instructions, exposure, unauthenticated, previous}
 * @param {object} ctx {findings, add(rule, fields)}
 * @returns {{tools:object[], summary:object}}
 */
export function analyzeDefinitions(d, ctx) {
  const { server } = d;
  const add = (rule, f) => ctx.findings.add(rule, { app: server.id, origin: 'app', ...f });
  const exposedUnauth = d.unauthenticated === true;
  const reachable = d.exposure === 'public' ? 'public' : d.exposure === 'private' ? 'private' : 'loopback';
  const toolsOut = [];
  const budget = { left: BUDGET_CHARS, exhausted: false };
  let partialStrings = 0;

  // 1. strings the model reads
  const targets = [];
  const walk = (kind, item, label) => {
    for (const s of collectStrings(item, label)) targets.push({ kind, label, ...s });
  };
  const lab = x => visible(String(x ?? '?')).replace(/\./g, '·').slice(0, 80) || '?';          // labels are shown to people: no invisible characters, no dots (the path separator)
  (d.tools || []).forEach(t => walk('tool', t, `tools.${lab(t?.name)}`));
  (d.resources || []).forEach(r => walk('resource', r, `resources.${lab(r?.name ?? r?.uri)}`));
  (d.resourceTemplates || []).forEach(r => walk('resource', r, `resourceTemplates.${lab(r?.name ?? r?.uriTemplate)}`));
  (d.prompts || []).forEach(p => walk('prompt', p, `prompts.${lab(p?.name)}`));
  if (typeof d.instructions === 'string') walk('instructions', d.instructions, 'instructions');
  // group per definition so one finding says which definition and which field
  const byDef = new Map();
  for (const t of targets) (byDef.get(t.label.split('.').slice(0, 2).join('.')) || byDef.set(t.label.split('.').slice(0, 2).join('.'), []).get(t.label.split('.').slice(0, 2).join('.'))).push(t);
  if (d.instructions) byDef.set('instructions', targets.filter(t => t.kind === 'instructions'));
  for (const [defLabel, strs] of byDef) {
    const hidden = [], hits = new Map();
    let longest = 0;
    for (const s of strs) {
      if (typeof s.text !== 'string' || !s.text) continue;
      const h = hiddenChars(s.text);
      if (h) hidden.push({ path: s.path, ...h });
      const decodedExtra = h?.decoded ? `\n${h.decoded}` : '';
      if (/\.(?:uri|uriTemplate|mimeType)$/.test(s.path)) continue;                        // a resource's address is data, not prose: mcp.resource.sensitive reads it
      const { hits: hs, partial } = scoreText(`${s.text}${decodedExtra}`, budget);
      if (partial) partialStrings++;
      for (const x of hs) { const k = x.label; if (!hits.has(k)) hits.set(k, { ...x, path: s.path }); }
      if (!s.isKey && /\.description$|^instructions$/.test(s.path) || s.path.endsWith('description')) longest = Math.max(longest, s.text.length);
    }
    if (hidden.length) {
      const kinds = [...new Set(hidden.flatMap(h => h.kinds))];
      const smuggled = hidden.map(h => h.decoded).filter(Boolean).join(' ').trim();
      add('mcp.tool.hidden_unicode', {
        artifact: defLabel, key: `hidden:${defLabel}`, severity: smuggled ? 'critical' : 'high',
        description: `${defLabel} contains ${hidden.reduce((a, h) => a + h.count, 0)} invisible character(s) (${kinds.join(', ')}) in ${hidden.length} field(s). They are not visible to the person approving the tool, but the model reads them.${smuggled ? ' The Unicode tag characters decode to hidden ASCII text, which is shown below.' : ''}`,
        evidence: [...hidden.slice(0, 4).map(h => `${h.path}: ${h.count} × ${h.kinds.join(', ')}`), ...(smuggled ? [`hidden text: ${snip(smuggled, 200)}`] : [])],
      });
    }
    const score = [...hits.values()].reduce((a, h) => a + h.weight, 0) + (hidden.some(h => h.decoded) ? 4 : 0);
    const sev = severityOf(score);
    if (sev && hits.size) {
      add('mcp.tool.poisoning', {
        artifact: defLabel, key: `poison:${defLabel}`, severity: sev, confidence: 'medium',
        title: defLabel === 'instructions' ? 'Server instructions contain text aimed at the model' : undefined,
        description: `${defLabel} contains wording that is addressed to the model rather than describing the ${defLabel === 'instructions' ? 'server' : 'tool'}: ${[...hits.values()].map(h => h.label).join(', ')}. This is how tool poisoning works: the model follows the text while the person approving the call sees only the tool's name.`,
        evidence: [...hits.values()].slice(0, 6).map(h => `${h.label} (${h.path}): ${h.snippet}`),
      });
    }
    if (longest > 2500) add('mcp.tool.long_description', { artifact: defLabel, key: `long:${defLabel}`, severity: longest > 8000 ? 'medium' : 'low', description: `The longest text in ${defLabel} is ${longest} characters. A user reads the first lines; the model reads all of them.${longest > 2 * SCAN_CHARS ? ` Only its first and last ${SCAN_CHARS} characters were checked for instructions to the model.` : ''}`, evidence: [`${longest} characters`] });
  }

  // 2. names
  const seen = new Map();
  for (const t of d.tools || []) {
    const name = String(t?.name ?? '');
    seen.set(name, (seen.get(name) || 0) + 1);
    if (/[^\x00-\x7F]/.test(name) || name.normalize('NFKC') !== name) add('mcp.tool.homoglyph_name', { artifact: `tools.${visible(name)}`, key: `homoglyph:${name}`, description: `A tool name contains non-ASCII or look-alike characters: "${[...name].map(c => /[^\x20-\x7E]/.test(c) ? `\\u${c.codePointAt(0).toString(16)}` : c).join('')}". Names like this are used to imitate another tool.`, evidence: [name.length > 80 ? `${name.slice(0, 80)}…` : name] });
    else if (!/^[A-Za-z0-9_.-]{1,128}$/.test(name)) add('mcp.tool.invalid_name', { artifact: `tools.${snip(name, 60)}`, key: `invalid:${name}`, description: `The tool name "${snip(name, 60)}" is outside the character set and length the specification allows.`, evidence: [snip(name, 80)] });
  }
  for (const [name, n] of seen) if (n > 1) add('mcp.tool.duplicate_name', { artifact: `tools.${snip(name, 60)}`, key: `dup:${name}`, description: `The server lists the tool "${snip(name, 60)}" ${n} times.`, evidence: [`${n} definitions`] });

  // 3. capabilities, annotations, free-form parameters
  const capTools = new Map();
  const annot = [], sinks = [], identity = [];
  for (const t of d.tools || []) {
    if (!t || typeof t !== 'object') continue;
    const caps = classify(t);
    const h = hashes(t);
    toolsOut.push({ name: String(t.name ?? ''), title: t.title ? snip(t.title, 120) : undefined, description: snip(t.description || '', 300), ...h, capabilities: caps, annotations: t.annotations && typeof t.annotations === 'object' ? t.annotations : undefined, params: Object.keys(t.inputSchema?.properties || {}).slice(0, 30) });
    for (const c of caps) (capTools.get(c) || capTools.set(c, []).get(c)).push(t.name);
    const a = t.annotations || {};
    if (a.readOnlyHint === true && caps.some(c => ['exec', 'file_write', 'sql', 'messaging', 'secrets'].includes(c))) annot.push(`${t.name}: readOnlyHint=true but the tool can ${caps.filter(c => ['exec', 'file_write', 'sql', 'messaging', 'secrets'].includes(c)).map(c => CAPS.find(x => x[0] === c)[1]).join(' and ')}`);
    if (a.destructiveHint === false && /\b(?:delete|remove|drop|truncate|wipe|destroy|purge|erase)\b/i.test(String(t.name || '').replace(/[_-]/g, ' '))) annot.push(`${t.name}: destructiveHint=false on a tool named like a deletion`);
    for (const [pn, ps] of Object.entries(t.inputSchema?.properties || {})) {
      if (IDENTITY_PARAM.test(pn)) identity.push({ tool: String(t.name), param: pn, documented: !!(ps && typeof ps === 'object' && ps.description) });
      if (SINK_PARAM.test(pn) && ps && (ps.type === 'string' || ps.type === undefined) && !ps.enum && !ps.pattern && !ps.maxLength && !ps.const) sinks.push({ tool: t.name, param: pn, danger: DANGEROUS_PARAM.test(pn) });
    }
  }
  if (annot.length) add('mcp.tool.annotation_mismatch', { artifact: 'tools', key: 'annotations', description: `${annot.length} tool(s) carry annotations that contradict what they do. Clients use these hints to decide whether to ask before calling.`, evidence: annot.slice(0, 8) });
  if (identity.length) add('mcp.tool.identity_override_param', {
    artifact: 'tools', key: 'identity', severity: identity.some(i => !i.documented) ? 'high' : 'medium',
    description: `${identity.length} parameter(s) let the caller name the user to act as (${identity.slice(0, 4).map(i => `${i.tool}.${i.param}`).join(', ')}). The server has to check that the caller may act for that user; if it trusts the session's identity instead, passing another one reads or changes that user's data.${identity.some(i => !i.documented) ? ' At least one of them has no description in the schema, so it is not shown to the person reviewing the tool.' : ''}`,
    evidence: identity.slice(0, 10).map(i => `${i.tool}(${i.param})${i.documented ? '' : ' — not described in the schema'}`),
  });
  const DANGER = ['exec', 'file_write', 'sql', 'secrets', 'network', 'messaging', 'file_read'];
  for (const c of DANGER) {
    let names = capTools.get(c);
    if (c === 'file_read' && names) names = names.filter(n => sinks.some(s => s.tool === n && PATH_PARAM.test(s.param)));      // reading files is reported when the path is free-form
    if (!names?.length) continue;
    if (c !== 'exec' && !exposedUnauth) continue;                      // only command execution is reported on its own; the rest matter when anyone can call them
    const sev = exposedUnauth ? (reachable === 'public' ? 'critical' : reachable === 'private' ? 'high' : 'medium') : 'medium';
    add('mcp.tool.dangerous_capability', {
      artifact: `tools (${c})`, key: `cap:${c}`, severity: c === 'exec' || exposedUnauth ? sev : 'low',
      title: `Server exposes tools that ${CAPS.find(x => x[0] === c)[1]}`,
      description: `${names.length} tool(s) ${CAPS.find(x => x[0] === c)[1]}: ${names.slice(0, 6).join(', ')}${names.length > 6 ? ', …' : ''}.${c === 'file_read' ? ' The path is a free-form string in the schema, so nothing visible restricts them to a directory: they can read any file the server process can read (keys, tokens, configuration).' : ''}${exposedUnauth ? ` The endpoint does not authenticate and is ${d.exposure === 'public' ? 'on a public address' : d.exposure === 'private' ? 'on the local network' : 'on this machine'}, so whoever can reach it can use them.` : ' Anything that can steer the model (a web page it read, a poisoned tool description) can reach them, so the client should ask before each call.'}`,
      evidence: names.slice(0, 12).map(String),
    });
  }
  if (sinks.length && !d.static) add('mcp.tool.unconstrained_sink', {
    artifact: 'tools', key: 'sinks', severity: sinks.some(s => s.danger) ? 'medium' : 'low',
    description: `${sinks.length} parameter(s) are free-form strings named like a command, path, URL or query. Whether they are validated cannot be seen from the schema; they are where injection happens.`,
    evidence: sinks.slice(0, 10).map(s => `${s.tool}(${s.param}: string)`),
  });

  // 4. resources
  const sens = (d.resources || []).filter(r => r && typeof r.uri === 'string' && (/^file:/i.test(r.uri) ? SENSITIVE_URI.test(r.uri) : SENSITIVE_NAME.test(`${r.uri} ${r.name ?? ''}`)));
  if (sens.length) add('mcp.resource.sensitive', { artifact: 'resources', key: 'sensitive', severity: exposedUnauth ? 'high' : 'medium', description: `${sens.length} resource(s) point at credential or system files, or are named like a secret. A client can read a resource without being asked, and its content goes into the model's context.`, evidence: sens.slice(0, 8).map(r => snip(r.uri, 120)) });

  // 5. changes since the previous scan (rug pull)
  const prev = d.previous;
  if (prev?.tools) {
    const before = new Map(prev.tools.map(t => [t.name, t]));
    const changed = [], added = [];
    for (const t of toolsOut) {
      const b = before.get(t.name);
      if (!b) added.push(t.name);
      else if (b.hash !== t.hash) changed.push(`${t.name}: ${b.description_hash !== t.description_hash ? 'description' : ''}${b.description_hash !== t.description_hash && b.schema_hash !== t.schema_hash ? ' + ' : ''}${b.schema_hash !== t.schema_hash ? 'input schema' : ''}${b.description_hash === t.description_hash && b.schema_hash === t.schema_hash ? 'annotations or title' : ''} changed`);
    }
    if (changed.length) add('mcp.tool.changed', { artifact: 'tools', key: `changed:${changed.map(c => c.split(':')[0]).sort().join(',')}`, description: `${changed.length} tool definition(s) of this server differ from the previous scan. A server that changes a description after the user approved the tool can redirect the model without a new prompt.`, evidence: changed.slice(0, 10) });
    if (added.length) add('mcp.tool.added', { artifact: 'tools', key: `added:${added.sort().join(',')}`, description: `${added.length} tool(s) were not in the previous scan.`, evidence: added.slice(0, 10) });
  }
  return { tools: toolsOut, summary: { truncated: budget.exhausted || partialStrings > 0 ? { budgetExhausted: budget.exhausted, partialStrings } : undefined, tools: (d.tools || []).length, resources: (d.resources || []).length, prompts: (d.prompts || []).length, capabilities: Object.fromEntries([...capTools].map(([k, v]) => [k, v.length])) } };
}

/** Tool names offered by more than one server in this scan. */
export function shadowing(serverTools, findings) {
  const by = new Map();
  for (const { server, names } of serverTools) for (const n of new Set(names)) (by.get(n) || by.set(n, []).get(n)).push(server);
  for (const [name, servers] of by) {
    if (servers.length < 2) continue;
    findings.add('mcp.tool.shadowing', { app: servers[0].id, origin: 'app', artifact: `tools.${snip(name, 60)}`, key: `shadow:${name}`, description: `The tool "${snip(name, 60)}" is offered by ${servers.length} servers (${servers.map(s => s.name).join(', ')}). Which one the model calls depends on the client; a malicious server can use a trusted tool's name to intercept its calls.`, evidence: servers.map(s => `${s.client}:${s.name}`) });
  }
}
