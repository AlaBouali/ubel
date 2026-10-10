'use strict';

import { regexCanFollow, consumeRegexLiteral } from '../chunker/regexliteral.js';

// ─── Function extraction helpers ──────────────────────────────────────────

// Masks out the contents of string literals, template literals, comments,
// and regex literals with spaces (preserving line breaks and overall
// length/offsets) so that regex-based call detection below never matches
// an identifier that only appears inside quoted text, a comment, or a
// regex pattern — e.g. a log message like "calling runQuery(input)" must
// not be treated as a real call to runQuery. Regex-literal handling exists
// because, without it, a pattern like /^https?:\/\// reads as "//"
// partway through (the escaped slash sits right next to the real closing
// slash) and everything after it on that line gets swallowed as a fake
// comment — silently dropping real code from call-graph resolution, which
// can misclassify a function as an orphan with no callers (see
// regexLiteral.js for the full rationale).
function maskNonCode(code) {
  let out = '';
  let i = 0;
  let inStr = false, strChar = '';
  let inTemplate = false;
  let inLineComment = false, inBlockComment = false;
  // Tracks the last significant token scanned, so a bare '/' can be told
  // apart from the start of a regex literal.
  let lastToken = null;
  let wordBuf   = '';
  const flushWord = () => { if (wordBuf) { lastToken = wordBuf; wordBuf = ''; } };

  while (i < code.length) {
    const ch = code[i];
    const ch2 = code.slice(i, i + 2);

    if (inLineComment) {
      if (ch === '\n') { inLineComment = false; out += ch; } else { out += ' '; }
      i++; continue;
    }
    if (inBlockComment) {
      if (ch2 === '*/') { out += '  '; i += 2; inBlockComment = false; continue; }
      out += (ch === '\n') ? '\n' : ' '; i++; continue;
    }
    if (inStr || inTemplate) {
      if (ch === '\\') { out += '  '; i += 2; continue; }
      if (inStr && ch === strChar) { inStr = false; lastToken = 'VALUE'; out += ch; i++; continue; }
      if (inTemplate && ch === '`') { inTemplate = false; lastToken = 'VALUE'; out += ch; i++; continue; }
      // Preserve template interpolation delimiters/newlines structurally,
      // mask everything else (the literal text content).
      out += (ch === '\n') ? '\n' : ' ';
      i++; continue;
    }
    if (ch2 === '//') { inLineComment = true; out += '  '; i += 2; continue; }
    if (ch2 === '/*') { inBlockComment = true; out += '  '; i += 2; continue; }
    if (ch === '/' && regexCanFollow(lastToken)) {
      const end = consumeRegexLiteral(code, i);
      if (end !== null) {
        // Mask the whole regex literal like a string — its contents may
        // contain arbitrary punctuation (including brace/paren-shaped
        // quantifiers like {2,4}) that must never feed the call-detection
        // regex in findCalledFunctions/findCallers.
        for (let k = i; k < end; k++) out += (code[k] === '\n') ? '\n' : ' ';
        lastToken = 'VALUE';
        i = end;
        continue;
      }
      // No valid closing '/' on this line — not actually a regex literal
      // (almost certainly division). Fall through, treat '/' normally.
    }
    if (ch === '"' || ch === "'") { inStr = true; strChar = ch; out += ch; i++; continue; }
    if (ch === '`') { inTemplate = true; out += ch; i++; continue; }
    out += ch;
    if (/[A-Za-z0-9_$]/.test(ch)) {
      wordBuf += ch;
    } else {
      flushWord();
      if (!/\s/.test(ch)) lastToken = ch;
    }
    i++;
  }
  return out;
}

function extractFunctionName(codeSnippet) {
  const patterns = [
    /function\s+([a-zA-Z_]\w*)\s*\(/,
    /const\s+([a-zA-Z_]\w*)\s*=\s*(?:async\s+)?\(/,
    /const\s+([a-zA-Z_]\w*)\s*=\s*function/,
    /export\s+default\s+function\s+([a-zA-Z_]\w*)/,
    /async\s+function\s+([a-zA-Z_]\w*)/,
    /([a-zA-Z_]\w*)\s*=\s*(?:async\s+)?\(/,
    /^([a-zA-Z_]\w*)\s*:/,
  ];

  for (const pattern of patterns) {
    const match = codeSnippet.match(pattern);
    if (match) return match[1];
  }
  return null;
}

function findCalledFunctions(code, sourceChunk, chunkMap) {
  const maskedCode = maskNonCode(code);
  const callRegex = /\b([a-zA-Z_]\w*)\s*\(/g;
  const matches = [];
  let match;
  const keywords = new Set(['if', 'for', 'while', 'switch', 'catch', 'try', 'return', 'throw', 'await', 'new', 'delete', 'typeof', 'instanceof', 'void', 'yield']);

  while ((match = callRegex.exec(maskedCode)) !== null) {
    const funcName = match[1];
    if (keywords.has(funcName)) continue;
    if (['console', 'process', 'require', 'import', 'exports', 'module', '__dirname', '__filename', 'setTimeout', 'setInterval', 'clearTimeout', 'clearInterval', 'Promise', 'Buffer', 'JSON', 'Math', 'Date', 'Array', 'Object', 'String', 'Number', 'Boolean', 'RegExp', 'Error', 'Map', 'Set', 'WeakMap', 'WeakSet'].includes(funcName)) continue;

    // Search across all files — same-file matches take priority,
    // but cross-file definitions are included so taint can follow imports.
    const candidates = Object.values(chunkMap).filter(c =>
      c.name === funcName && c.id !== sourceChunk.id
    );
    // Prefer same-file definition; fall back to first cross-file match
    const calledChunk = candidates.find(c => c.file === sourceChunk.file)
                     || candidates[0]
                     || null;

    matches.push({ name: funcName, chunk: calledChunk });
  }

  return matches;
}

function buildCallChain(sourceChunk, chunkMap) {
  const chain = [sourceChunk];
  const visited = new Set([sourceChunk.id]);

  const calledFunctions = findCalledFunctions(sourceChunk.code, sourceChunk, chunkMap);

  for (const call of calledFunctions) {
    if (call.chunk && !visited.has(call.chunk.id)) {
      visited.add(call.chunk.id);
      chain.push(call.chunk);

      const nestedCalls = findCalledFunctions(call.chunk.code, call.chunk, chunkMap);
      for (const nested of nestedCalls) {
        if (nested.chunk && !visited.has(nested.chunk.id)) {
          visited.add(nested.chunk.id);
          chain.push(nested.chunk);
        }
      }
    }
  }

  return chain;
}

// ─── Reverse call chain helpers ──────────────────────────────────────────

// Short single-word names that are almost certainly not unique function identifiers.
// Matching them across the whole codebase produces too many false callers.
const COMMON_NAMES = new Set([
  'get','set','run','next','done','init','new','create','update','delete',
  'load','save','read','write','open','close','start','stop','send','recv',
  'call','exec','main','test','check','parse','format','handle','process',
  'render','build','push','pop','map','filter','reduce','find','sort',
  'log','info','warn','error','debug','emit','on','off','once',
]);

// Maximum number of callers we accept for a single function name.
// If a name matches more chunks than this it's too generic to be useful.
const MAX_CALLERS = 20;

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Memoizes maskNonCode() output per chunk so repeated findCallers() calls
// across BFS depth levels (and across multiple findings) don't re-scan the
// same chunk's code from scratch every time.
const _maskedCodeCache = new WeakMap();
function getMaskedCode(chunk) {
  let masked = _maskedCodeCache.get(chunk);
  if (masked === undefined) {
    masked = maskNonCode(chunk.code);
    _maskedCodeCache.set(chunk, masked);
  }
  return masked;
}

function findCallers(funcName, chunkMap) {
  // Bail out early for generic names that would flood the chain
  if (COMMON_NAMES.has(funcName) || funcName.length <= 2) return [];

  const callers    = [];
  const callRegex  = new RegExp(`\\b${escapeRegex(funcName)}\\s*\\(`, 'g');

  for (const chunk of Object.values(chunkMap)) {
    if (chunk.name === funcName) continue;
    callRegex.lastIndex = 0;
    // Match against masked code so a call-shaped substring sitting inside a
    // string literal or comment (e.g. a log line mentioning the function by
    // name) is never treated as a real caller in the taint-trace evidence.
    if (callRegex.test(getMaskedCode(chunk))) {
      callers.push(chunk);
      if (callers.length >= MAX_CALLERS) break; // name is too generic — cap it
    }
  }
  return callers;
}

// ─── Full (caller + callee) chain for the taint-trace prompt ─────────────────
//
// Returns an Array of chunk references ordered outermost caller → … → nearest
// caller → SINK → nearest callee → …, with these extra properties so the
// prompt can label every entry correctly:
//   chain.roles[i]        'caller' | 'sink' | 'callee'
//   chain.callTargets[i]  names (in the chain) that entry i calls — used to
//                         excerpt a caller down to its call-site windows
//   chain.sinkIndex       index of the chunk that holds the flagged finding
//
// maxDepth is a real BFS depth now: callers-of-callers are followed for up to
// `maxDepth` LEVELS (it used to be 10 node expansions, which is far less on
// a wide graph). maxChainLength caps the total number of chunks; when the
// graph is bigger, the NEAREST callers and callees are kept (alternating
// caller / callee, so slots one side doesn't need go to the other) — the old
// splice() dropped the nearest callers and kept the farthest.
function buildFullCallChain(sourceChunk, chunkMap, maxDepth = 10, maxChainLength = 15) {
  const visited = new Set([sourceChunk.id]);

  // 1. Callers (reverse), level-by-level BFS. Each entry remembers the name
  //    of the function it calls toward the sink so it can be excerpted later.
  const callers = [];                       // { chunk, depth, calls:Set<string> }
  let frontier = [sourceChunk];
  for (let depth = 1; depth <= maxDepth && frontier.length > 0; depth++) {
    const next = [];
    for (const current of frontier) {
      for (const caller of findCallers(current.name, chunkMap)) {
        if (visited.has(caller.id)) {
          const seen = callers.find(c => c.chunk.id === caller.id);
          if (seen) seen.calls.add(current.name);
          continue;
        }
        visited.add(caller.id);
        const entry = { chunk: caller, depth, calls: new Set([current.name]) };
        callers.push(entry);
        next.push(caller);
      }
    }
    frontier = next;
  }

  // 2. Callees (forward): direct callees first, then the callees they call.
  const callees = [];                       // { chunk, depth }
  const direct = findCalledFunctions(sourceChunk.code, sourceChunk, chunkMap);
  for (const call of direct) {
    if (call.chunk && !visited.has(call.chunk.id)) {
      visited.add(call.chunk.id);
      callees.push({ chunk: call.chunk, depth: 1 });
    }
  }
  for (const d1 of [...callees]) {
    for (const nested of findCalledFunctions(d1.chunk.code, d1.chunk, chunkMap)) {
      if (nested.chunk && !visited.has(nested.chunk.id)) {
        visited.add(nested.chunk.id);
        callees.push({ chunk: nested.chunk, depth: 2 });
      }
    }
  }

  // 3. Cap: nearest first, alternating caller / callee.
  const budget = Math.max(0, maxChainLength - 1);
  const callersByDist = [...callers].sort((a, b) => a.depth - b.depth);
  const calleesByDist = [...callees].sort((a, b) => a.depth - b.depth);
  const keptCallers = [], keptCallees = [];
  let ci = 0, ei = 0;
  while (keptCallers.length + keptCallees.length < budget && (ci < callersByDist.length || ei < calleesByDist.length)) {
    if (ci < callersByDist.length) keptCallers.push(callersByDist[ci++]);
    if (keptCallers.length + keptCallees.length >= budget) break;
    if (ei < calleesByDist.length) keptCallees.push(calleesByDist[ei++]);
  }

  // 4. Order: outermost callers first, nearest caller last, then the sink,
  //    then callees nearest-first.
  const orderedCallers = keptCallers.sort((a, b) => b.depth - a.depth);
  const chain = [];
  const roles = [];
  const callTargets = [];
  for (const c of orderedCallers) { chain.push(c.chunk); roles.push('caller'); callTargets.push([...c.calls]); }
  const sinkIndex = chain.length;
  chain.push(sourceChunk); roles.push('sink'); callTargets.push(null);
  for (const c of keptCallees) { chain.push(c.chunk); roles.push('callee'); callTargets.push(null); }

  chain.roles = roles;
  chain.callTargets = callTargets;
  chain.sinkIndex = sinkIndex;
  chain.truncated = (callers.length + callees.length) > (keptCallers.length + keptCallees.length);
  return chain;
}

// ─── Excerpting: keep the taint prompt small ─────────────────────────────────
//
// A caller only matters at the lines where it calls the next function toward
// the sink, and a callee only matters for what it does with its inputs — so
// instead of sending every chain member whole, send the call-site windows
// (callers) or the head (callees) within a character budget. The sink chunk is
// always sent whole.
function excerptAroundCalls(code, names, maxChars, context = 6) {
  if (code.length <= maxChars) return code;
  const lines  = code.split('\n');
  const masked = maskNonCode(code).split('\n');
  const re = names && names.length
    ? new RegExp(`\\b(?:${names.map(escapeRegex).join('|')})\\s*\\(`)
    : null;

  const hit = [];
  if (re) masked.forEach((l, i) => { if (re.test(l)) hit.push(i); });
  if (hit.length === 0) return excerptHead(code, maxChars);

  const ranges = [];
  for (const i of hit) {
    const lo = Math.max(0, i - context), hi = Math.min(lines.length - 1, i + context);
    const last = ranges[ranges.length - 1];
    if (last && lo <= last[1] + 1) last[1] = Math.max(last[1], hi); else ranges.push([lo, hi]);
  }

  const out = [];
  let used = 0, prevEnd = -1;
  for (const [lo, hi] of ranges) {
    const seg = lines.slice(lo, hi + 1).join('\n');
    if (used + seg.length > maxChars && out.length > 0) break;
    const room = maxChars - used;
    const text = seg.length > room ? seg.slice(0, room) : seg;
    if (lo > prevEnd + 1) out.push(`// … ${lo - prevEnd - 1} line(s) omitted …`);
    out.push(text);
    used += text.length; prevEnd = hi;
    if (used >= maxChars) break;
  }
  if (prevEnd < lines.length - 1) out.push(`// … ${lines.length - 1 - prevEnd} line(s) omitted …`);
  return out.join('\n');
}

function excerptHead(code, maxChars) {
  if (code.length <= maxChars) return code;
  const cut = code.slice(0, maxChars);
  const lastNl = cut.lastIndexOf('\n');
  const body = lastNl > maxChars * 0.5 ? cut.slice(0, lastNl) : cut;
  const omitted = code.slice(body.length).split('\n').length - 1;
  return `${body}\n// … ${Math.max(omitted, 1)} more line(s) omitted …`;
}

// Applies the excerpt policy to a chain. `strip(chunk)` returns the chunk with
// comments removed (done BEFORE excerpting so comment text never eats budget).
// Returns plain objects [{...chunk, code, _role, _excerpted}] ready for the prompt.
function prepareChainForPrompt(chain, strip, { maxChainChars = 24000, perChunkChars = 3500 } = {}) {
  const sinkIdx = chain.sinkIndex ?? 0;
  const sink = strip(chain[sinkIdx]);
  const others = chain.length - 1;
  const remaining = Math.max(0, maxChainChars - sink.code.length);
  const perOther = others > 0 ? Math.max(600, Math.min(perChunkChars, Math.floor(remaining / others))) : 0;

  return chain.map((c, i) => {
    const role = chain.roles ? chain.roles[i] : (i === sinkIdx ? 'sink' : 'caller');
    if (i === sinkIdx) return { ...sink, _role: 'sink', _excerpted: false };
    const stripped = strip(c);
    const code = role === 'caller'
      ? excerptAroundCalls(stripped.code, chain.callTargets ? chain.callTargets[i] : null, perOther)
      : excerptHead(stripped.code, perOther);
    return { ...stripped, code, _role: role, _excerpted: code !== stripped.code };
  });
}

export  {
  maskNonCode,
  extractFunctionName,
  findCalledFunctions,
  buildCallChain,
  COMMON_NAMES,
  MAX_CALLERS,
  escapeRegex,
  getMaskedCode,
  findCallers,
  buildFullCallChain,
  excerptAroundCalls,
  excerptHead,
  prepareChainForPrompt,
};