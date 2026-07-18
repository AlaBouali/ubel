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

function buildFullCallChain(sourceChunk, chunkMap, maxDepth = 10, maxChainLength = 15) {
  const visited = new Set([sourceChunk.id]);
  const chain = [];

  // 1. Collect callers (reverse) using BFS
  const callerQueue = [sourceChunk];
  const callerSet = new Set();

  for (let depth = 0; depth < maxDepth && callerQueue.length > 0; depth++) {
    const current = callerQueue.shift();
    const callers = findCallers(current.name, chunkMap);
    for (const caller of callers) {
      if (!visited.has(caller.id)) {
        visited.add(caller.id);
        callerSet.add(caller);
        callerQueue.push(caller);
      }
    }
  }

  // 2. Collect callees (forward) using existing function
  const calleeSet = new Set();
  const forwardChain = buildCallChain(sourceChunk, chunkMap);
  for (const chunk of forwardChain) {
    if (chunk.id !== sourceChunk.id && !visited.has(chunk.id)) {
      visited.add(chunk.id);
      calleeSet.add(chunk);
    }
  }

  // 3. Order: outermost callers first (reverse of BFS order), then source, then callees
  const callerArray = Array.from(callerSet);
  callerArray.reverse(); // outermost first

  // Cap the chain length to avoid token overflow
  const total = callerArray.length + 1 + calleeSet.size;
  let maxCallers = Math.max(0, Math.floor((maxChainLength - 1) / 2));
  let maxCallees = Math.max(0, maxChainLength - 1 - maxCallers);
  if (total > maxChainLength) {
    const excess = total - maxChainLength;
    if (callerArray.length > maxCallers) {
      callerArray.splice(maxCallers);
    }
    if (calleeSet.size > maxCallees) {
      // Remove excess callees (keep closest)
      const calleeArray = Array.from(calleeSet);
      calleeArray.splice(maxCallees);
      calleeSet.clear();
      calleeArray.forEach(c => calleeSet.add(c));
    }
  }

  chain.push(...callerArray);
  chain.push(sourceChunk);
  chain.push(...Array.from(calleeSet));

  return chain;
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
};