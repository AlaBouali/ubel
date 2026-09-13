'use strict';

import { collectBraceBlock, buildImportChunk, makeChunk } from '../braceblock.js';
import { computeBraceDelta } from '../bracedelta.js';

// ─── Rust chunker ─────────────────────────────────────────────────────────────

function chunkRust(filePath, lines) {
  const chunks = [];
  const importChunk = buildImportChunk(filePath, lines, /^use\s+/);
  if (importChunk) chunks.push(importChunk);

  const implRe   = /^(?:pub\s+)?impl(?:<[^>]+>)?\s+(?:[^{]+\s+for\s+)?([A-Za-z_]\w*)/;
  const fnRe     = /^(?:(?:pub(?:\([^)]+\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_]\w*))/;
  const structRe = /^(?:pub\s+)?struct\s+([A-Za-z_]\w*)/;

  // Masks out line comments, block comments (via commentState, same
  // convention as computeBraceDelta), and "..."/'...' literal contents from
  // a line, replacing masked characters with spaces so a '{' or ';' that
  // only appears inside a string or comment can never be mistaken for the
  // real terminator below. Does NOT handle raw strings (r"...", r#"..."#) —
  // a documented, narrow, best-effort gap consistent with the rest of this
  // chunker; a brace or semicolon inside a raw string could desync this scan.
  function maskRustLine(line, commentState) {
    let out = '';
    let j = 0;
    if (commentState.inBlockComment) {
      const end = line.indexOf('*/');
      if (end === -1) return ' '.repeat(line.length);
      out += ' '.repeat(end + 2);
      j = end + 2;
      commentState.inBlockComment = false;
    }
    while (j < line.length) {
      const ch = line[j];
      const ch2 = line.slice(j, j + 2);
      if (ch2 === '//') { out += ' '.repeat(line.length - j); break; }
      if (ch2 === '/*') {
        const end = line.indexOf('*/', j + 2);
        if (end === -1) { commentState.inBlockComment = true; out += ' '.repeat(line.length - j); break; }
        out += ' '.repeat(end + 2 - j);
        j = end + 2; continue;
      }
      if (ch === '"' || ch === "'") {
        const quote = ch; const start = j; j++;
        while (j < line.length) {
          if (line[j] === '\\') { j += 2; continue; }
          if (line[j] === quote) { j++; break; }
          j++;
        }
        out += ' '.repeat(j - start);
        continue;
      }
      out += ch; j++;
    }
    return out;
  }

  // Rust `fn` signatures without a body are completely ordinary — trait
  // method declarations (`fn area(&self) -> f64;`) and `extern` block
  // declarations both end in ';' instead of '{'. fnRe alone can't tell
  // those apart from a real definition. Treating a bodyless signature as
  // the start of a real function used to make collectBraceBlock scan
  // forward with `started` never set (no '{' on that line), so the
  // trait/extern block's own closing '}' silently decremented depth past
  // zero without tripping any exit condition — the collector kept
  // consuming everything (further signatures, the block's '}', unrelated
  // code) until the next '{' anywhere in the file finally set `started`,
  // producing one corrupted chunk and silently losing whatever function
  // was actually at that next '{'. Same lookahead strategy as c.js's
  // prototype-vs-definition guard, adapted for Rust's simpler (no K&R
  // pointer/reference ambiguity) but still braces-vs-generics-vs-tuple-
  // return-type signature shape.
  function lookaheadFnTerminator(lines, startLine, commentState) {
    let sawOpenBrace = false, sawSemicolon = false;
    let scanLine = startLine;
    let parenDepth = 0;
    let seenOpenParen = false;
    const lookaheadState = { inBlockComment: commentState.inBlockComment };
    outer:
    for (; scanLine < Math.min(startLine + 20, lines.length); scanLine++) {
      const sl = maskRustLine(lines[scanLine], lookaheadState);
      for (let k = 0; k < sl.length; k++) {
        const c = sl[k];
        if (c === '(') { parenDepth++; seenOpenParen = true; }
        else if (c === ')') { parenDepth--; }
        else if (seenOpenParen && parenDepth === 0) {
          if (c === '{') { sawOpenBrace = true; break outer; }
          if (c === ';') { sawSemicolon = true; break outer; }
          if (c === '}') { break outer; } // enclosing block ended — not a real signature
        }
      }
    }
    return { sawOpenBrace, sawSemicolon, scanLine };
  }

  let i = 0;
  let currentImpl = null;
  // Brace depth recorded when entering the current impl body, so we know
  // when a closing '}' actually ends the impl rather than some nested block
  // inside one of its methods (a closure body, a match arm block). Without
  // this, that nested block's own closing '}' was mistaken for the impl
  // ending — which silently misattributed every method declared afterward
  // as a free function instead of belonging to the impl.
  let implBraceDepth = 0;
  let braceDepth = 0;
  // Pending #[attr] / #![attr] lines immediately preceding an fn declaration.
  // Only the attribute call lines are prepended — not any derive macro expansions.
  const pendingAttrs = [];
  // Tracks whether we're inside an unclosed /* ... */ comment, so
  // continuation lines are correctly skipped instead of falling through
  // to the impl/struct/fn regexes below.
  const commentState = { inBlockComment: false };
  // Every top-level (and in-impl-but-not-a-fn) survivor — static/const
  // items, trait method signatures without a body, extern block contents —
  // is collected here instead of being silently dropped.
  const moduleLevel = [];
  let moduleLevelStart = -1;

  while (i < lines.length) {
    const line    = lines[i];
    const stripped = line.trim();

    if (commentState.inBlockComment) {
      braceDepth += computeBraceDelta(line, commentState);
      i++; continue;
    }

    if (stripped.startsWith('//') || stripped.startsWith('*')) { i++; continue; }
    if (stripped.startsWith('/*')) {
      braceDepth += computeBraceDelta(line, commentState);
      i++; continue;
    }

    // Collect outer attribute lines: #[...] or #![...]
    if (/^#!?\[/.test(stripped)) {
      pendingAttrs.push(line);
      braceDepth += computeBraceDelta(line, commentState);
      i++; continue;
    }

    const implMatch = stripped.match(implRe);
    if (implMatch) {
      currentImpl = implMatch[1];
      pendingAttrs.length = 0;
      implBraceDepth = braceDepth; // depth BEFORE this impl's own '{' is consumed
      braceDepth += computeBraceDelta(line, commentState);
      i++; continue;
    }
    if (currentImpl && stripped.startsWith('}') && braceDepth === implBraceDepth + 1) {
      braceDepth += computeBraceDelta(line, commentState);
      currentImpl = null;
      i++; continue;
    }

    const structMatch = stripped.match(structRe);
    if (structMatch) {
      const name = structMatch[1]; const blockStart = i - pendingAttrs.length;
      const block = collectBraceBlock(lines, i);
      // Struct attrs (e.g. #[derive(...)]) are useful context too.
      chunks.push(makeChunk(filePath, 'struct', name, name, [...pendingAttrs, ...block.lines], blockStart));
      pendingAttrs.length = 0;
      for (const bl of block.lines) braceDepth += computeBraceDelta(bl, commentState);
      i = block.nextIndex; continue;
    }

    const fnMatch = stripped.match(fnRe);
    if (fnMatch) {
      const { sawOpenBrace, sawSemicolon, scanLine } = lookaheadFnTerminator(lines, i, commentState);

      if (sawOpenBrace) {
        const name = fnMatch[1];
        const blockStart = i - pendingAttrs.length;
        const block = collectBraceBlock(lines, i);
        // Prepend attribute calls so the LLM sees #[test], #[route(...)], etc.
        chunks.push(makeChunk(filePath, currentImpl ? 'method' : 'function', currentImpl, name,
          [...pendingAttrs, ...block.lines], blockStart));
        pendingAttrs.length = 0;
        for (const bl of block.lines) braceDepth += computeBraceDelta(bl, commentState);
        i = block.nextIndex; continue;
      }
      if (sawSemicolon) {
        // Bodyless signature — a trait method declaration or an `extern`
        // block item. Not a definition. Captured into module_code (still
        // security-relevant: it documents the trait's contract / the FFI
        // surface) rather than mistaken for a real function body.
        if (moduleLevelStart === -1) moduleLevelStart = i - pendingAttrs.length;
        for (const bl of pendingAttrs) moduleLevel.push(bl);
        pendingAttrs.length = 0;
        for (const bl of lines.slice(i, scanLine + 1)) moduleLevel.push(bl);
        for (const bl of lines.slice(i, scanLine + 1)) braceDepth += computeBraceDelta(bl, commentState);
        i = scanLine + 1; continue;
      }
      // Neither found within the lookahead window (e.g. a false-positive
      // match, or the enclosing block ended first) — fall through and
      // treat as module code below, same as c.js.
    }

    if (pendingAttrs.length > 0) {
      if (moduleLevelStart === -1) moduleLevelStart = i - pendingAttrs.length;
      moduleLevel.push(...pendingAttrs);
      pendingAttrs.length = 0;
    }

    if (stripped.length > 0 && stripped !== '{' && stripped !== '}') {
      if (moduleLevelStart === -1) moduleLevelStart = i;
      moduleLevel.push(line);
    }
    braceDepth += computeBraceDelta(line, commentState);
    i++;
  }

  // An attribute on the very last line(s) of the file with nothing after it
  // would otherwise never reach the flush inside the loop above.
  if (pendingAttrs.length > 0) {
    if (moduleLevelStart === -1) moduleLevelStart = lines.length - pendingAttrs.length;
    moduleLevel.push(...pendingAttrs);
  }

  if (moduleLevel.length > 0) {
    chunks.push({
      id: `${filePath}:module_code`, type: 'module_code', file: filePath,
      class: null, name: 'module_code',
      startLine: moduleLevelStart + 1,
      endLine:   moduleLevelStart + moduleLevel.length,
      code: moduleLevel.join('\n'),
    });
  }
  return chunks;
}

export { chunkRust };