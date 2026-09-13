'use strict';

import { collectBraceBlock, buildImportChunk, makeChunk } from '../braceblock.js';
import { computeBraceDelta } from '../bracedelta.js';

// ─── C / C++ chunker ────────────────────────────────────────────────────────
//
// C/C++ has no function/fn/def keyword to anchor on — a definition is just
// "return type, then name, then ( ... )" — so the two things that matter
// most here are:
//   1. Never confuse a PROTOTYPE (`int foo(int x);`) with a DEFINITION
//      (`int foo(int x) {`). Header files are mostly prototypes; treating
//      every prototype as the start of a function body would make
//      collectBraceBlock scan forward and swallow unrelated code until it
//      happens to find some future brace pair — exactly the bug found (and
//      avoided here) in the Java/C# chunkers, which don't guard against it.
//   2. Signatures are very often split across multiple lines before the
//      opening brace ever appears, so the prototype-vs-definition check
//      has to look ahead across lines, not just at the current line.
//
// Scope-wise, this follows the same rule used for every other language in
// this file: only named function/method declarations and class/struct
// methods become their own chunk. Function-pointer variables, lambdas
// (`auto f = [](int x){ ... };`) and macro bodies are intentionally left
// out of scope and fall through into module_code — along with every other
// top-level survivor (globals, typedefs, enums, #define'd values) so
// nothing outside a function/method body is silently dropped.

function chunkC(filePath, lines) {
  const chunks = [];
  const importChunk = buildImportChunk(filePath, lines, /^#\s*include\b/);
  if (importChunk) chunks.push(importChunk);

  // Strips line comments, block comments (single- and multi-line, using the
  // same commentState convention as computeBraceDelta), and string/char literal
  // contents from a line, replacing stripped characters with spaces so
  // column positions are preserved. Used by the signature lookahead scan
  // below so a ';', '{', or '}' that only appears inside a comment or string
  // can never be mistaken for real code structure.
  function maskCLine(line, commentState) {
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

  const classRe = /^(?:template\s*<[^>]*>\s*)?(?:class|struct)\s+([A-Za-z_]\w*)/;

  // A line that looks like it could start a function/method signature.
  // Handles: normal `ReturnType name(`, multi-token/pointer/reference return
  // types, constructors (`ClassName(` — no return type at all), destructors
  // (`~ClassName(`), and out-of-class definitions (`ClassName::method(`).
  // The previous lazy-quantifier approach for the return-type portion could
  // eat into the start of the function name itself when there was no return
  // type to consume (e.g. a constructor) — this version anchors the name to
  // require either nothing before it (constructor) or whitespace/a pointer-
  // or-reference sigil immediately before it, so the name capture can never
  // be partially absorbed by the return-type portion.
  const signatureStartRe =
    /^(?:template\s*<[^>]*>\s*)?(?:(?:static|inline|virtual|explicit|extern|friend|constexpr)\s+)*(?:[\w:<>,*&]+(?:\s+|(?<=[*&]))\s*)*(~?[A-Za-z_]\w*(?:::~?[A-Za-z_]\w*)?)\s*\(/;

  const controlKw = new Set([
    'if', 'for', 'while', 'switch', 'catch', 'else', 'return', 'sizeof',
    'static_cast', 'dynamic_cast', 'const_cast', 'reinterpret_cast', 'new', 'delete',
  ]);
  const preprocessorRe = /^#/;

  let i = 0;
  let currentClass = null;
  // Brace depth recorded when entering the current class/struct body, so we
  // know when a closing '}' actually ends the class rather than some nested
  // block inside one of its methods.
  let classBraceDepth = 0;
  let braceDepth = 0;
  // Carries block-comment state across lines for the whole file walk, so a
  // /* ... */ comment that spans multiple lines is correctly skipped on
  // every continuation line — not just the line where it opens.
  const commentState = { inBlockComment: false };
  // Every top-level survivor — globals, typedefs, enums, #define'd values,
  // and anything else that isn't an #include, a class/struct, or a
  // function/method — is collected here instead of being silently dropped.
  const moduleLevel = [];
  let moduleLevelStart = -1;

  while (i < lines.length) {
    const line     = lines[i];
    const stripped = line.trim();

    if (commentState.inBlockComment) {
      // Mid-comment continuation line: consume it for comment-closing
      // purposes only, never test it against the signature/class regexes.
      braceDepth += computeBraceDelta(line, commentState);
      i++; continue;
    }

    if (stripped === '' || stripped.startsWith('//')) { i++; continue; }
    if (stripped.startsWith('/*') || stripped.startsWith('*')) {
      // Still need to check whether this comment closes on the same line —
      // computeBraceDelta's commentState tracking handles that for us.
      braceDepth += computeBraceDelta(line, commentState);
      i++; continue;
    }

    // Preprocessor directives (#define, #ifdef, #pragma, etc.) are never
    // function bodies — including multi-line macros ending in a trailing
    // backslash, which we skip line-by-line without trying to brace-match.
    // Captured into module_code rather than discarded: a #define is
    // frequently exactly where a hardcoded secret or a dangerous macro body
    // lives.
    if (preprocessorRe.test(stripped)) {
      let j = i;
      while (lines[j] && lines[j].trimEnd().endsWith('\\')) j++;
      if (moduleLevelStart === -1) moduleLevelStart = i;
      for (let k = i; k <= j; k++) moduleLevel.push(lines[k]);
      i = j + 1; continue;
    }

    const classMatch = stripped.match(classRe);
    if (classMatch) {
      currentClass = classMatch[1];
      classBraceDepth = braceDepth; // depth BEFORE this class's own '{' is consumed
      braceDepth += computeBraceDelta(line, commentState);
      i++; continue;
    }
    if (currentClass && stripped.startsWith('}') && braceDepth === classBraceDepth + 1) {
      braceDepth += computeBraceDelta(line, commentState);
      currentClass = null;
      i++; continue;
    }

    const sigMatch = stripped.match(signatureStartRe);
    if (sigMatch && !controlKw.has(sigMatch[1])) {
      // Look ahead (across lines, in case the parameter list spans several
      // lines) to find whichever comes first: the '{' that starts a real
      // definition, or a ';' that closes a prototype/declaration. Scans a
      // MASKED copy of each line (comments and string/char contents blanked
      // out) so a ';' or '{' that only appears inside a trailing comment —
      // e.g. `int f(int x) // see docs; more text` — or inside a string
      // literal can never be mistaken for the real terminator. Uses a local
      // copy of commentState so this speculative scan never mutates the
      // outer walk's comment tracking; the real computeBraceDelta() calls
      // below (once we know which branch we took) advance the shared state
      // for real.
      let sawOpenBrace = false, sawSemicolon = false;
      let scanLine = i;
      let parenDepth = 0;
      let seenOpenParen = false;
      const lookaheadState = { inBlockComment: commentState.inBlockComment };
      outer:
      for (; scanLine < Math.min(i + 20, lines.length); scanLine++) {
        const sl = maskCLine(lines[scanLine], lookaheadState);
        for (let k = 0; k < sl.length; k++) {
          const c = sl[k];
          if (c === '(') { parenDepth++; seenOpenParen = true; }
          else if (c === ')') { parenDepth--; }
          else if (seenOpenParen && parenDepth === 0) {
            if (c === '{') { sawOpenBrace = true; break outer; }
            if (c === ';') { sawSemicolon = true; break outer; }
            // `: initializer_list` after a constructor's ')' is valid and
            // should not abort the lookahead — only bail on a stray '}'
            // (end of an enclosing block) which would mean this was never
            // a real signature to begin with.
            if (c === '}') { break outer; }
          }
        }
      }

      if (sawOpenBrace) {
        const name = sigMatch[1].includes('::') ? sigMatch[1].split('::').pop() : sigMatch[1];
        const ownerFromScope = sigMatch[1].includes('::') ? sigMatch[1].split('::')[0] : null;
        const blockStart = i;
        const block = collectBraceBlock(lines, i);
        const owner = currentClass || ownerFromScope;
        chunks.push(makeChunk(filePath, owner ? 'method' : 'function', owner, name, block.lines, blockStart));
        for (const bl of block.lines) braceDepth += computeBraceDelta(bl, commentState);
        i = block.nextIndex; continue;
      }
      if (sawSemicolon) {
        // Prototype / declaration only — not a definition. Captured into
        // module_code (a prototype can still carry security-relevant
        // context, e.g. a signature change) rather than skipped entirely.
        if (moduleLevelStart === -1) moduleLevelStart = i;
        for (const bl of lines.slice(i, scanLine + 1)) moduleLevel.push(bl);
        for (const bl of lines.slice(i, scanLine + 1)) braceDepth += computeBraceDelta(bl, commentState);
        i = scanLine + 1; continue;
      }
      // Neither found within the lookahead window (e.g. a false-positive
      // match inside an expression) — fall through and treat as module code.
    }

    if (stripped !== '{' && stripped !== '}') {
      if (moduleLevelStart === -1) moduleLevelStart = i;
      moduleLevel.push(line);
    }
    braceDepth += computeBraceDelta(line, commentState);
    i++;
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

export { chunkC };