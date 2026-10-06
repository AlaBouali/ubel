'use strict';

// ─── Declaration scanner (Dart / Swift) ───────────────────────────────────────
//
// collectBraceBlock() (braceblock.js) assumes the first '{' it meets opens the
// body. That is wrong for two shapes common in Dart and Swift:
//
//   • Dart named parameters live inside braces *within the parameter list*:
//         Widget _row({
//           required String label,
//         }) {                      ← the real body
//     The '{' … '}' of the parameter list balances to depth 0 on its own, so
//     collectBraceBlock stops there and the method body is lost.
//
//   • Dart arrow members (`Widget build(ctx) => Foo(...);`, `int get x => _x;`)
//     have no braces at all; collectBraceBlock would run on until it found some
//     unrelated '{' further down the file.
//
// scanDeclaration() walks the declaration from its first line, tracks
// parentheses/brackets so parameter-list braces are ignored, and reports:
//   kind: 'block'  — body is a { … } block (returned lines end at its close)
//   kind: 'arrow'  — body is `=> expr;` (returned lines end at the ';')
//   null           — a declaration with no body (abstract / protocol
//                    requirement / `external` / constructor ending in ';')
//
// It understands // and /* */ comments (nested, for Swift), '...' / "..."
// strings with escapes, and triple-quoted multi-line strings, so braces and
// semicolons inside them never count. Raw-string prefixes (Dart r'..', Swift
// #".."#) are a narrow best-effort gap, consistent with bracedelta.js.

function scanDeclaration(lines, startIndex, opts = {}) {
  const { arrow = false, maxLines = 600, maxHeaderLines = 40 } = opts;

  let paren = 0;           // () and [] nesting while still in the declaration header
  let brace = 0;           // {} nesting once the body has started
  let mode  = 'header';    // 'header' | 'block' | 'arrow'
  let nest  = 0;           // all-bracket nesting inside an arrow body
  let blockComment = 0;    // nesting depth of an open /* */ comment
  let triple = null;       // active triple-quote delimiter, if inside one

  const end = Math.min(lines.length, startIndex + maxLines);

  for (let i = startIndex; i < end; i++) {
    if (mode === 'header' && i - startIndex >= maxHeaderLines) return null;
    const line = lines[i];
    let j = 0;

    while (j < line.length) {
      const ch  = line[j];
      const ch2 = line.slice(j, j + 2);
      const ch3 = line.slice(j, j + 3);

      if (blockComment > 0) {
        if (ch2 === '*/') { blockComment--; j += 2; }
        else if (ch2 === '/*') { blockComment++; j += 2; }
        else j++;
        continue;
      }
      if (triple) {
        if (ch === '\\') { j += 2; continue; }
        if (ch3 === triple) { triple = null; j += 3; continue; }
        j++; continue;
      }

      if (ch2 === '//') break;
      if (ch2 === '/*') { blockComment++; j += 2; continue; }
      if (ch3 === '"""' || ch3 === "'''") { triple = ch3; j += 3; continue; }
      if (ch === '"' || ch === "'") {
        const q = ch; j++;
        while (j < line.length) {
          if (line[j] === '\\') { j += 2; continue; }
          if (line[j] === q) { j++; break; }
          j++;
        }
        continue;
      }

      if (mode === 'header') {
        if (ch === '(' || ch === '[') paren++;
        else if (ch === ')' || ch === ']') paren--;
        else if (paren <= 0) {
          if (ch === '{') { mode = 'block'; brace = 1; }
          else if (arrow && ch2 === '=>') { mode = 'arrow'; j += 2; continue; }
          else if (ch === ';' || ch === '}') return null; // no body
        }
        j++; continue;
      }

      if (mode === 'block') {
        if (ch === '{') brace++;
        else if (ch === '}') {
          brace--;
          if (brace === 0) return finish(lines, startIndex, i, 'block');
        }
        j++; continue;
      }

      // mode === 'arrow'
      if (ch === '(' || ch === '[' || ch === '{') nest++;
      else if (ch === ')' || ch === ']' || ch === '}') nest--;
      else if (ch === ';' && nest <= 0) return finish(lines, startIndex, i, 'arrow');
      j++;
    }
  }
  return null;
}

function finish(lines, startIndex, lastIndex, kind) {
  return {
    kind,
    lines: lines.slice(startIndex, lastIndex + 1),
    nextIndex: lastIndex + 1,
  };
}

export { scanDeclaration };
