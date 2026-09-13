'use strict';

// ─── Shared C-family brace-delta counter ───────────────────────────────────
//
// Computes the net { / } delta for a single line, skipping line comments,
// block comments, and single/double-quoted string/char literal contents so
// braces inside them are never counted as real code structure.
//
// `commentState.inBlockComment` is carried across calls (by reference, via
// the object) so a /* ... */ comment spanning multiple lines is correctly
// skipped on every continuation line, not just the line where it opens —
// callers must reuse the same commentState object across the whole file walk.
//
// This intentionally does NOT handle language-specific extended string forms
// (C# verbatim `@"..."` / interpolated `$"..."` strings, Rust raw `r"..."`
// strings, C++11 raw `R"(...)"` strings). Those are narrow, best-effort gaps
// consistent with the rest of this chunker rather than silently-assumed-away
// correctness — a brace inside one of those could desync depth tracking.
function computeBraceDelta(line, commentState) {
  let delta = 0;
  let j = 0;
  if (commentState.inBlockComment) {
    const end = line.indexOf('*/');
    if (end === -1) return 0;             // whole line still inside the comment
    j = end + 2;
    commentState.inBlockComment = false;
  }
  while (j < line.length) {
    const ch = line[j];
    const ch2 = line.slice(j, j + 2);
    if (ch2 === '//') break;
    if (ch2 === '/*') {
      const end = line.indexOf('*/', j + 2);
      if (end === -1) { commentState.inBlockComment = true; break; }
      j = end + 2; continue;
    }
    if (ch === '"' || ch === "'") {
      const quote = ch; j++;
      while (j < line.length) {
        if (line[j] === '\\') { j += 2; continue; }
        if (line[j] === quote) { j++; break; }
        j++;
      }
      continue;
    }
    if (ch === '{') delta++;
    else if (ch === '}') delta--;
    j++;
  }
  return delta;
}

export { computeBraceDelta };