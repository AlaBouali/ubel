'use strict';

// ─── Shared JS/TS regex-literal lexing helper ──────────────────────────────
//
// Every hand-rolled scanner in this codebase that walks JS-family source
// char-by-char (stripCommentsJS here, collectBraceBlock in braceblock.js,
// and maskNonCode in ubel-sast/callGraph.js) previously had no concept of
// a bare `/regex/` literal. That's a correctness bug, not a cosmetic one:
// a pattern like `/^https?:\/\//` contains an escaped slash immediately
// followed by the real closing slash, which reads as `//` to a scanner
// that only tracks strings/templates/comments — so the scanner mistakes it
// for a line comment and silently discards everything after it on that
// line, before the code ever reaches an LLM, a brace-depth counter, or the
// call-graph resolver.
//
// This module implements the standard lexer heuristic for regex-vs-division
// disambiguation (the same one real JS lexers like Esprima/Acorn use): a
// `/` can start a regex literal only if the last significant token scanned
// was NOT something that behaves like a value (identifier, number, string,
// `)`, `]`). After a value, `/` is division. Everywhere else — operators,
// punctuation, keywords like `return`/`typeof`, or the start of a
// statement — `/` is allowed to start a regex.
//
// This is intentionally not a full parser, and doesn't try to be — it's
// the same class of best-effort heuristic as the rest of the chunker, just
// applied to one more token type. `}` is genuinely ambiguous between
// end-of-block and end-of-object-literal without real scope tracking; this
// defaults to "regex allowed", which is right far more often than not in
// real code, and errs toward the failure mode (over-eager regex detection
// on rare/invalid-looking code) that at worst re-copies a span verbatim,
// rather than the failure mode this replaces (silently eating real code).

const REGEX_ALLOWED_KEYWORDS = new Set([
  'return', 'typeof', 'instanceof', 'in', 'of', 'new', 'delete', 'void',
  'throw', 'case', 'do', 'else', 'yield', 'await', 'if', 'while', 'for',
  'switch', 'with', 'export', 'default', 'extends', 'import', 'const',
  'let', 'var', 'function', 'async', 'static', 'class', 'try', 'catch',
  'finally',
]);

// `lastToken` is one of:
//   null        — start of scan / start of a statement
//   'VALUE'     — sentinel meaning the last thing scanned behaves like a
//                 value (closed string, closed template, closed regex,
//                 or a number literal)
//   a bare word — an identifier or keyword, e.g. "return", "foo"
//   a single punctuation character, e.g. '(', ',', '=', '{', '}', ')', ']'
function regexCanFollow(lastToken) {
  if (lastToken === null) return true;
  if (lastToken === 'VALUE') return false;
  if (/^\d/.test(lastToken)) return false;                 // number literal
  if (/^[A-Za-z_$][\w$]*$/.test(lastToken)) {               // identifier/keyword
    return REGEX_ALLOWED_KEYWORDS.has(lastToken);
  }
  if (lastToken === ')' || lastToken === ']') return false; // end of call/index
  return true; // operators, '(', ',', '{', ';', ':', '=', etc.
}

// Attempts to consume a full `/regex/flags` literal starting at s[start]
// (which must be '/'). Honours backslash escapes and `[...]` character
// classes, where an unescaped '/' inside a class does not close the
// literal. Regex literals cannot span lines in JS, so hitting '\n' before
// an unescaped closing '/' means this was never a valid regex literal —
// returns null so the caller falls back to treating the '/' as an ordinary
// character (division, or a stray unterminated slash — either way, safer
// to consume nothing than to guess).
function consumeRegexLiteral(s, start) {
  let j = start + 1;
  let inClass = false;
  while (j < s.length) {
    const ch = s[j];
    if (ch === '\n') return null;
    if (ch === '\\') { j += 2; continue; }
    if (ch === '[') { inClass = true; j++; continue; }
    if (ch === ']') { inClass = false; j++; continue; }
    if (ch === '/' && !inClass) {
      j++;
      while (j < s.length && /[a-zA-Z]/.test(s[j])) j++; // flags: g i m s u y d v
      return j;
    }
    j++;
  }
  return null;
}

export { REGEX_ALLOWED_KEYWORDS, regexCanFollow, consumeRegexLiteral };