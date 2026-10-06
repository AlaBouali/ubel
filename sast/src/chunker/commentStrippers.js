'use strict';

import path from 'path';
import { EXT_FAMILY } from './constants.js';
import { detectDockerKind } from './configDetect.js';
import { regexCanFollow, consumeRegexLiteral } from './regexliteral.js';

// ─── Comment stripper ─────────────────────────────────────────────────────────
//
// Removes comments from extracted chunk code so the LLM focuses on logic only.
// Each language family has its own stripper. All return the cleaned code string
// with blank lines collapsed (no more than one consecutive blank line).

function stripCommentsJS(code) {
  const lines   = code.split('\n');
  const out     = [];
  let inBlock   = false;
  // Tracks the last significant token scanned (across the whole chunk, not
  // just the current line) so a bare '/' can be told apart from the start
  // of a regex literal — see regexLiteral.js for why this matters (without
  // it, /^https?:\/\// reads as "//" partway through and truncates the
  // rest of the line as a fake comment).
  let lastToken = null;
  let wordBuf   = '';
  const flushWord = () => { if (wordBuf) { lastToken = wordBuf; wordBuf = ''; } };

  for (const line of lines) {
    let result  = '';
    let i       = 0;
    let inStr   = false;
    let strChar = '';
    while (i < line.length) {
      const ch  = line[i];
      const ch2 = line.slice(i, i + 2);
      if (inBlock) {
        if (ch2 === '*/') { inBlock = false; i += 2; } else { i++; }
        continue;
      }
      if (inStr) {
        result += ch;
        if (ch === '\\') { result += line[i + 1] || ''; i += 2; continue; }
        if (ch === strChar) { inStr = false; lastToken = 'VALUE'; }
        i++; continue;
      }
      if (ch === '"' || ch === "'" || ch === '`') { inStr = true; strChar = ch; result += ch; i++; continue; }
      if (ch2 === '//') break;              // rest of line is a comment
      if (ch2 === '/*') { inBlock = true; i += 2; continue; }
      if (ch === '/' && regexCanFollow(lastToken)) {
        const end = consumeRegexLiteral(line, i);
        if (end !== null) {
          result += line.slice(i, end);
          lastToken = 'VALUE';
          i = end;
          continue;
        }
        // No valid closing '/' on this line — not actually a regex literal
        // (almost certainly division). Fall through, treat '/' normally.
      }
      result += ch;
      if (/[A-Za-z0-9_$]/.test(ch)) {
        wordBuf += ch;
      } else {
        flushWord();
        if (!/\s/.test(ch)) lastToken = ch;
      }
      i++;
    }
    flushWord();
    out.push(result);
  }
  return collapseBlankLines(out);
}

function stripCommentsPython(code) {
  const lines  = code.split('\n');
  const out    = [];
  let inTriple = false;
  let tripleQ  = '';
  for (const line of lines) {
    // Handle triple-quoted docstrings (skip entirely)
    if (inTriple) {
      if (line.includes(tripleQ)) inTriple = false;
      continue;
    }
    const t = line.trim();
    if (t.startsWith('"""') || t.startsWith("'''")) {
      tripleQ = t.slice(0, 3);
      // Single-line docstring on same line?
      const rest = t.slice(3);
      if (rest.includes(tripleQ)) continue;   // """...""" on one line
      inTriple = true; continue;
    }
    // Inline comment: find # not inside a string
    let result  = '';
    let inStr   = false;
    let strChar = '';
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (inStr) {
        if (ch === '\\') { i++; continue; }
        if (ch === strChar) inStr = false;
        result += ch; continue;
      }
      if (ch === '"' || ch === "'") { inStr = true; strChar = ch; result += ch; continue; }
      if (ch === '#') break;
      result += ch;
    }
    out.push(result);
  }
  return collapseBlankLines(out);
}

function stripCommentsPHP(code) {
  // PHP shares // # and /* */ with JS, plus # comment style
  const lines  = code.split('\n');
  const out    = [];
  let inBlock  = false;
  for (const line of lines) {
    let result = '';
    let i = 0;
    let inStr = false; let strChar = '';
    while (i < line.length) {
      const ch  = line[i];
      const ch2 = line.slice(i, i + 2);
      if (inBlock) {
        if (ch2 === '*/') { inBlock = false; i += 2; } else i++;
        continue;
      }
      if (inStr) {
        result += ch;
        if (ch === '\\') { result += line[i + 1] || ''; i += 2; continue; }
        if (ch === strChar) inStr = false;
        i++; continue;
      }
      if (ch === '"' || ch === "'") { inStr = true; strChar = ch; result += ch; i++; continue; }
      if (ch2 === '//' || ch === '#') break;
      if (ch2 === '/*') { inBlock = true; i += 2; continue; }
      result += ch; i++;
    }
    out.push(result);
  }
  return collapseBlankLines(out);
}

function stripCommentsRuby(code) {
  const lines = code.split('\n');
  const out   = [];
  let inHere  = false;
  for (const line of lines) {
    if (inHere) { if (line.trim() === '=end') inHere = false; continue; }
    if (line.trim().startsWith('=begin')) { inHere = true; continue; }
    // Walk character-by-character so we don't strip # inside string literals
    let result  = '';
    let inStr   = false;
    let strChar = '';
    let i       = 0;
    while (i < line.length) {
      const ch = line[i];
      if (inStr) {
        result += ch;
        if (ch === '\\') { result += line[i + 1] || ''; i += 2; continue; }
        // #{...} interpolation: the # is part of the string — do NOT break
        if (ch === '#' && line[i + 1] === '{') { result += line[i + 1]; i += 2; continue; }
        if (ch === strChar) inStr = false;
        i++; continue;
      }
      if (ch === '"' || ch === "'" || ch === '`') { inStr = true; strChar = ch; result += ch; i++; continue; }
      if (ch === '#') break;   // real comment — rest of line discarded
      result += ch; i++;
    }
    out.push(result);
  }
  return collapseBlankLines(out);
}

function stripCommentsGo(code) {
  // Same as JS comment syntax
  return stripCommentsJS(code);
}

function stripCommentsRust(code) {
  // Rust uses // and /* */ — same as JS for our purposes
  return stripCommentsJS(code);
}

function stripCommentsJava(code) {
  return stripCommentsJS(code);
}

function stripCommentsKotlin(code) {
  return stripCommentsJS(code);
}

function stripCommentsCSharp(code) {
  return stripCommentsJS(code);
}

// Dart and Swift share C-style comments but differ from JS in ways that make
// the JS stripper unsafe for them:
//   • no regex literals — the JS stripper's regex heuristic could misread a
//     division as the start of one (and truncate the line)
//   • multi-line strings (Dart '''…''' / """…""", Swift """…""") that can
//     contain `//` (URLs) across lines
//   • Swift block comments nest; Swift raw strings (#"…"#); Dart raw strings
//     (r'…'); Dart single-quoted strings but Swift has no '…' strings at all
// so one character-level scanner, parameterised per language, handles both.
function stripCommentsCStyle(code, { singleQuoteStrings, nestedBlockComments, swiftRawStrings }) {
  const n = code.length;
  let out = '';
  let i = 0;

  while (i < n) {
    const ch  = code[i];
    const ch2 = code.slice(i, i + 2);
    const ch3 = code.slice(i, i + 3);

    if (ch2 === '//') { while (i < n && code[i] !== '\n') i++; continue; }

    if (ch2 === '/*') {
      let depth = 1;
      i += 2;
      while (i < n && depth > 0) {
        const two = code.slice(i, i + 2);
        if (two === '*/') { depth--; i += 2; }
        else if (nestedBlockComments && two === '/*') { depth++; i += 2; }
        else { if (code[i] === '\n') out += '\n'; i++; }
      }
      continue;
    }

    // Swift raw strings: #"…"#, ##"…"##, #"""…"""#
    if (swiftRawStrings && ch === '#') {
      const m = code.slice(i, i + 12).match(/^(#+)("""|")/);
      if (m) {
        const closer = m[2] + m[1];
        const start  = i;
        i += m[0].length;
        while (i < n && code.slice(i, i + closer.length) !== closer) i++;
        i = Math.min(n, i + closer.length);
        out += code.slice(start, i);
        continue;
      }
    }

    // Triple-quoted multi-line strings
    if (ch3 === '"""' || (singleQuoteStrings && ch3 === "'''")) {
      const start = i;
      i += 3;
      while (i < n && code.slice(i, i + 3) !== ch3) { if (code[i] === '\\') i++; i++; }
      i = Math.min(n, i + 3);
      out += code.slice(start, i);
      continue;
    }

    // Ordinary strings. Dart raw strings (r'…') have no escapes.
    if (ch === '"' || (singleQuoteStrings && ch === "'")) {
      const raw = singleQuoteStrings && /[rR]/.test(code[i - 1] || '') && !/[\w$]/.test(code[i - 2] || '');
      const start = i;
      i++;
      while (i < n && code[i] !== '\n') {
        if (!raw && code[i] === '\\') { i += 2; continue; }
        if (code[i] === ch) { i++; break; }
        i++;
      }
      out += code.slice(start, i);
      continue;
    }

    out += ch;
    i++;
  }
  return collapseBlankLines(out.split('\n'));
}

function stripCommentsDart(code) {
  return stripCommentsCStyle(code, { singleQuoteStrings: true, nestedBlockComments: true, swiftRawStrings: false });
}

function stripCommentsSwift(code) {
  return stripCommentsCStyle(code, { singleQuoteStrings: false, nestedBlockComments: true, swiftRawStrings: true });
}

// Dockerfile / Compose / Kubernetes / CloudFormation / Ansible: the only
// comment marker is '#', and — unlike shell — it's only treated as a comment
// when it starts the line or follows whitespace. This matters because these
// files commonly carry unquoted values containing '#' or '//' that are NOT
// comments, e.g. `ENV API_URL=http://example.com/path#fragment` — a JS-style
// stripper would wrongly truncate that at "//".
function stripCommentsHash(code) {
  const lines = code.split('\n');
  const out   = [];
  for (const line of lines) {
    let result  = '';
    let inStr   = false;
    let strChar = '';
    let i       = 0;
    while (i < line.length) {
      const ch = line[i];
      if (inStr) {
        result += ch;
        if (ch === '\\') { result += line[i + 1] || ''; i += 2; continue; }
        if (ch === strChar) inStr = false;
        i++; continue;
      }
      if (ch === '"' || ch === "'") { inStr = true; strChar = ch; result += ch; i++; continue; }
      if (ch === '#' && (i === 0 || /\s/.test(line[i - 1]))) break; // rest of line is a comment
      result += ch; i++;
    }
    out.push(result);
  }
  return collapseBlankLines(out);
}

// Terraform/HCL: '#', '//', and '/* */' comments, all quote-aware — same
// syntax PHP supports, so reuse that stripper. Unlike Dockerfile/YAML, HCL
// string values are always quoted, so no whitespace-precedes-'#' heuristic
// is needed here.
function stripCommentsHcl(code) {
  return stripCommentsPHP(code);
}

// Collapse more than one consecutive blank line into a single blank line
function collapseBlankLines(lines) {
  const out = [];
  let lastBlank = false;
  for (const line of lines) {
    const blank = line.trim().length === 0;
    if (blank && lastBlank) continue;
    out.push(line);
    lastBlank = blank;
  }
  // trim leading/trailing blank lines
  while (out.length > 0 && out[0].trim() === '')  out.shift();
  while (out.length > 0 && out[out.length - 1].trim() === '') out.pop();
  return out.join('\n');
}

// Dispatch to the right stripper based on file extension/name.
// Terraform (.tf/.tfvars) and Dockerfile/Compose (filename-based, no
// reliable extension) are checked before the EXT_FAMILY lookup since neither
// is resolvable from extension alone. Kubernetes/CloudFormation/Ansible share
// the ambiguous .yaml/.yml/.json extension with countless non-IaC files, but
// all use '#'-only comments same as Dockerfile/Compose, so no content sniff
// is needed here — just route any of those three extensions to the hash
// stripper.
function stripComments(code, filePath) {
  const ext = path.extname(filePath).toLowerCase();

  if (ext === '.tf' || ext === '.tfvars') return stripCommentsHcl(code);
  if (detectDockerKind(filePath)) return stripCommentsHash(code);
  if (ext === '.yaml' || ext === '.yml' || ext === '.json') return stripCommentsHash(code);

  const family = EXT_FAMILY[ext];
  switch (family) {
    case 'python': return stripCommentsPython(code);
    case 'php':    return stripCommentsPHP(code);
    case 'ruby':   return stripCommentsRuby(code);
    case 'go':     return stripCommentsGo(code);
    case 'rust':   return stripCommentsRust(code);
    case 'java':   return stripCommentsJava(code);
    case 'kotlin': return stripCommentsKotlin(code);
    case 'dart':   return stripCommentsDart(code);
    case 'swift':  return stripCommentsSwift(code);
    case 'csharp': return stripCommentsCSharp(code);
    case 'js':
    default:       return stripCommentsJS(code);
  }
}

export {
  stripComments,
  stripCommentsJS,
  stripCommentsPython,
  stripCommentsPHP,
  stripCommentsRuby,
  stripCommentsGo,
  stripCommentsRust,
  stripCommentsJava,
  stripCommentsKotlin,
  stripCommentsDart,
  stripCommentsSwift,
  stripCommentsCSharp,
  stripCommentsHash,
  stripCommentsHcl,
  collapseBlankLines,
};