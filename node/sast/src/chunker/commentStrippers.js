'use strict';

import path from 'path';
import { EXT_FAMILY } from './constants.js';
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

// Dispatch to the right stripper based on file extension
function stripComments(code, filePath) {
  const family = EXT_FAMILY[path.extname(filePath).toLowerCase()];
  switch (family) {
    case 'python': return stripCommentsPython(code);
    case 'php':    return stripCommentsPHP(code);
    case 'ruby':   return stripCommentsRuby(code);
    case 'go':     return stripCommentsGo(code);
    case 'rust':   return stripCommentsRust(code);
    case 'java':   return stripCommentsJava(code);
    case 'kotlin': return stripCommentsKotlin(code);
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
  stripCommentsCSharp,
  collapseBlankLines,
};