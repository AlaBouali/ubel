'use strict';

import { regexCanFollow, consumeRegexLiteral } from './regexliteral.js';

// ─── Brace-balanced block collector ──────────────────────────────────────────
// Returns collected lines AND the 1-based start line number of the block.

function collectBraceBlock(lines, startIndex) {
  const collected = [];
  let depth        = 0;
  let started      = false;
  let i            = startIndex;
  let inBlockComment = false;
  // Template-literal tracking: stack of nesting depths at the time each
  // backtick was opened, so ${…} braces inside template literals don't
  // throw off our depth counter.
  let inTemplateLiteral = false;
  let templateDepthStack = []; // brace-depth at each nested template level

  // Tracks the last significant token scanned (across the whole block, not
  // just the current line) so a bare '/' can be told apart from the start
  // of a regex literal — see regexLiteral.js. Without this, a pattern like
  // /^https?:\/\// reads as "//" partway through and the scanner mistakes
  // it for a line comment, losing whatever sat after it on that line —
  // including, in the worst case, the block's own opening '{'.
  let lastToken = null;
  let wordBuf   = '';
  const flushWord = () => { if (wordBuf) { lastToken = wordBuf; wordBuf = ''; } };

  while (i < lines.length) {
    const line = lines[i];
    collected.push(line);

    let j = 0;
    while (j < line.length) {
      const ch  = line[j];
      const ch2 = line.slice(j, j + 2);

      // ── Block comment ─────────────────────────────────────────────────
      if (inBlockComment) {
        if (ch2 === '*/') { inBlockComment = false; j += 2; }
        else { j++; }
        continue;
      }

      // ── Inside a template literal ─────────────────────────────────────
      if (inTemplateLiteral) {
        if (ch === '\\') { j += 2; continue; }          // escape sequence
        if (ch2 === '${') {                              // enter interpolation
          templateDepthStack.push(depth);
          depth++; started = true;
          inTemplateLiteral = false;                     // now scanning normal JS
          lastToken = null;                               // fresh expression context
          j += 2; continue;
        }
        if (ch === '`') { inTemplateLiteral = false; lastToken = 'VALUE'; j++; continue; } // end template
        j++;
        continue;
      }

      // ── Line comment ──────────────────────────────────────────────────
      if (ch2 === '//') break;

      // ── Block comment open ────────────────────────────────────────────
      if (ch2 === '/*') { inBlockComment = true; j += 2; continue; }

      // ── Regex literal ─────────────────────────────────────────────────
      // Must run before string handling below (both start scanning at a
      // single-char check) and after the '//'/'/*' checks above, since
      // JS never treats '//' or '/*' as a regex opener regardless of
      // context — comment syntax always wins that ambiguity.
      if (ch === '/' && regexCanFollow(lastToken)) {
        const end = consumeRegexLiteral(line, j);
        if (end !== null) {
          lastToken = 'VALUE';
          j = end;
          continue;
        }
        // No valid closing '/' on this line — not actually a regex
        // literal. Fall through, treat '/' as an ordinary character below.
      }

      // ── String literals ───────────────────────────────────────────────
      if (ch === '"' || ch === "'") {
        const quote = ch; j++;
        while (j < line.length) {
          if (line[j] === '\\') { j += 2; continue; }
          if (line[j] === quote) { j++; break; }
          j++;
        }
        lastToken = 'VALUE';
        continue;
      }

      // ── Template literal open ─────────────────────────────────────────
      if (ch === '`') { inTemplateLiteral = true; j++; continue; }

      // ── Braces ────────────────────────────────────────────────────────
      if (ch === '{') {
        depth++; started = true;
        // If we just closed a template interpolation, pop its saved depth
      } else if (ch === '}') {
        // Check if this closes a template interpolation
        if (templateDepthStack.length > 0 && depth === templateDepthStack[templateDepthStack.length - 1] + 1) {
          templateDepthStack.pop();
          inTemplateLiteral = true; // back inside the template literal
          depth--;
        } else {
          depth--;
        }
      }

      if (/[A-Za-z0-9_$]/.test(ch)) {
        wordBuf += ch;
      } else {
        flushWord();
        if (!/\s/.test(ch)) lastToken = ch;
      }
      j++;
    }
    flushWord();

    i++;
    if (!started && line.includes('=>') && line.trimEnd().endsWith(';')) break;
    if (started && depth === 0) break;
  }

  return { lines: collected, nextIndex: i };
}

// ─── Import chunk builder ─────────────────────────────────────────────────────

function buildImportChunk(filePath, lines, importRe) {
  const importLines = [];
  for (let i = 0; i < lines.length; i++) {
    if (importRe.test(lines[i].trim())) importLines.push(lines[i]);
  }
  if (importLines.length === 0) return null;
  return {
    id:        `${filePath}:imports`,
    type:      'imports',
    file:      filePath,
    class:     null,
    name:      'imports',
    startLine: 1,
    endLine:   importLines.length,
    code:      importLines.join('\n'),
  };
}

// ─── Chunk factory helper ─────────────────────────────────────────────────────

function makeChunk(filePath, type, className, name, blockLines, startIndex) {
  const startLine = startIndex + 1;           // convert 0-based index → 1-based line
  const endLine   = startLine + blockLines.length - 1;
  const code      = blockLines.join('\n');    // raw source — comments stripped later, before LLM submission
  return {
    id:        className ? `${filePath}:${className}:${name}` : `${filePath}:${name}`,
    type,
    file:      filePath,
    class:     className,
    name,
    startLine,
    endLine,
    code,
  };
}

export { collectBraceBlock, buildImportChunk, makeChunk };