'use strict';

import { makeChunk, buildImportChunk } from '../braceblock.js';

// ─── Ruby chunker ─────────────────────────────────────────────────────────────

function chunkRuby(filePath, lines) {
  const chunks = [];
  const importChunk = buildImportChunk(filePath, lines,
    /^(?:require|require_relative|include|extend|prepend)\s+/);
  if (importChunk) chunks.push(importChunk);

  const classRe = /^(?:class|module)\s+([A-Za-z_][\w:]*)/;
  const defRe   = /^(\s*)def\s+(?:self\.)?([A-Za-z_]\w*[?!]?)/;

  // Ruby method-level macros: bare method calls at the same indent as the
  // upcoming def that annotate or configure it. Covers:
  //   Rails:   before_action, after_action, around_action, skip_before_action,
  //            before_filter, around_filter, validates, validate, belongs_to,
  //            has_many, has_one, scope, attr_accessible, attr_protected
  //   RSpec:   subject, let, let!, shared_context, before, after, around
  //   Devise:  devise, devise_for
  //   Pundit:  policy_class
  //   General: attr_reader, attr_writer, attr_accessor, memoize,
  //            deprecated, throttle, authorize, authenticate, cache
  // The regex matches any snake_case call (with or without args) that is NOT
  // a structural keyword, not a require/include/extend (handled elsewhere),
  // and not a def/class/module/end. This is intentionally broad — a false
  // positive (collecting a stray expression as a "macro") is far less harmful
  // than missing a security-relevant decorator like `skip_before_action`.
  const macroRe = /^([a-z_]\w*)[\s(!'":,\[]/;
  const macroStructuralKw = new Set([
    'if', 'unless', 'while', 'until', 'for', 'case', 'when', 'begin',
    'rescue', 'ensure', 'raise', 'return', 'yield', 'super', 'self',
    'end', 'do', 'then', 'else', 'elsif', 'in', 'and', 'or', 'not',
    'require', 'require_relative', 'include', 'extend', 'prepend',
    'class', 'module', 'def',
  ]);

  let i = 0;
  let currentClass = null;
  const moduleLevel = [];
  let moduleLevelStart = -1;
  // Pending macro call lines immediately preceding a def.
  const pendingMacros = [];

  // Flushes any buffered macro lines that never attached to a def — a
  // trailing macro right before 'end' closes the class, a macro followed
  // by another non-def line, or a macro on the last line(s) of the file
  // with nothing after it. Without this they were silently discarded the
  // moment pendingMacros.length was reset to 0, rather than surviving
  // anywhere in the output — and a macro like skip_before_action is
  // exactly the kind of line that matters for a security review.
  function flushPendingMacros(atIndex) {
    if (pendingMacros.length === 0) return;
    if (moduleLevelStart === -1) moduleLevelStart = atIndex - pendingMacros.length;
    moduleLevel.push(...pendingMacros);
    pendingMacros.length = 0;
  }

  while (i < lines.length) {
    const line     = lines[i];
    const stripped = line.trimStart();
    const trimmed  = stripped.trimEnd();

    if (stripped.startsWith('#')) { i++; continue; }

    // Blank lines between macros and the def are allowed — don't reset.
    if (trimmed.length === 0) { i++; continue; }

    const classMatch = stripped.match(classRe);
    if (classMatch) { flushPendingMacros(i); currentClass = classMatch[1]; i++; continue; }
    if (stripped.trim() === 'end' && currentClass) { flushPendingMacros(i); currentClass = null; i++; continue; }

    const defMatch = stripped.match(defRe);
    if (defMatch) {
      const name       = defMatch[2];
      const blockStart = i - pendingMacros.length;
      const blockLines = [...pendingMacros, line];
      pendingMacros.length = 0;
      i++;
      let depth = 1;
      const blockOpenerRe = /^\s*(?:def|begin|if|unless|case|while|until|for|class|module)\b/;
      const doBlockRe     = /\bdo\s*(?:\|[^|]*\|)?\s*(?:#.*)?$/;
      while (i < lines.length && depth > 0) {
        const nl = lines[i];
        const ns = nl.trimStart();
        if (!ns.startsWith('#')) {
          const clean = ns.replace(/'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|`(?:[^`\\]|\\.)*`/g, '""');
          if (blockOpenerRe.test(clean) || doBlockRe.test(clean)) {
            depth++;
          } else if (/^end\b/.test(clean)) {
            depth--;
          }
        }
        blockLines.push(nl);
        i++;
        if (depth === 0) break;
      }
      chunks.push(makeChunk(filePath, currentClass ? 'method' : 'function', currentClass, name, blockLines, blockStart));
      continue;
    }

    // Collect macro calls. Only buffer lines that look like a bare method call
    // (lowercase start, not a structural keyword) and are within a class body
    // or at module level where method decorators appear in practice.
    const macroMatch = trimmed.match(macroRe);
    if (macroMatch && !macroStructuralKw.has(macroMatch[1])) {
      pendingMacros.push(line);
      i++; continue;
    }

    // Any other non-blank, non-comment line that isn't a macro or def resets
    // — flushed to module_code first so nothing is silently lost.
    flushPendingMacros(i);

    if (trimmed.length > 0 && !classRe.test(stripped) && !defRe.test(stripped) &&
        !/^(?:require|require_relative|include|extend|prepend)\s/.test(stripped)) {
      if (moduleLevelStart === -1) moduleLevelStart = i;
      moduleLevel.push(line);
    }
    i++;
  }

  // A macro on the very last line(s) of the file with nothing after it
  // would otherwise never hit any of the flush points above.
  flushPendingMacros(lines.length);

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

export { chunkRuby };