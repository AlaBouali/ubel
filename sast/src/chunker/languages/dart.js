'use strict';

import { buildImportChunk, makeChunk } from '../braceblock.js';
import { computeBraceDelta } from '../bracedelta.js';
import { scanDeclaration } from '../declscan.js';

// ─── Dart / Flutter chunker ───────────────────────────────────────────────────
//
// Chunks: top-level functions (`main`, helpers), class / mixin / enum /
// extension members (methods, constructors with bodies, getters/setters,
// operators, `build()` overrides). Everything else — fields, const
// constructors, enum values, top-level variables — is gathered into one
// module_code chunk instead of being dropped.
//
// Dart-specific shapes handled here:
//   • arrow members:        `Widget build(ctx) => Foo(...);`, `int get x => _x;`
//   • named-parameter braces inside the parameter list (see declscan.js)
//   • `extension on T { … }` (unnamed extensions)
//   • annotation lines (`@override`, `@JsonKey(...)`) are prepended to the member

const CONTROL_KW = new Set([
  'if', 'for', 'while', 'switch', 'catch', 'else', 'try', 'do', 'return',
  'assert', 'super', 'this', 'await', 'throw', 'new', 'case', 'yield',
]);

function chunkDart(filePath, lines) {
  const chunks = [];
  const importRe = /^(?:import|export|part|library)\s+/;
  const importChunk = buildImportChunk(filePath, lines, importRe);
  if (importChunk) chunks.push(importChunk);

  const typeRe = /^(?:(?:abstract|base|final|sealed|interface|mixin|macro)\s+)*(?:class|mixin|enum|extension)\s+(?:type\s+)?(?:const\s+)?([A-Za-z_]\w*)?/;
  const unnamedExtRe = /^extension\s+on\s+([A-Za-z_][\w]*)/;

  const mods     = '(?:(?:static|external|abstract|override|factory|const|covariant|late|final)\\s+)*';
  const typeTok  = '(?:[A-Za-z_][\\w.]*(?:<[^()=]*>)?\\??\\s+)*';
  const nameTok  = 'operator\\s*[^\\s(]+|[A-Za-z_]\\w*(?:\\.[A-Za-z_]\\w*)?';
  const callableRe = new RegExp(`^\\s*${mods}(${typeTok})(${nameTok})\\s*(?:<[^()=]*>)?\\s*\\(`);
  const accessorRe = new RegExp(`^\\s*${mods}${typeTok}(?:get|set)\\s+([A-Za-z_]\\w*)`);
  const pureAnnotationRe = /^\s*@[A-Za-z_][\w.]*(?:\([^)]*\))?\s*$/;

  let i = 0;
  // Stack of enclosing types: { name, depth } where depth is the brace depth
  // BEFORE that type's own '{' was consumed. A closing '}' ends the type only
  // when it brings braceDepth back to depth — nested blocks inside (initializer
  // lists, a multi-line map literal in a field) must not end it early.
  const typeStack = [];
  let braceDepth = 0;
  const pendingAnnotations = [];
  const commentState = { inBlockComment: false };
  const moduleLevel = [];
  let moduleLevelStart = -1;

  const flushPending = () => {
    if (pendingAnnotations.length > 0) {
      if (moduleLevelStart === -1) moduleLevelStart = i - pendingAnnotations.length;
      moduleLevel.push(...pendingAnnotations);
      pendingAnnotations.length = 0;
    }
  };

  while (i < lines.length) {
    const line     = lines[i];
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

    // Already emitted as the dedicated `imports` chunk above.
    if (braceDepth === 0 && importRe.test(stripped)) { i++; continue; }

    if (pureAnnotationRe.test(line)) {
      pendingAnnotations.push(line);
      i++; continue;
    }

    const top = typeStack.length ? typeStack[typeStack.length - 1] : null;

    // ── Type declarations (Dart has no nested types: top level only) ─────────
    if (braceDepth === 0 && /^\S/.test(line)) {
      const tm = stripped.match(typeRe);
      if (tm) {
        let name = tm[1];
        if (/^extension\s/.test(stripped)) {
          const um = stripped.match(unnamedExtRe);
          if (um) name = `extension_on_${um[1]}`;
        }
        // `class A = B with C;` — no body, nothing to track.
        const bodyless = !stripped.includes('{') && stripped.endsWith(';');
        pendingAnnotations.length = 0;
        if (name && !bodyless) typeStack.push({ name, depth: braceDepth });
        braceDepth += computeBraceDelta(line, commentState);
        i++; continue;
      }
    }

    if (top && stripped.startsWith('}') && braceDepth === top.depth + 1) {
      braceDepth += computeBraceDelta(line, commentState);
      typeStack.pop();
      i++; continue;
    }

    // ── Callable members / top-level functions ───────────────────────────────
    const atMemberLevel = top ? braceDepth === top.depth + 1
                              : (braceDepth === 0 && /^\S/.test(line));
    if (atMemberLevel) {
      const owner = top ? top.name : null;
      let name = null;
      let arrow = true;

      const am = line.match(accessorRe);
      if (am) {
        name = am[1];
      } else {
        const cm = line.match(callableRe);
        if (cm) {
          name = cm[2];
          const hadType = cm[1].trim().length > 0;
          const isCtor  = owner && (name === owner || name.startsWith(`${owner}.`));
          // With no return type, only a constructor of the enclosing type is
          // plausible — otherwise this is a continuation line of a multi-line
          // field initializer (`Foo(a),`) and must not become a chunk.
          if (!hadType && !isCtor && !/^\s*factory\s/.test(line)) name = null;
        }
      }
      if (name && CONTROL_KW.has(name)) name = null;

      if (name) {
        const decl = scanDeclaration(lines, i, { arrow });
        if (decl) {
          const blockStart = i - pendingAnnotations.length;
          const blockLines = [...pendingAnnotations, ...decl.lines];
          pendingAnnotations.length = 0;
          chunks.push(makeChunk(filePath, owner ? 'method' : 'function', owner, name, blockLines, blockStart));
          // The consumed declaration is brace-balanced, so braceDepth is unchanged.
          i = decl.nextIndex; continue;
        }
      }
    }

    flushPending();
    if (stripped.length > 0 && stripped !== '{' && stripped !== '}') {
      if (moduleLevelStart === -1) moduleLevelStart = i;
      moduleLevel.push(line);
    }
    braceDepth += computeBraceDelta(line, commentState);
    i++;
  }

  if (pendingAnnotations.length > 0) {
    if (moduleLevelStart === -1) moduleLevelStart = lines.length - pendingAnnotations.length;
    moduleLevel.push(...pendingAnnotations);
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

export { chunkDart };
