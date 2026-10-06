'use strict';

import { buildImportChunk, makeChunk } from '../braceblock.js';
import { computeBraceDelta } from '../bracedelta.js';
import { scanDeclaration } from '../declscan.js';

// ─── Swift chunker ────────────────────────────────────────────────────────────
//
// Chunks: top-level functions and every func / init / deinit / subscript /
// computed property (`var body: some View { … }`) inside a class, struct, enum,
// actor or extension. Stored properties, enum cases, property-observer-only
// declarations and top-level statements (main.swift style) are gathered into one
// module_code chunk instead of being dropped.
//
// Swift-specific shapes handled here:
//   • nested types (a stack of enclosing types, not a single "current class")
//   • inline attributes: `@objc func …`, `@IBAction func …`, `@MainActor final class …`
//   • `class func` / `class var` are members, not class declarations
//   • protocol bodies hold requirements with no body — members are not chunked there
//   • computed properties (`var x: T { … }`), distinguished from stored ones by
//     the absence of `=` before the '{'

const NOT_A_TYPE_NAME = new Set(['func', 'var', 'let', 'init', 'subscript', 'deinit']);

function chunkSwift(filePath, lines) {
  const chunks = [];
  const importRe = /^(?:@[\w.]+\s+)*import\s+/;
  const importChunk = buildImportChunk(filePath, lines, importRe);
  if (importChunk) chunks.push(importChunk);

  const attrs = '(?:@[\\w.]+(?:\\([^)]*\\))?\\s+)*';
  const mods  = '(?:(?:public|open|internal|fileprivate|private|package|static|class|final|override|mutating|nonmutating|lazy|dynamic|convenience|required|nonisolated|indirect|prefix|postfix|infix|weak|unowned|optional|distributed)(?:\\([a-z]+\\))?\\s+)*';

  const typeRe     = new RegExp(`^${attrs}${mods}(class|struct|enum|protocol|extension|actor)\\s+([A-Za-z_][\\w.]*)`);
  const funcRe     = new RegExp(`^\\s*${attrs}${mods}func\\s+([^\\s(<]+)`);
  const initRe     = new RegExp(`^\\s*${attrs}${mods}(init[?!]?|deinit)\\s*(?:<[^>]*>)?\\s*[({]`);
  const subscriptRe = new RegExp(`^\\s*${attrs}${mods}(subscript)\\s*(?:<[^>]*>)?\\s*\\(`);
  const computedRe = new RegExp(`^\\s*${attrs}${mods}var\\s+([A-Za-z_]\\w*)\\s*:\\s*[^={}]+\\{`);
  const pureAttributeRe = /^\s*@[A-Za-z_][\w.]*(?:\([^)]*\))?\s*$/;

  let i = 0;
  // Stack of enclosing types: { name, kind, depth } where depth is the brace
  // depth BEFORE that type's own '{' was consumed. See dart.js for why a plain
  // "closing brace ends the type" test is not enough.
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

    if (pureAttributeRe.test(line)) {
      pendingAnnotations.push(line);
      i++; continue;
    }

    const top = typeStack.length ? typeStack[typeStack.length - 1] : null;
    const atMemberLevel = top ? braceDepth === top.depth + 1 : braceDepth === 0;

    // ── Type declarations (top level or directly inside another type) ───────
    if (atMemberLevel) {
      const tm = stripped.match(typeRe);
      if (tm && !NOT_A_TYPE_NAME.has(tm[2])) {
        pendingAnnotations.length = 0;
        typeStack.push({ name: tm[2], kind: tm[1], depth: braceDepth });
        braceDepth += computeBraceDelta(line, commentState);
        i++; continue;
      }
    }

    if (top && stripped.startsWith('}') && braceDepth === top.depth + 1) {
      braceDepth += computeBraceDelta(line, commentState);
      typeStack.pop();
      i++; continue;
    }

    // ── Members / top-level functions ────────────────────────────────────────
    // Protocol bodies only declare requirements (no bodies) — leave them as
    // module_code context rather than chunking bodiless declarations.
    if (atMemberLevel && !(top && top.kind === 'protocol')) {
      const m = line.match(funcRe) || line.match(initRe) || line.match(subscriptRe) || line.match(computedRe);
      if (m) {
        const owner = top ? top.name : null;
        const decl  = scanDeclaration(lines, i, { arrow: false });
        if (decl) {
          const blockStart = i - pendingAnnotations.length;
          const blockLines = [...pendingAnnotations, ...decl.lines];
          pendingAnnotations.length = 0;
          chunks.push(makeChunk(filePath, owner ? 'method' : 'function', owner, m[1], blockLines, blockStart));
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

export { chunkSwift };
