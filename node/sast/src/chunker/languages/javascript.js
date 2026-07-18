'use strict';

import { collectBraceBlock, buildImportChunk, makeChunk } from '../braceblock.js';

// ─── JavaScript / TypeScript chunker ─────────────────────────────────────────

function chunkJS(filePath, lines) {
  const chunks = [];
  const importChunk = buildImportChunk(filePath, lines, /^(?:import |const .+=\s*require\()/);
  if (importChunk) chunks.push(importChunk);

  const classRe       = /^(?:export\s+)?(?:default\s+)?class\s+([A-Za-z_]\w*)/;
  const namedFuncRe   = /^(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_]\w*)\s*\(/;
  // Only CommonJS named export assignments count as a named unit here —
  // `const x = (...) => {}` is intentionally NOT matched: per-scope decision,
  // plain variable-assigned functions/arrows are out of scope (anonymous-ish,
  // not a declaration), while `module.exports.foo = ...` / `exports.foo = ...`
  // names a real export and is kept in scope.
  const exportAssignRe = /^(?:module\.)?exports\.([A-Za-z_]\w*)\s*=\s*(?:async\s+)?\(?/;
  const methodShortRe = /^(?:static\s+)?(?:async\s+)?([A-Za-z_]\w*)\s*\([^)]*\)\s*\{/;
  const methodArrowRe = /^(?:static\s+)?(?:async\s+)?([A-Za-z_]\w*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>/;
  const controlKw     = new Set(['if', 'for', 'while', 'switch', 'catch', 'else', 'try', 'finally']);

  // Class context stack: each entry { name, depth } where depth is the
  // brace depth recorded *before* the class opening { is consumed.
  // The class body closes when braceDepth drops back to that value.
  const classStack = [];
  let braceDepth   = 0;

  // Returns the net { - } delta for a single line, ignoring strings/comments.
  // `commentState.inBlock` carries block-comment state across calls so a
  // /* ... */ comment spanning multiple lines is correctly skipped on every
  // continuation line, not just the line where it opens.
  function netBraceDelta(line, commentState) {
    let delta = 0, j = 0;
    let inStr = false, strChar = '';
    let inTemplate = false;
    const tplDepthStack = [];
    if (commentState.inBlock) {
      const end = line.indexOf('*/');
      if (end === -1) return 0;             // whole line still inside the comment
      j = end + 2;
      commentState.inBlock = false;
    }
    while (j < line.length) {
      const ch = line[j], ch2 = line.slice(j, j + 2);
      if (inTemplate) {
        if (ch === '\\') { j += 2; continue; }
        if (ch2 === '${') { tplDepthStack.push(delta); delta++; inTemplate = false; j += 2; continue; }
        if (ch === '`')  { inTemplate = false; j++; continue; }
        j++; continue;
      }
      if (inStr) {
        if (ch === '\\') { j += 2; continue; }
        if (ch === strChar) inStr = false;
        j++; continue;
      }
      if (ch2 === '//') break;
      if (ch2 === '/*') {
        const end = line.indexOf('*/', j + 2);
        if (end === -1) { commentState.inBlock = true; break; }
        j = end + 2; continue;
      }
      if (ch === '"' || ch === "'") { inStr = true; strChar = ch; j++; continue; }
      if (ch === '`') { inTemplate = true; j++; continue; }
      if (ch === '{') {
        delta++;
      } else if (ch === '}') {
        if (tplDepthStack.length > 0 && delta === tplDepthStack[tplDepthStack.length - 1] + 1) {
          tplDepthStack.pop(); inTemplate = true; delta--;
        } else {
          delta--;
        }
      }
      j++;
    }
    return delta;
  }

  let i = 0;
  const moduleLevel = [];
  let moduleLevelStart = -1;
  // Carries block-comment state across the whole file walk (see netBraceDelta).
  const commentState = { inBlock: false };
  // Pending TypeScript/JS decorator lines (@Decorator / @decorator(...))
  // immediately preceding a class, function, or method declaration.
  // Only the call lines are buffered — not the decorator implementation.
  // Common in NestJS (@Get, @UseGuards), Angular (@Component), TypeORM
  // (@Column, @Entity), and the TC39 decorator proposal.
  const pendingDecorators = [];

  // Flushes any buffered decorator lines that never attached to a function
  // or method — a decorator on the class itself (@Entity, @Component:
  // describes the class, not any one method, so intentionally never
  // prepended to a method chunk), a decorator followed by another
  // non-declaration line, or a decorator on the last line(s) of the file
  // with nothing after it. Without this they were silently discarded the
  // moment pendingDecorators.length was reset to 0, rather than surviving
  // anywhere in the output.
  function flushPendingDecorators(atIndex) {
    if (pendingDecorators.length === 0) return;
    if (moduleLevelStart === -1) moduleLevelStart = atIndex - pendingDecorators.length;
    moduleLevel.push(...pendingDecorators);
    pendingDecorators.length = 0;
  }

  while (i < lines.length) {
    const line     = lines[i];
    const stripped = line.trim();

    if (commentState.inBlock) {
      // Mid-comment continuation line: only resolve whether the comment
      // closes on this line (and any trailing code's braces) — never test
      // it against the class/function/method regexes below.
      braceDepth += netBraceDelta(line, commentState);
      i++; continue;
    }

    // Collect decorator lines: @Name or @Name(...) or @ns.Name(...)
    // Must be tested before the classRe / namedFuncRe branches so decorators
    // on classes are buffered too (we flush them at the class-match site).
    if (/^@[A-Za-z_][\w.]*/.test(stripped)) {
      pendingDecorators.push(line);
      braceDepth += netBraceDelta(line, commentState);
      i++; continue;
    }

    // Pop class stack entries whose body has fully closed
    while (classStack.length > 0 && braceDepth <= classStack[classStack.length - 1].depth) {
      classStack.pop();
    }
    const currentClass = classStack.length > 0 ? classStack[classStack.length - 1].name : null;

    const classMatch = stripped.match(classRe);
    if (classMatch) {
      // Decorators on the class itself are not prepended to individual method
      // chunks — they describe the class, not any one method — but are still
      // flushed to module_code rather than discarded outright.
      flushPendingDecorators(i);
      classStack.push({ name: classMatch[1], depth: braceDepth });
      braceDepth += netBraceDelta(line, commentState);
      i++; continue;
    }

    const namedFuncMatch = stripped.match(namedFuncRe);
    if (namedFuncMatch) {
      const name = namedFuncMatch[1];
      const blockStart = i - pendingDecorators.length;
      const block = collectBraceBlock(lines, i);
      chunks.push(makeChunk(filePath, currentClass ? 'method' : 'function', currentClass, name,
        [...pendingDecorators, ...block.lines], blockStart));
      pendingDecorators.length = 0;
      for (const bl of block.lines) braceDepth += netBraceDelta(bl, commentState);
      i = block.nextIndex; continue;
    }

    const exportAssignMatch = stripped.match(exportAssignRe);
    if (exportAssignMatch) {
      let hasArrowOrFunc = stripped.includes('=>') || stripped.includes('function');
      // Only look ahead if THIS line's statement is still open — i.e. it has no
      // terminating ';' yet (a complete `module.exports.foo = otherFn;` re-export
      // must never trigger a multi-line lookahead, or it will swallow unrelated
      // code below it the moment an unrelated '=>' appears anywhere downstream).
      const lineIsTerminated = /;\s*(?:\/\/.*)?$/.test(stripped);
      if (!hasArrowOrFunc && !lineIsTerminated) {
        for (let look = i + 1; look < Math.min(i + 8, lines.length); look++) {
          const lt = lines[look].trim();
          if (lt.includes('=>') || lt.includes('function')) { hasArrowOrFunc = true; break; }
          // Stop the lookahead the moment we hit a line that itself completes
          // a statement, starts an unrelated statement, or is a new declaration —
          // continuing past that point is how unrelated code got swallowed.
          if (/;\s*(?:\/\/.*)?$/.test(lt)) break;
          if (/^(?:export|const|let|var|function|class|if|for|while|return|\/\/)/.test(lt)) break;
        }
      }
      if (hasArrowOrFunc) {
        const name = exportAssignMatch[1];
        const blockStart = i - pendingDecorators.length;
        const block = collectBraceBlock(lines, i);
        chunks.push(makeChunk(filePath, currentClass ? 'method' : 'function', currentClass, name,
          [...pendingDecorators, ...block.lines], blockStart));
        pendingDecorators.length = 0;
        for (const bl of block.lines) braceDepth += netBraceDelta(bl, commentState);
        i = block.nextIndex; continue;
      }
    }

    if (currentClass) {
      const mMatch = stripped.match(methodShortRe) || stripped.match(methodArrowRe);
      if (mMatch) {
        const name = mMatch[1];
        if (name && !controlKw.has(name)) {
          const blockStart = i - pendingDecorators.length;
          const block = collectBraceBlock(lines, i);
          chunks.push(makeChunk(filePath, 'method', currentClass, name,
            [...pendingDecorators, ...block.lines], blockStart));
          pendingDecorators.length = 0;
          for (const bl of block.lines) braceDepth += netBraceDelta(bl, commentState);
          i = block.nextIndex; continue;
        }
      }
    }

    // Any line that isn't a decorator and didn't match a declaration resets
    // the buffer — a stray line between @Decorator and the function means the
    // decorator belongs to something else (or is itself a decorated
    // expression). Flushed to module_code first so nothing is silently lost.
    flushPendingDecorators(i);

    if (stripped.length > 0 && !stripped.startsWith('//') && !stripped.startsWith('*') &&
        !stripped.startsWith('/*') && !stripped.match(classRe) && !stripped.match(namedFuncRe) &&
        !/^(?:import |const .+=\s*require\()/.test(stripped) &&
        stripped !== '{' && stripped !== '}') {
      if (moduleLevelStart === -1) moduleLevelStart = i;
      moduleLevel.push(line);
    }
    braceDepth += netBraceDelta(line, commentState);
    i++;
  }

  // A decorator on the very last line(s) of the file with nothing after it
  // would otherwise never hit any of the flush points above.
  flushPendingDecorators(lines.length);

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

export { chunkJS };