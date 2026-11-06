'use strict';

// ─── Deterministic taint engine (replaces the LLM verify + taint passes) ──────
//
// Per chunk (Flow):
//   1. parameters the framework fills from the request become sources;
//   2. statements are walked in order; an assignment whose right-hand side
//      carries taint taints its target (through concatenation, interpolation,
//      calls, destructuring, loops, mutators like list.append());
//   3. sanitizers (see syntax.js) mark a value clean for the classes they
//      neutralise; a reassignment that replaces a value drops its taint.
//
// A value's state is a list of CONTRIBUTORS:
//   { kind:'src',   origin, line, cleared:Set }   attacker input (request data, argv, …)
//   { kind:'param', param,  line, cleared:Set }   depends on a parameter of this function
//
// Across chunks (traceParam): a `param` contributor is resolved by looking at
// every call site of the function and asking what that call passes.

import {
  SOURCES, LIT_SOURCES, OUT_SOURCES, SANITIZER_SUFFIX, SANITIZER_CAST, sanitizerGroups, CALLBACK_MAPPERS, typedAccessorGroups,
  parseParams, goRequestNames, splitTop, isFrameworkParamName,
  LOCAL_ORIGIN, LOCAL_OK_GROUPS, WEB_CONTEXT, NON_WEB_SOURCES, JS_MESSAGE_SOURCE, JS_MESSAGE_CONTEXT,
} from './syntax.js';
import { prepareChunk, accessPaths, resolveFamily } from './context.js';
import { readFileText } from './filetext.js';

const KEYWORD_LINE = /^\s*(?:if|else|elif|elsif|while|until|switch|case|default|return|throw|raise|yield|assert|echo|print|puts|import|from|package|using|include|require|goto|break|continue|do|try|catch|finally|except|with|unless|when|lock|delete|del|pass|fn|def|function|func|fun|class|struct|enum|interface|impl|trait|namespace|module|use|mod|type)\b/;
const NOT_VAR = new Set(['_', 'err', 'error', 'ok', 'e', 'ex', 'exc', 'nil', 'null', 'None', 'true', 'false', 'this', 'self', 'cls', 'let', 'var', 'val', 'const', 'final', 'mut', 'auto', 'static', 'new', 'global', 'local', 'my', 'our', 'public', 'private', 'protected', 'readonly', 'String', 'string', 'int', 'long', 'bool', 'boolean', 'float', 'double', 'char', 'byte', 'Object', 'object', 'dynamic', 'List', 'Map', 'Set', 'Optional', 'Future']);

const MUT_NAME = /^(?:append|push|add|extend|put|write|writeln|insert|concat|set|setdefault|update|unshift|addAll|prepend|merge|appendLine|appendFormat|push_str|offer|putAll|Add|Append|AppendLine|AppendFormat|Write|WriteString|WriteLine|Insert|Concat|assign)$/;
const MUT_CALL = /^(.+)\.(?:append|push|add|extend|put|write|writeln|insert|concat|set|setdefault|update|unshift|addAll|prepend|merge|appendLine|appendFormat|push_str|offer|putAll|Add|Append|AppendLine|AppendFormat|Write|WriteString|WriteLine|Insert|Concat|assign)$/;
const MUTATORS = /\.\s*(?:append|push|add|extend|put|write|writeln|insert|concat|set|setdefault|update|unshift|addAll|prepend|merge|appendLine|appendFormat|append_str|push_str|offer|putAll|Add|Append|AppendLine|AppendFormat|Write|WriteString|WriteLine|Insert|Concat|assign)\s*\(/;

export const GROUP_ALL = 'all';

function indentOf(text, ctx, ll) {
  const ls = ctx.starts[ll.line - 1] ?? 0;
  const raw = ctx.chunk.code.slice(ls, ll.start);
  return raw.replace(/\t/g, '    ').length;
}

// ── helpers over expression text ─────────────────────────────────────────────
// Top-level argument ranges [start, end) of the call whose '(' is at `open`.
function argRanges(text, open) {
  const out = [];
  let depth = 0, s0 = open + 1;
  for (let k = open + 1; k < text.length; k++) {
    const c = text[k];
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') {
      if (depth === 0) { out.push([s0, k]); return out; }
      depth--;
    } else if (c === ',' && depth === 0) { out.push([s0, k]); s0 = k + 1; }
  }
  out.push([s0, text.length]);
  return out;
}

function enclosingCallees(text, pos) {
  // every call whose argument list contains `pos`: callee path, the argument position `pos` sits in, and the
  // ranges of all its arguments (so a sibling argument, e.g. an array_map callback name, can be read)
  const out = [];
  let depth = 0;
  for (let k = pos - 1; k >= 0; k--) {
    const c = text[k];
    if (c === ')') depth++;
    else if (c === '(') {
      if (depth > 0) depth--;
      else {
        const before = text.slice(Math.max(0, k - 80), k);
        const m = /([A-Za-z_$][\w$]*(?:\s*(?:\?\.|\.|::|->)\s*[A-Za-z_$][\w$]*)*)\s*!?\s*$/.exec(before);
        if (m) {
          const ranges = argRanges(text, k);
          let arg = ranges.findIndex(([a, b]) => pos >= a && pos < b);
          if (arg < 0) arg = 0;
          out.push({ callee: m[1].replace(/\s+/g, '').replace(/\?\./g, '.').replace(/->/g, '.'), arg, ranges });
        }
      }
    }
  }
  return out;
}

// `lit` (optional) is the literal view of `text`, used to read callback names such as array_map('absint', …).
function clearedBy(text, start, end, family = null, lit = '') {
  const groups = new Set();
  const litAligned = lit && lit.length === text.length;
  for (const e of enclosingCallees(text, start)) {
    for (const g of sanitizerGroups(e.callee, e.arg, family)) groups.add(g);
    // array_map('sanitize_text_field', $_POST['ids']):  the callback named in the literal cleans every element
    if (litAligned) {
      const mapper = CALLBACK_MAPPERS.find(c => c.langs.includes(family) && c.re.test(e.callee));
      const cbRange = mapper && e.arg !== mapper.cb ? e.ranges[mapper.cb] : null;
      const cbName = cbRange ? /^\s*['"]\\?([A-Za-z_][\w\\]*)['"]\s*$/.exec(lit.slice(cbRange[0], cbRange[1])) : null;
      if (cbName) for (const g of sanitizerGroups(cbName[1].split('\\').pop(), 0, family)) groups.add(g);
    }
  }
  if (SANITIZER_CAST.test(text.slice(Math.max(0, start - 40), start))) groups.add(GROUP_ALL);
  // new URL(rel, location.href): the second argument is only the BASE used to resolve `rel`; a base can
  // supply the origin only when `rel` is relative, and then it is the page's own origin.
  if (/\bnew\s+URL\s*\([^,()]*,\s*$/.test(text.slice(Math.max(0, start - 160), start))) groups.add(GROUP_ALL);
  // methods applied after the value:  x.to_i   x.length   req.query.id.isdigit()
  const tail = text.slice(end, end + 240);
  let m, rest = tail, guard = 0;
  while (guard++ < 8 && (m = /^\s*(?:\?\.|\.|->|::)\s*[A-Za-z_$][\w$]*(?:\s*\([^()]*\))?/.exec(rest))) {
    for (const s of SANITIZER_SUFFIX) if (s.re.test(rest)) s.groups.forEach(g => groups.add(g));
    rest = rest.slice(m[0].length);
  }
  for (const s of SANITIZER_SUFFIX) if (s.re.test(rest)) s.groups.forEach(g => groups.add(g));
  return groups;
}

// ── parts of an expression that cannot contribute to its VALUE ─────────────────────────────────────────────
//   cond ? a : b     `cond` only chooses a branch; only `a` and `b` can end up in the result
//   a === b          a comparison yields a boolean, whatever its operands were
// Masking them (offset-preserving) stops `$class = ($name === $_REQUEST['s']) ? ' class="x"' : '';` from being
// treated as request data.
const TERNARY_FAMILIES = new Set(['php', 'js', 'java', 'csharp', 'c', 'cpp', 'dart', 'swift', 'ruby']);
const VALUE_LOGIC_FAMILIES = new Set(['js', 'python', 'ruby']);   // `a && b` / `a || b` evaluate to an operand there, to a boolean elsewhere

function matchingColon(text, from) {
  let depth = 0, nested = 0;
  for (let j = from; j < text.length; j++) {
    const c = text[j];
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') { if (depth === 0) return -1; depth--; }
    else if (depth === 0) {
      if (c === '?') {
        const nx = text[j + 1] || '', pv = text[j - 1] || '';
        if (nx === '?' || pv === '?' || nx === ':' || nx === '>' || nx === '[' || nx === '.' || (nx === '-' && text[j + 2] === '>')) continue;
        nested++;
      } else if (c === ':') {
        if (text[j + 1] === ':') { j++; continue; }
        if (text[j - 1] === ':' || text[j - 1] === '?') continue;
        if (nested === 0) return j;
        nested--;
      } else if (c === ',' || c === ';') return -1;
    }
  }
  return -1;
}

function nonFlowingRanges(text, family) {
  const ranges = [];
  const ternary = TERNARY_FAMILIES.has(family) && text.includes('?');
  const pyIf = family === 'python' && /\bif\b/.test(text) && /\belse\b/.test(text);
  const cmp = /[=!<>]=|<>|\binstanceof\b/.test(text);
  if (!ternary && !pyIf && !cmp) return ranges;

  // 1. conditions of `cond ? a : b` (and Python's `a if cond else b`)
  if (ternary) {
    const segStart = [0], colonAt = new Set();
    for (let i = 0; i < text.length; i++) {
      const c = text[i], d = segStart.length - 1;
      if (c === '(' || c === '[' || c === '{') segStart.push(i + 1);
      else if (c === ')' || c === ']' || c === '}') { if (d > 0) segStart.pop(); }
      else if (c === ',' || c === ';') segStart[d] = i + 1;
      else if (c === ':' && colonAt.has(i)) segStart[d] = i + 1;
      else if (c === '?') {
        const nx = text[i + 1] || '', pv = text[i - 1] || '';
        if (nx === '?' || pv === '?' || nx === ':' || nx === '>' || nx === '[' || (nx === '.' && !/\d/.test(text[i + 2] || '')) || (nx === '-' && text[i + 2] === '>')) continue;
        const colon = matchingColon(text, i + 1);
        if (colon < 0) continue;
        if (i > segStart[d]) ranges.push([segStart[d], i]);
        colonAt.add(colon);
        segStart[d] = i + 1;
      }
    }
  }
  if (pyIf) {
    const depth = new Array(text.length);
    let d = 0;
    for (let i = 0; i < text.length; i++) { const c = text[i]; if (c === ')' || c === ']' || c === '}') d--; depth[i] = d; if (c === '(' || c === '[' || c === '{') d++; }
    const re = /\bif\b/g; let m;
    while ((m = re.exec(text)) !== null) {
      const dk = depth[m.index], er = /\belse\b/g; er.lastIndex = m.index + 2; let e;
      while ((e = er.exec(text)) !== null) {
        if (depth[e.index] < dk) break;
        if (depth[e.index] === dk) { ranges.push([m.index + 2, e.index]); break; }
      }
    }
  }

  // 2. boolean-valued sub-expressions: comparisons (and, where `&&`/`||` yield booleans, logical combinations of them)
  if (cmp) {
    let t2 = text;
    for (const [a, b] of ranges) t2 = t2.slice(0, a) + ' '.repeat(b - a) + t2.slice(b);
    const valueLogic = VALUE_LOGIC_FAMILIES.has(family);
    const fresh = (s0) => ({ s: s0, cmp: false, logic: false, other: false });
    const stack = [fresh(0)];
    const finish = (sg, e) => {
      if (sg.other || e <= sg.s) return;
      if (sg.cmp || (sg.logic && !valueLogic)) { if (!(sg.logic && valueLogic)) ranges.push([sg.s, e]); }
    };
    for (let i = 0; i < t2.length; i++) {
      const c = t2[i], sg = stack[stack.length - 1];
      if (c === '(' || c === '[' || c === '{') stack.push(fresh(i + 1));
      else if (c === ')' || c === ']' || c === '}') { if (stack.length > 1) finish(stack.pop(), i); }
      else if (c === ',' || c === ';') { finish(sg, i); Object.assign(sg, fresh(i + 1)); }
      else {
        const o3 = t2.substr(i, 3);
        if (o3 === '===' || o3 === '!==' || o3 === '<=>') { sg.cmp = true; i += 2; }
        else if (/^(?:==|!=|<=|>=|<>)/.test(o3)) { sg.cmp = true; i += 1; }
        else if (o3.startsWith('=>')) { sg.other = true; i += 1; }
        else if (c === '=' && !/[=!<>+\-*/.%&|^?]/.test(t2[i - 1] || '')) sg.other = true;      // assignment inside the segment
        else if (o3.startsWith('&&') || o3.startsWith('||')) { sg.logic = true; i += 1; }
        else if (o3.startsWith('??')) { sg.other = true; i += 1; }
        else if (c === '?' ) sg.other = true;
        else if (/[A-Za-z_]/.test(c) && !/[\w$]/.test(t2[i - 1] || '')) {
          const w = /^(?:instanceof|and|or|xor)\b/.exec(t2.slice(i, i + 11));
          if (w) { if (w[0] === 'instanceof') sg.cmp = true; else sg.logic = true; i += w[0].length - 1; }
        }
      }
    }
    while (stack.length) finish(stack.pop(), t2.length);
  }
  return ranges;
}

function maskRanges(str, ranges) {
  if (!ranges.length) return str;
  const chars = str.split('');
  for (const [a, b] of ranges) for (let i = a; i < b && i < chars.length; i++) chars[i] = ' ';
  return chars.join('');
}

const union = (a, b) => { const o = new Set(a); for (const x of b) o.add(x); return o; };

// "/assets/" + id   "/login?next=" + x   fmt.Sprintf("/r/%s", id): the literal fixes the origin, so the
// value can only change the path/query. Needs a non-slash after the leading '/', otherwise "/" + x = "//host".
const REDIR_FIXED_ORIGIN = /^\s*(?:fmt\.Sprintf\s*\(\s*|f|b|u)?[`"']\/[^\/\\"'`%{$]/;
// `to += "?next=" + x`: appended query/fragment text cannot change the origin of what `to` already holds
// (whatever `to` held before keeps its own taint).
const REDIR_QUERY_SUFFIX = /^\s*[`"'][?&#]/;
const markRedirectSafe = (contribs) => contribs.map(c => ({ ...c, cleared: union(c.cleared, new Set(['redirect'])) }));
const intersects = (set, groups) => set.has(GROUP_ALL) || groups.some(g => set.has(g));

/** Can this contributor reach a sink of `group`?  Cleaned values and (for most classes) local-only sources cannot. */
export function isUsable(c, group) {
  if (isCleared(c, group)) return false;
  if (c.local && !LOCAL_OK_GROUPS.has(group)) return false;
  return true;
}

// Groups whose danger is the MAGNITUDE of a number, so a numeric conversion does not clean them.
const MAGNITUDE_GROUPS = new Set(['mem', 'int', 'alloc']);
export function isCleared(contrib, group) {
  if (contrib.cleared.has(GROUP_ALL)) return true;
  if (group && contrib.cleared.has(group)) return true;
  return contrib.cleared.has('num') && !MAGNITUDE_GROUPS.has(group);
}

// ── Flow (one chunk) ─────────────────────────────────────────────────────────
class Flow {
  constructor(engine, chunk) {
    this.engine = engine; this.chunk = chunk;
    this.family = resolveFamily(chunk);
    this.ctx = prepareChunk(chunk, this.family);
    const { params, routeHandler } = parseParams(chunk, this.family);
    this.paramList = params; this.routeHandler = routeHandler;
    this.params = new Map();
    for (const p of params) if (!this.params.has(p.name)) this.params.set(p.name, p);
    this.vars = new Map();      // path → { contribs, indent }
    this.returned = null;
    this.sourceRe = this._sourceRegex();
    this._seed();
    this._walk();
  }

  _sourceRegex() {
    let base = SOURCES[this.family];
    const gate = WEB_CONTEXT[this.family];
    if (gate) {
      const text = readFileText(this.chunk.file, this.chunk.code);
      this.webContext = gate.test(text) || gate.test(this.chunk.code);
      if (!this.webContext) base = NON_WEB_SOURCES[this.family] || null;
    } else this.webContext = true;
    if (this.family === 'js' && base && JS_MESSAGE_CONTEXT.test(readFileText(this.chunk.file, this.chunk.code))) {
      base = new RegExp(base.source + '|' + JS_MESSAGE_SOURCE.source, 'g');
    }
    if (this.family !== 'go' || !base || !this.webContext) return base || null;
    const sig = this.chunk.code.slice(0, 400);
    const names = [...goRequestNames(sig)].join('|');
    return new RegExp(
      base.source + '|' +
      String.raw`\b(?:${names})\s*\.\s*(?:Query|QueryParam|QueryParams|QueryArray|QueryMap|DefaultQuery|Param|Params|ParamValues|PostForm|DefaultPostForm|PostFormArray|FormValue|FormParams|FormFile|GetHeader|GetRawData|Cookie|Cookies|Body|BodyParser|Bind|BindJSON|BindQuery|ShouldBind|ShouldBindJSON|ShouldBindQuery|ShouldBindUri|MultipartForm|QueryString|PathParam|Hostname|OriginalURL|FormValue|Form|URL|Header|Host|RequestURI|Referer|UserAgent)\b`, 'g');
  }

  _seed() {
    for (const p of this.paramList) {
      const cleared = new Set(p.cleared);
      if (p.source) this.vars.set(p.name, { contribs: [{ kind: 'src', origin: `request parameter "${p.name}"`, line: 1, cleared }], indent: -1 });
    }
    // Rust/Go/etc. typed extractors are handled by parseParams; Java @RequestBody beans etc. likewise.
  }

  // ── expression state ───────────────────────────────────────────────────────
  state(text, lit = '', line = 1) {
    const dead = nonFlowingRanges(text, this.family);
    if (dead.length) {
      if (lit && lit.length === text.length) lit = maskRanges(lit, dead);
      text = maskRanges(text, dead);
    }
    const out = [];
    const seen = new Set();
    const add = (c) => { const key = `${c.kind}|${c.origin || c.param}|${[...c.cleared].sort().join(',')}`; if (!seen.has(key)) { seen.add(key); out.push(c); } };

    if (this.sourceRe) {
      this.sourceRe.lastIndex = 0;
      let m;
      while ((m = this.sourceRe.exec(text)) !== null) {
        if (m[0] === '') { this.sourceRe.lastIndex++; continue; }
        const origin = m[0].replace(/\s+/g, '');
        add({ kind: 'src', origin, line, local: LOCAL_ORIGIN.test(origin), cleared: union(clearedBy(text, m.index, m.index + m[0].length, this.family, lit), typedAccessorGroups(origin, this.family)) });
      }
    }
    const lit2 = LIT_SOURCES[this.family];
    if (lit2 && lit) {
      lit2.lastIndex = 0;
      let m;
      while ((m = lit2.exec(lit)) !== null) add({ kind: 'src', origin: m[0].replace(/\s+/g, ''), line, cleared: clearedBy(text, m.index, m.index + m[0].length, this.family, lit) });
    }

    for (const p of accessPaths(text)) {
      const segs = p.path.split('.');
      let hit = null, used = 0;
      for (let n = segs.length; n >= 1; n--) {
        const key = segs.slice(0, n).join('.');
        if (this.vars.has(key)) { hit = this.vars.get(key); used = n; break; }
      }
      if (hit) {
        const after = clearedBy(text, p.start, p.ends[used - 1] ?? p.end, this.family, lit);
        for (const c of hit.contribs) add({ ...c, cleared: union(c.cleared, after) });
        continue;
      }
      if (this.params.has(p.base) && !this.vars.has(p.base) && !isFrameworkParamName(p.base)) {
        const pr = this.params.get(p.base);
        add({ kind: 'param', param: p.base, index: pr.index, line, cleared: union(new Set(pr.cleared), clearedBy(text, p.start, p.ends[0], this.family, lit)) });
        continue;
      }
      if (p.call) {
        const callee = this.engine.returnTaint(p.path.split('.').pop(), this.chunk);
        if (callee) add({ kind: 'src', origin: `${p.path}() return value (${callee})`, line, cleared: clearedBy(text, p.start, p.end, this.family, lit) });
      }
    }
    return lit && REDIR_FIXED_ORIGIN.test(lit) ? markRedirectSafe(out) : out;
  }

  // ── walking ────────────────────────────────────────────────────────────────
  _assign(names, contribs, indent, compound) {
    for (const name of names) {
      const prev = this.vars.get(name);
      if (contribs.length === 0 || contribs.every(c => c.cleared.has(GROUP_ALL))) {
        // replaced by something clean: drop taint, but only for an unconditional (same/outer level) reassignment
        if (prev && !compound && indent <= prev.indent) this.vars.delete(name);
        else if (prev && contribs.length) this.vars.set(name, { contribs: [...prev.contribs, ...contribs], indent: prev.indent });
        continue;
      }
      if (prev && (compound || indent > prev.indent)) this.vars.set(name, { contribs: [...prev.contribs, ...contribs], indent: Math.min(prev.indent, indent) });
      else if (prev && indent <= prev.indent) this.vars.set(name, { contribs, indent });
      else this.vars.set(name, { contribs, indent });
    }
  }

  _walk() {
    const { ctx } = this;
    for (let pass = 0; pass < 2; pass++) {
      for (const ll of ctx.logical) {
        const text = ll.text, lit = ll.lit;
        const indent = indentOf(text, ctx, ll);

        // return statements (for return-value taint)
        const ret = /^\s*return\b\s*([\s\S]*)$/.exec(text);
        if (ret) {
          const st = this.state(ret[1], lit.slice(lit.length - ret[1].length), ll.line);
          if (st.length) this.returned = (this.returned || []).concat(st);
          continue;
        }

        // for-loops / iteration:  for x in SRC,  for (const x of SRC),  foreach (var x in SRC),  for _, x := range SRC
        const loop = this._loop(text);
        if (loop) {
          const st = this.state(loop.rhs, '', ll.line);
          if (st.length) this._assign(loop.names, st, indent + 1, true);
        }
        // callbacks: SRC.forEach(x => …)   SRC.each { |x| … }   SRC.map(lambda x: …)
        const cb = /([\s\S]+?)\.\s*(?:forEach|map|filter|flatMap|some|every|reduce|each|each_with_index|select|collect|flat_map|find|sort_by|then|ifPresent|forEachIndexed|let|also|apply|run)\s*(?:\(\s*(?:async\s*)?(?:\(([^)]*)\)|([A-Za-z_$][\w$]*))\s*=>|\{\s*\|([^|]+)\||do\s*\|([^|]+)\||\{\s*(?:\(([^)]*)\)|([A-Za-z_]\w*))\s*->)/.exec(text);
        if (cb) {
          const st = this.state(cb[1], '', ll.line);
          const nameStr = cb[2] ?? cb[3] ?? cb[4] ?? cb[5] ?? cb[6] ?? cb[7] ?? '';
          if (st.length && nameStr) this._assign((nameStr.match(/[A-Za-z_$][\w$]*/g) || []).filter(n => !NOT_VAR.has(n)), st, indent + 1, true);
        }

        // assignment
        const asg = this._parseAssignment(text);
        if (asg && !KEYWORD_LINE.test(text)) {
          // rhs is trimmed, so trim the literal view the same way before aligning from the end (CRLF files end each
          // logical line with '\r', which shifted the slice by one and defeated every literal-prefix check)
          const litT = lit.replace(/\s+$/, '');
          const rhsLit = litT.slice(litT.length - asg.rhs.length);
          let st = this.state(asg.rhs, rhsLit, ll.line);
          if (asg.compound && REDIR_QUERY_SUFFIX.test(rhsLit)) st = markRedirectSafe(st);
          this._assign(asg.lhs, st, indent, asg.compound);
        }

        // mutators:  buf.append(tainted)
        if (MUTATORS.test(text)) {
          for (const call of ctx.calls) {
            if (call.start < ll.start || call.start >= ll.end) continue;
            // `sb.append(a).append(b)`: the chained call has no receiver of its own, the receiver is the head of the chain
            const target = !call.callee.includes('.') && call.chain && call.chain.includes('().') && MUT_NAME.test(call.callee) ? call.chain.split('().')[0] : call.callee;
            const m = MUT_CALL.exec(target);
            if (!m) continue;
            const recv = m[1].replace(/\(\)/g, '');
            const st = this.state(call.args.map(a => a.text).join(', '), call.args.map(a => a.lit).join(', '), ll.line);
            if (st.length) this._assign([recv], st, indent, true);
          }
        }

        // C copy functions:  strcpy(dst, src)  sprintf(dst, fmt, …)  memcpy(dst, src, n)  →  dst carries what the sources carry
        if (this.family === 'c') {
          for (const call of ctx.calls) {
            if (call.start < ll.start || call.start >= ll.end) continue;
            if (!/^(?:strcpy|strncpy|strcat|strncat|stpcpy|sprintf|snprintf|vsprintf|vsnprintf|memcpy|memmove|wcscpy|wcscat|std::copy|strlcpy|strlcat|g_strlcpy|bcopy)$/.test(call.callee)) continue;
            const dstArg = call.callee === 'bcopy' ? call.args[1] : call.args[0]; if (!dstArg) continue;
            const srcs = call.args.filter((a) => a !== dstArg);
            const st = this.state(srcs.map(a => a.text).join(', '), srcs.map(a => a.lit).join(', '), ll.line);
            const dp = accessPaths(dstArg.text.replace(/^[&*(\s]+|[)\s]+$/g, '').replace(/\[.*$/, ''))[0];
            if (st.length && dp) this._assign([dp.path], st, indent, true);
          }
        }

        // C-style out-parameters:  fgets(buf, …)  scanf("%s", buf)
        const outs = OUT_SOURCES[this.family];
        if (outs) {
          for (const call of ctx.calls) {
            if (call.start < ll.start || call.start >= ll.end) continue;
            for (const o of outs) {
              if (!o.callee.test(call.callee)) continue;
              const idx = o.args === 'rest' ? call.args.map((_, i) => i).slice(1)
                : (o.pick && o.pick[call.callee]) || o.args;
              for (const i of idx) {
                const a = call.args[i]; if (!a) continue;
                const nm = a.text.replace(/^[&*(\s]+|[)\s]+$/g, '').replace(/\[.*$/, '');
                const p = accessPaths(nm)[0];
                if (p) this.vars.set(p.path, { contribs: [{ kind: 'src', origin: `${call.callee}()`, line: ll.line, local: LOCAL_ORIGIN.test(call.callee), cleared: new Set() }], indent });
              }
            }
          }
        }
      }
    }
  }

  _loop(text) {
    let m;
    if ((m = /^\s*for\s+(?:await\s+)?\(?\s*(?:(?:const|let|var|val|final|auto|mut)\s+)?(?:[\w<>?\[\]]+\s+)?([A-Za-z_$][\w$]*(?:\s*,\s*[A-Za-z_$][\w$]*)*)\s+(?:in|of)\s+([\s\S]+?)\)?\s*(?:\{|:|do)?\s*$/.exec(text)))
      return { names: m[1].split(/\s*,\s*/).filter(n => !NOT_VAR.has(n)), rhs: m[2] };
    if ((m = /^\s*(?:for)?each\s*\(\s*(?:[\w<>?\[\]]+\s+)?(\w+)\s+in\s+([\s\S]+?)\)/.exec(text)))
      return { names: [m[1]], rhs: m[2] };
    if ((m = /^\s*for\s*\(\s*(?:final\s+)?(?:[\w<>?\[\],.]+\s+)(\w+)\s*:\s*([\s\S]+?)\)\s*\{?\s*$/.exec(text)))
      return { names: [m[1]], rhs: m[2] };
    if ((m = /^\s*for\s+(?:[A-Za-z_]\w*\s*,\s*)?([A-Za-z_]\w*)\s*:?=\s*range\s+([\s\S]+?)\s*\{?\s*$/.exec(text)))
      return { names: [m[1]], rhs: m[2] };
    return null;
  }

  _parseAssignment(text) {
    let depth = 0, idx = -1, op = '=';
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (c === '(' || c === '[' || c === '{') depth++;
      else if (c === ')' || c === ']' || c === '}') depth--;
      else if (depth === 0 && c === '=') {
        const prev = text[i - 1], next = text[i + 1];
        if (next === '=' || next === '>' || next === '~') { i++; continue; }
        if (prev === '!') continue;
        if ((prev === '<' || prev === '>') && text[i - 2] !== prev) continue;       // <=  >=  (but <<=, >>= are assignments)
        idx = i; break;
      }
    }
    if (idx < 0) return null;
    let lhsEnd = idx;
    let compound = false;
    const pre = text[idx - 1];
    if (pre === ':' ) { lhsEnd = idx - 1; if (text[idx - 2] === ':') return null; }
    else if (pre && /[+\-*/%|&^.?<>]/.test(pre)) { compound = true; lhsEnd = idx - 1; while (lhsEnd > 0 && /[+\-*/%|&^.?<>]/.test(text[lhsEnd - 1])) lhsEnd--; }
    let lhs = text.slice(0, lhsEnd).trim();
    const rhs = text.slice(idx + 1).trim();
    if (!lhs || !rhs) return null;
    if (/^(?:if|while|for|switch|else)\b/.test(lhs)) return null;
    if (/^(?:async\s+)?function\b|^lambda\b|^(?:async\s*)?(?:\([^)]*\)|[\w$]+)\s*=>/.test(rhs)) return null;      // a function value, not data
    lhs = lhs.replace(/^(?:export\s+|public\s+|private\s+|protected\s+|internal\s+|static\s+|final\s+|readonly\s+|const\s+|let\s+|var\s+|val\s+|auto\s+|my\s+|our\s+|local\s+|global\s+|new\s+|mut\s+)+/g, '');
    let names = [];
    if (/^[{[(]/.test(lhs) || lhs.includes(',')) {
      const body = lhs.replace(/^[{[(]|[)}\]]$/g, '');
      for (const part of splitTop(body)) {
        const t = part.trim().replace(/^\.\.\./, '');
        const renamed = /:\s*([A-Za-z_$][\w$]*)\s*(?:=.*)?$/.exec(t);        // { a: b }
        const id = renamed ? renamed[1] : (/^[A-Za-z_$][\w$]*/.exec(t) || [])[0];
        if (id && !NOT_VAR.has(id)) names.push(id);
      }
      if (!names.length) { names = (lhs.match(/[A-Za-z_$][\w$]*/g) || []).filter(n => !NOT_VAR.has(n)); }
    } else {
      let l = lhs;
      if (/[^:]:[^:]/.test(l) && !/\?[^:]*:/.test(l)) l = l.slice(0, l.search(/[^:]:[^:]/) + 1);   // `x: T`
      const ps = accessPaths(l.replace(/<[^<>]*>/g, ''));
      const last = ps[ps.length - 1];
      if (last && !NOT_VAR.has(last.path)) names = [last.path];
    }
    if (!names.length) return null;
    return { lhs: names, lhsText: lhs, rhs, compound, op };
  }

  /** Contributors of a call site's argument expression text. */
  stateOfArg(arg, line) { return this.state(arg.text, arg.lit, line); }
}

// ── Engine across all chunks ─────────────────────────────────────────────────
export class FlowEngine {
  constructor(chunks) {
    this.chunks = chunks;
    this.byName = new Map();
    for (const c of chunks) {
      if (!c.name) continue;
      const key = String(c.name).replace(/^.*[.:#]/, '');
      if (!this.byName.has(key)) this.byName.set(key, []);
      this.byName.get(key).push(c);
    }
    this.flows = new Map();
    this._rt = new Map();
    this._rtDepth = 0;
  }

  /** name → every call site of that name across the project (built once, on first trace). */
  _siteIndex() {
    if (this._si) return this._si;
    const idx = new Map();
    for (const c of this.chunks) {
      if (c.type === 'imports') continue;
      let fl; try { fl = this.flow(c); } catch { continue; }
      for (const call of fl.ctx.calls) {
        const nm = call.name.replace(/!$/, '');
        let arr = idx.get(nm); if (!arr) { arr = []; idx.set(nm, arr); }
        arr.push({ chunk: c, flow: fl, call });
      }
    }
    return (this._si = idx);
  }

  flow(chunk) {
    let f = this.flows.get(chunk.id);
    if (!f) { f = new Flow(this, chunk); this.flows.set(chunk.id, f); }
    return f;
  }

  /** Does the function called `name` return attacker input? Returns a short reason or null. */
  returnTaint(name, from) {
    const cands = (this.byName.get(name) || []).filter(c => c.id !== from.id);
    if (cands.length === 0 || cands.length > 3) return null;
    const callee = cands.find(c => c.file === from.file) || cands[0];
    if (this._rt.has(callee.id)) return this._rt.get(callee.id);
    if (this._rtDepth > 3) return null;
    this._rt.set(callee.id, null);                   // recursion guard
    this._rtDepth++;
    let result = null;
    try {
      const f = this.flow(callee);
      const src = (f.returned || []).find(c => c.kind === 'src' && !c.cleared.has(GROUP_ALL));
      if (src) result = `${callee.file.split(/[\\/]/).pop()}:${callee.startLine} returns ${src.origin}`;
    } catch { /* ignore */ }
    this._rtDepth--;
    this._rt.set(callee.id, result);
    return result;
  }

  /**
   * Resolve a `param` contributor: what do the callers pass for parameter `index`
   * of `chunk`?  Returns
   *   { verdict: 'tainted', path:[…], origin }  an attacker-controlled value reaches it
   *   { verdict: 'clean',  callers:n }          callers exist, none passes attacker input
   *   { verdict: 'unknown', reason }            cannot be decided (no/generic callers, depth)
   */
  traceParam(chunk, index, group, depth = 0, seen = new Set(), via = []) {
    if (depth === 0) { this._budget = 600; }                     // site evaluations allowed per top-level trace
    const memoKey = `${chunk.id}|${index}|${group}`;
    this._memo ||= new Map();
    if (this._memo.has(memoKey)) {
      const m = this._memo.get(memoKey);
      if (m.verdict !== 'tainted' || depth === 0) return m.verdict === 'tainted' ? { ...m, path: [...via, ...m.path] } : m;
      return { ...m, path: [...via, ...m.path] };
    }
    if (this._budget <= 0) return { verdict: 'unknown', reason: 'depth_limit' };
    const res = this._traceParam(chunk, index, group, depth, seen, via);
    if (res.verdict !== 'unknown' || res.reason === 'no_callers' || res.reason === 'generic_function_name') {
      // memoise with the path relative to this function (callers' own prefix removed)
      this._memo.set(memoKey, res.verdict === 'tainted' ? { ...res, path: res.path.slice(via.length) } : res);
    }
    return res;
  }

  _traceParam(chunk, index, group, depth, seen, via) {
    const name = chunk.name ? String(chunk.name).replace(/^.*[.:#]/, '') : null;
    if (!name) return { verdict: 'unknown', reason: 'anonymous_function' };
    if (depth > 6) return { verdict: 'unknown', reason: 'depth_limit' };
    if (name.length <= 2) return { verdict: 'unknown', reason: 'generic_function_name' };
    const GENERIC = new Set(['get', 'set', 'run', 'next', 'done', 'init', 'new', 'create', 'update', 'delete', 'load', 'save', 'read', 'write', 'open', 'close', 'start', 'stop', 'send', 'call', 'exec', 'main', 'test', 'check', 'parse', 'format', 'handle', 'process', 'render', 'build', 'push', 'pop', 'map', 'filter', 'find', 'log', 'emit', 'on', 'off']);
    const stem = String(chunk.file || '').split(/[\\/]/).pop().replace(/\.[^.]+$/, '');
    const uniqueName = (this.byName.get(name) || []).length === 1;

    const sites = [];
    const myFamily = resolveFamily(chunk);
    for (const site of (this._siteIndex().get(name) || [])) {
      const c = site.chunk;
      if (c.id === chunk.id || seen.has(c.id) || site.flow.family !== myFamily) continue;
      const parts = site.call.callee.split(/[.:]+/).filter(Boolean);
      const recv = parts.length > 1 ? parts[parts.length - 2] : null;
      if (recv === null) { /* a plain call of that name */ }
      else if (chunk.class) { /* method: any receiver */ }
      else if (/^(?:self|this|cls|\$this)$/.test(recv) && c.file === chunk.file) { /* same-module call */ }
      else if (recv === stem || recv.toLowerCase() === stem.toLowerCase()) { /* module.name() */ }
      else if (uniqueName && !GENERIC.has(name) && name.length >= 5) { /* unambiguous project-wide */ }
      else continue;
      sites.push({ chunk: c, flow: site.flow, call: site.call });
    }
    if (sites.length === 0) return { verdict: 'unknown', reason: 'no_callers' };
    if (sites.length > 40) return { verdict: 'unknown', reason: 'too_many_callers' };

    let unresolved = 0;
    for (const s of sites) {
      if (--this._budget <= 0) return { verdict: 'unknown', reason: 'depth_limit' };
      const arg = s.call.args[index];
      if (!arg) { unresolved++; continue; }
      const st = s.flow.stateOfArg(arg, s.call.line).filter(c => isUsable(c, group));
      const src = st.find(c => c.kind === 'src');
      const where = `${s.chunk.file.split(/[\\/]/).pop()}:${s.chunk.startLine + s.call.line - 1}`;
      if (src) return { verdict: 'tainted', path: [...via, `${s.chunk.name || 'module'}() at ${where}`], origin: src.origin };
      const pr = st.find(c => c.kind === 'param');
      if (pr) {
        const nseen = new Set(seen); nseen.add(chunk.id);
        const r = this.traceParam(s.chunk, pr.index, group, depth + 1, nseen, [...via, `${s.chunk.name || 'module'}() at ${where}`]);
        if (r.verdict === 'tainted') return r;
        if (r.verdict === 'unknown') unresolved++;
      }
    }
    if (unresolved) return { verdict: 'unknown', reason: 'caller_depends_on_unresolved_parameter' };
    return { verdict: 'clean', callers: sites.length };
  }
}

export { Flow };
