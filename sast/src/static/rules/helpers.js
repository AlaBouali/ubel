'use strict';

import { readFileText } from '../filetext.js';

// Rule constructors shared by the rule tables.
//
//   call(...)     a call expression: `callee` (or `chain`) regex, which argument(s)
//                 to follow, and what must be true of them (`need`):
//                   'taint'   attacker input / a parameter reaches it   (default)
//                   'dynamic' the argument is not a pure literal
//                   'always'  the call itself is the finding
//   assign(...)   an assignment `LHS = RHS` whose LHS matches `lhs`
//   pattern(...)  a regex over the literal (or code) view of the chunk
//   custom(...)   arbitrary logic: run(flow, emit)

export const WEB = ['js', 'python', 'php', 'ruby', 'go', 'rust', 'java', 'kotlin', 'csharp'];
export const MOBILE = ['dart', 'swift'];
export const ALLL = [...WEB, ...MOBILE, 'c'];
export const JVM = ['java', 'kotlin'];

export const call    = (d) => ({ kind: 'call',    conf: 'medium', need: 'taint', ...d });
export const assign  = (d) => ({ kind: 'assign',  conf: 'medium', need: 'taint', ...d });
export const pattern = (d) => ({ kind: 'pattern', conf: 'medium', view: 'literal', ...d });
export const custom  = (d) => ({ kind: 'custom',  conf: 'medium', ...d });

// Is `re` present in the whole chunk / in the whole file?
export const inChunk = (flow, re) => re.test(flow.ctx.literal);
export const fileText = (flow) => readFileText(flow.chunk.file, flow.ctx.literal);
export const inFile = (flow, re) => re.test(fileText(flow));
