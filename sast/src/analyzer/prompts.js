'use strict';

import { buildVulnCatalog, filterVulnClassesForLanguage } from './vulnCatalog.js';
import { KIND_FENCE_LANG } from '../chunker/configDetect.js';

// A scan prompt is built in two parts so it can be cached and packed:
//   prefix — everything that is identical for every chunk of one language:
//            role line, vulnerability catalog, analysis rules, output schema.
//   body   — the code (one chunk, or several packed into one call).
// The prefix always comes first and the code last, which is what makes the
// request prefix-cacheable (explicitly on Anthropic via cache_control, and
// automatically on providers that cache identical prompt prefixes).

const RULE_LINE = '════════════════════════════════════════════════════════';

// Renders the code section. `multi` = several chunks in one call: each gets a
// short id (C1, C2, …) the model cites back in `chunk_id` so findings can be
// attributed to the right chunk.
function renderChunkBlocks(chunks, multi) {
  if (!multi) {
    const chunk = chunks[0];
    return `Language  : ${chunk.language}
Type      : ${chunk.type}

\`\`\`${KIND_FENCE_LANG[chunk.type] || chunk.language.toLowerCase()}
${chunk.code}
\`\`\``;
  }
  return chunks.map((chunk, i) =>
    `=== CHUNK C${i + 1} ===\nName: ${chunk.name || '(anonymous)'}   Type: ${chunk.type}   Language: ${chunk.language}\n\n` +
    `\`\`\`${KIND_FENCE_LANG[chunk.type] || chunk.language.toLowerCase()}\n${chunk.code}\n\`\`\``
  ).join('\n\n');
}

/**
 * Builds { prefix, body } for the scan pass.
 *   chunks — one or more chunks of the SAME language (the catalog is filtered
 *            by language, so a mixed-language call would be wrong).
 * Override the whole thing via opts.buildPrompt (single chunk → string); a
 * custom builder is never given packed calls — packing is skipped for it.
 */
function buildScanPromptParts(chunks, vulnClasses, includeSignals = false) {
  const multi = chunks.length > 1;
  const language = chunks[0].language;
  // A pack may hold several languages that share one catalog (JS+TS, C+C++, …).
  const languages = [...new Set(chunks.map(c => c.language))].join(' / ');
  const applicableClasses = filterVulnClassesForLanguage(vulnClasses, language);
  const catalog = buildVulnCatalog(applicableClasses, includeSignals);

  const scopeLine = multi
    ? `Analyze each ${languages} code chunk below (C1…C${chunks.length}) for security vulnerabilities. Chunks are independent: judge each one only on its own code.`
    : `Analyze the following ${language} code chunk for security vulnerabilities.`;

  const multiRules = multi
    ? `\n10. Every finding MUST carry "chunk_id": the id (C1, C2, …) of the chunk its code_snippet was copied from.\n11. If a chunk has no vulnerabilities, simply omit it — do not emit an entry for it.`
    : '';

  const chunkIdField = multi
    ? `\n      "chunk_id": "<C1, C2, … — the chunk the finding is in>",`
    : '';

  const prefix = `You are a senior application security engineer performing a SAST review.
${scopeLine}

${RULE_LINE}
VULNERABILITY CATALOG  (report ONLY classes listed here)
${RULE_LINE}
${catalog}

${RULE_LINE}
ANALYSIS RULES
${RULE_LINE}
1. Report ONLY concrete issues whose evidence is present in the code shown.
   Do NOT speculate about code you cannot see.
2. For classes marked "Scope: attacker-controlled input required", the taint source
   (user input, request param, file upload, env var, network socket, CLI arg) must be
   visible in the chunk or clearly implied by the function signature / parameter names.
3. For classes NOT requiring a taint source (hardcoded secrets, crypto weakness,
   missing auth check, etc.), report the issue based solely on the code pattern.
4. Each finding must quote the exact vulnerable line or expression in code_snippet.
5. Confidence rules:
   - "high"   — sink and source both visible, no apparent sanitisation
   - "medium" — sink visible, source inferred from context / parameter name
   - "low"    — pattern matches but context is ambiguous
6. The fix must name a specific API, function, or technique — never generic advice
   like "validate input" or "use a safe API".
7. Severity must be assigned as follows:
   - "critical" — direct, unauthenticated RCE, auth bypass, or full data exfiltration with high confidence
   - "high"     — exploitable injection (SQL, command, SSRF, XXE, path traversal) or hardcoded secret reachable from outside
   - "medium"   — exploitable but requires authentication, or significant data exposure / privilege escalation
   - "low"      — defense-in-depth issue, information disclosure, weak crypto without direct exploitability
8. If you find NO vulnerabilities, return exactly: {"findings": []}
9. Respond ONLY with valid JSON. No markdown, no explanation outside the JSON.${multiRules}

${RULE_LINE}
OUTPUT SCHEMA
${RULE_LINE}
{
  "findings": [
    {${chunkIdField}
      "vuln_name": "<exact name from catalog above>",
      "description": "<one sentence: what is wrong and why it is dangerous in this specific code>",
      "code_snippet": "<the exact vulnerable line or expression, copied verbatim>",
      "severity": "critical|high|medium|low",
      "confidence": "high|medium|low",
      "fix": "<concrete fix: name the safe API / parameterised call / validation step required>"
    }
  ]
}

${RULE_LINE}
${multi ? 'CODE CHUNKS' : 'CODE CHUNK'}
${RULE_LINE}
`;

  return { prefix, body: renderChunkBlocks(chunks, multi) };
}

/**
 * Default single-chunk prompt builder (kept for programmatic callers and as the
 * override signature): (chunk, vulnClasses, includeSignals) => string.
 *
 * The vuln catalog is first filtered down to the classes relevant to
 * chunk.language (see vulnCatalog.js), so a C file's prompt never carries
 * CSRF/CORS/JWT classes and a PHP file's never carries Rust's "unsafe block".
 *
 * includeSignals: false (the default everywhere) omits the per-class
 * "Detect when you see" bullets — class name, CWE and scope rule are always
 * kept. Signals are the single biggest part of the catalog: for Python they
 * add roughly 6k tokens to every Pass-1 call (see README "Fixed prompt
 * scaffolding, measured"). Pass --include-signals when the recall is worth it.
 */
function defaultBuildPrompt(chunk, vulnClasses, includeSignals = false) {
  const { prefix, body } = buildScanPromptParts([chunk], vulnClasses, includeSignals);
  return prefix + body;
}

// ─── Verification prompt ────────────────────────────────────────────────────
function defaultVerificationPrompt(finding, chunk) {
  return `You are a strict security auditor. You are given a potential vulnerability finding and the original code chunk it was derived from. Your task is to determine if the finding is a FALSE POSITIVE. A false positive means the reported vulnerability does NOT actually exist in the code, or it is not exploitable due to context (e.g., the "attacker-controlled input" is actually not under attacker control, or the vulnerability class is misapplied).

Code:
\`\`\`
${chunk.code}
\`\`\`

Finding:
${JSON.stringify(finding, null, 2)}

Based on the code, is this finding valid? Respond with a JSON object with a field "is_valid" (boolean) and optionally "reason" (string). For example: {"is_valid": true, "reason": "The input is indeed user-controlled."} or {"is_valid": false, "reason": "The code_snippet is inside a function that is only called with hardcoded values."}

Do not include any other text.`;
}

// ─── Batched verification prompt (all findings of ONE chunk, one call) ─────
// The chunk is sent once instead of once per finding. Response is an array
// keyed by the finding's index; workers.js falls back to per-finding calls
// for any index the model leaves out or garbles.
function defaultBatchVerificationPrompt(findings, chunk) {
  const list = findings.map((f, index) => ({ index, ...f }));
  return `You are a strict security auditor. You are given several potential vulnerability findings and the single original code chunk they were derived from. For EACH finding, determine if it is a FALSE POSITIVE. A false positive means the reported vulnerability does NOT actually exist in the code, or it is not exploitable due to context (e.g., the "attacker-controlled input" is actually not under attacker control, or the vulnerability class is misapplied). Judge every finding independently.

Code:
\`\`\`
${chunk.code}
\`\`\`

Findings (each has an "index"):
${JSON.stringify(list, null, 2)}

Respond with a JSON object containing one entry per finding, using the same "index": {"results": [{"index": 0, "is_valid": true, "reason": "The input is indeed user-controlled."}, {"index": 1, "is_valid": false, "reason": "The code_snippet is only called with hardcoded values."}]}
"is_valid" must be a boolean and "reason" is optional. Do not include any other text.`;
}

// ─── Taint trace prompt ────────────────────────────────────────────────────
// Each chain entry is labelled from the role buildFullCallChain() assigned it
// (chunk._role), NOT from its position: the sink is the chunk that holds the
// finding, callers sit above it and callees below it. (Labelling by position
// used to call the last callee "SINK" and the real sink "FUNCTION 1".)
function renderCallChain(callChain) {
  const hasRoles = callChain.some(c => c && c._role);
  const callerCount = callChain.filter(c => c._role === 'caller').length;
  let callerSeen = 0, calleeSeen = 0;

  return callChain.map((chunk, i) => {
    let label;
    if (!hasRoles) {
      label = i === 0 ? '🔴 ENTRY POINT (caller)'
            : i === callChain.length - 1 ? '🟢 SINK (vulnerable code)'
            : `🔄 FUNCTION ${i}`;
    } else if (chunk._role === 'sink') {
      label = callChain.length === 1
        ? '🟢 SINK (vulnerable code — no callers or callees found)'
        : '🟢 SINK (vulnerable code — contains the flagged finding)';
    } else if (chunk._role === 'caller') {
      callerSeen++;
      label = callerSeen === 1
        ? '🔴 OUTERMOST CALLER (possible entry point)'
        : `🔄 CALLER ${callerSeen}/${callerCount} (calls toward the sink)`;
    } else {
      calleeSeen++;
      label = `🔄 CALLEE ${calleeSeen} (called from the sink)`;
    }
    const note = chunk._excerpted ? '\n// NOTE: excerpt only — call-site windows / head of the function, not the whole chunk' : '';
    return `// === ${label} ===\n// File: ${chunk.file}\n// Lines: ${chunk.startLine}–${chunk.endLine}\n// Name: ${chunk.name}${note}\n${chunk.code}`;
  }).join('\n\n');
}

function defaultTaintTracePrompt(finding, callChain) {
  const chainCode = renderCallChain(callChain);

  return `You are a security analyst performing a final validation of a potential vulnerability. Your task is to trace the flow of attacker-controlled input through the entire call chain to determine if the vulnerability is actually exploitable.

ORIGINAL FINDING:
${JSON.stringify(finding, null, 2)}

CALL CHAIN (all functions involved, ordered from outermost callers, to the SINK, to its callees):
${chainCode}

TASK:
Trace the flow of attacker-controlled input from the outermost caller / entry point through the CALL CHAIN to the SINK.

Answer these questions:
1. Does the attacker-controlled input actually reach the vulnerable code? (reachable)
2. Are there any sanitization, validation, or escaping steps along the way? (sanitized)
3. If there are sanitization steps, do they properly neutralize the attack? (bypassed)
4. Is the vulnerability truly exploitable, or is it mitigated by the call chain? (exploitable)

Respond with a JSON object:
{
  "reachable": true/false,
  "sanitized": true/false,
  "bypassed": true/false,
  "exploitable": true/false,
  "flow_path": "step1 -> step2 -> ... -> sink (describe the actual flow)",
  "reasoning": "Detailed but short (less than 300 words) explanation of your analysis"
}

If the input does NOT reach the sink, set "reachable" to false and explain why.
If the input reaches the sink but is sanitized, set "sanitized" to true.
If the input bypasses sanitization, set "bypassed" to true and explain how.
If the vulnerability is truly exploitable, set "exploitable" to true.

Do not include any other text.`;
}

// Batched: every finding of ONE chunk shares the same call chain, so the chain
// is sent once with all the findings listed, instead of once per finding.
function defaultBatchTaintTracePrompt(findings, callChain) {
  const chainCode = renderCallChain(callChain);
  const list = findings.map((f, index) => ({ index, ...f }));

  return `You are a security analyst performing a final validation of several potential vulnerabilities that live in the same function (the SINK). Your task is to trace the flow of attacker-controlled input through the entire call chain to determine, for EACH finding, whether it is actually exploitable. Judge every finding independently.

ORIGINAL FINDINGS (each has an "index"):
${JSON.stringify(list, null, 2)}

CALL CHAIN (all functions involved, ordered from outermost callers, to the SINK, to its callees):
${chainCode}

TASK:
For each finding, trace the flow of attacker-controlled input from the outermost caller / entry point through the CALL CHAIN to the SINK and answer:
1. Does the attacker-controlled input actually reach the vulnerable code? (reachable)
2. Are there any sanitization, validation, or escaping steps along the way? (sanitized)
3. If there are sanitization steps, do they properly neutralize the attack? (bypassed)
4. Is the vulnerability truly exploitable, or is it mitigated by the call chain? (exploitable)

Respond with a JSON object with one entry per finding, using the same "index":
{
  "results": [
    {
      "index": 0,
      "reachable": true/false,
      "sanitized": true/false,
      "bypassed": true/false,
      "exploitable": true/false,
      "flow_path": "step1 -> step2 -> ... -> sink",
      "reasoning": "Short (less than 150 words) explanation"
    }
  ]
}

If the input does NOT reach the sink, set "reachable" to false. If it reaches the sink but is sanitized, set "sanitized" to true; if it bypasses the sanitization, set "bypassed" to true. If the vulnerability is truly exploitable, set "exploitable" to true.

Do not include any other text.`;
}

export {
  defaultBuildPrompt, buildScanPromptParts, renderChunkBlocks,
  defaultVerificationPrompt, defaultBatchVerificationPrompt,
  defaultTaintTracePrompt, defaultBatchTaintTracePrompt,
};
