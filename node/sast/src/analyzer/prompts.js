'use strict';

import { buildVulnCatalog, filterVulnClassesForLanguage } from './vulnCatalog.js';

/**
 * Default prompt builder. Receives the enriched chunk and vuln class list.
 * Override via opts.buildPrompt = (chunk, vulnClasses, includeSignals) => string
 *
 * The vuln catalog passed in is first filtered down to only the classes
 * relevant to chunk.language (see vulnCatalog.js's `languages` field on each
 * class and filterVulnClassesForLanguage) — e.g. a C file's prompt won't
 * carry CSRF/CORS/JWT classes, and a PHP file's prompt won't carry Rust's
 * "unsafe block" class. This cuts irrelevant catalog noise (and tokens) from
 * every chunk's prompt without the caller having to do anything.
 *
 * includeSignals: when false, the vulnerability catalog omits the per-class
 * "Detect when you see" bullets — set via opts.skipSignals on analyzeSast()
 * to reduce prompt tokens (catalog name/CWE/scope is still always included).
 */
function defaultBuildPrompt(chunk, vulnClasses, includeSignals = true) {
  const applicableClasses = filterVulnClassesForLanguage(vulnClasses, chunk.language);
  const catalog = buildVulnCatalog(applicableClasses, includeSignals);

  return `You are a senior application security engineer performing a SAST review.
Analyze the following ${chunk.language} code chunk for security vulnerabilities.

════════════════════════════════════════════════════════
VULNERABILITY CATALOG  (report ONLY classes listed here)
════════════════════════════════════════════════════════
${catalog}

════════════════════════════════════════════════════════
ANALYSIS RULES
════════════════════════════════════════════════════════
1. Report ONLY concrete issues whose evidence is present in this exact code chunk.
   Do NOT speculate about code you cannot see.
2. For classes marked "Scope: attacker-controlled input required", the taint source
   (user input, request param, file upload, env var, network socket, CLI arg) must be
   visible in this chunk or clearly implied by the function signature / parameter names.
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
9. Respond ONLY with valid JSON. No markdown, no explanation outside the JSON.

════════════════════════════════════════════════════════
OUTPUT SCHEMA
════════════════════════════════════════════════════════
{
  "findings": [
    {
      "vuln_name": "<exact name from catalog above>",
      "description": "<one sentence: what is wrong and why it is dangerous in this specific code>",
      "code_snippet": "<the exact vulnerable line or expression, copied verbatim>",
      "severity": "critical|high|medium|low",
      "confidence": "high|medium|low",
      "fix": "<concrete fix: name the safe API / parameterised call / validation step required>"
    }
  ]
}

════════════════════════════════════════════════════════
CODE CHUNK
════════════════════════════════════════════════════════
Language  : ${chunk.language}
Type      : ${chunk.type}

\`\`\`${chunk.language.toLowerCase()}
${chunk.code}
\`\`\``;
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

// ─── Taint trace prompt ────────────────────────────────────────────────────
function defaultTaintTracePrompt(finding, callChain) {
  const chainCode = callChain.map((chunk, i) => {
    const label = i === 0 ? '🔴 ENTRY POINT (caller)' :
                  i === callChain.length - 1 ? '🟢 SINK (vulnerable code)' :
                  `🔄 FUNCTION ${i}`;
    return `// === ${label} ===\n// File: ${chunk.file}\n// Lines: ${chunk.startLine}–${chunk.endLine}\n// Name: ${chunk.name}\n${chunk.code}`;
  }).join('\n\n');

  return `You are a security analyst performing a final validation of a potential vulnerability. Your task is to trace the flow of attacker-controlled input through the entire call chain to determine if the vulnerability is actually exploitable.

ORIGINAL FINDING:
${JSON.stringify(finding, null, 2)}

CALL CHAIN (all functions involved, from outermost callers to innermost callees):
${chainCode}

TASK:
Trace the flow of attacker-controlled input from the ENTRY POINT through the CALL CHAIN to the SINK.

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

export { defaultBuildPrompt, defaultVerificationPrompt, defaultTaintTracePrompt };