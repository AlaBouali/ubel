'use strict';
// signals.js — heuristics that need more than one fact about a method or a constant:
//   • sensitive-looking data written to the system log (Log.*)
//   • sensitive-looking values stored in plaintext SharedPreferences / SQLite
//   • hardcoded credentials in constants, JWT literals and JWT/HMAC signing secrets
//
// Everything here is pure (no I/O) so it can be unit-tested without a DEX fixture. The DEX walker in
// android.js feeds it the calls and string literals it sees inside one method, then asks for verdicts.
//
// These are heuristics, not data-flow analysis: ubel-mobile has no decompiler. A "direct" verdict means a
// constant argument of the call itself looks sensitive (Log.d("password", …), putString("accesstoken", …));
// a "near" verdict means the same method also loads a sensitive-looking label, which is weaker evidence and
// is reported with confidence "low". Whole-string-pool keyword matching is deliberately NOT used: SDK error
// messages ("The password is invalid …") would drown every real result.

import { mask } from './findings.js';

// Words that mark a value as sensitive. Deliberately conservative: "auth" and "key" alone are far too common.
export const SENSITIVE_LABEL = new RegExp(
  '(passw(?:or)?d|passwd|pwd|passcode|passphrase|secret|jwt|bearer|token|credential|\\botp\\b|\\bpin\\b|cvv|' +
  'card[_\\s-]?(?:no|num)|\\bssn\\b|api[_-]?key|private[_-]?key|authorization|session[_-]?(?:id|key|token)|account[_-]?(?:no|num))', 'i');

const strVal = a => (a && a.k === 'str' ? a.v : null);

/** A short, label-like literal that names something sensitive ("accesstoken", "password: "); prose is rejected. */
export function sensitiveLabel(s) {
  if (typeof s !== 'string' || s.length < 3 || s.length > 40) return null;
  if (s.trim().split(/\s+/).length > 3) return null;
  return SENSITIVE_LABEL.test(s) ? s : null;
}

const show = a => { const v = strVal(a); return v === null ? '…' : JSON.stringify(v.length > 40 ? `${v.slice(0, 40)}…` : v); };

// ── per-method call signals ─────────────────────────────────────────────────────────────────────────
export const SIGNAL_KEYS = new Map();
for (const m of ['v', 'd', 'i', 'w', 'e', 'wtf']) SIGNAL_KEYS.set(`Landroid/util/Log;->${m}`, { kind: 'log', short: `Log.${m}` });
for (const m of ['putString', 'putStringSet']) SIGNAL_KEYS.set(`Landroid/content/SharedPreferences$Editor;->${m}`, { kind: 'prefs', short: `Editor.${m}` });
for (const m of ['insert', 'insertOrThrow', 'insertWithOnConflict', 'replace', 'replaceOrThrow', 'update', 'updateWithOnConflict', 'execSQL']) {
  SIGNAL_KEYS.set(`Landroid/database/sqlite/SQLiteDatabase;->${m}`, { kind: 'sql', short: `SQLiteDatabase.${m}` });
}
SIGNAL_KEYS.set('Landroid/content/ContentValues;->put', { kind: 'cv', short: 'ContentValues.put' });

/** Collects what one method does, then judges it. Reuse one instance and call reset() before each method. */
export class MethodSignals {
  constructor() { this.reset(); }
  reset() { this.calls = []; this.labels = []; }
  call(key, args) { const sig = SIGNAL_KEYS.get(key); if (sig) this.calls.push({ ...sig, args: args || [] }); }
  label(s) { const l = sensitiveLabel(s); if (l && !this.labels.includes(l) && this.labels.length < 8) this.labels.push(l); }

  /** @returns {{rule:string, confidence:'medium'|'low', evidence:string, description:string}[]} */
  evaluate() {
    const out = [];
    const by = k => this.calls.filter(c => c.kind === k);
    const near = this.labels.slice(0, 3).map(l => JSON.stringify(l)).join(', ');

    const logs = by('log');
    if (logs.length) {
      // A tag is usually a class name ("GetTokenResponse"), so it only counts when it is a plain word ("Token", "jwt").
      const plainTag = t => (/^[A-Za-z][a-z0-9_:\- ]{2,24}$/.test(t || '') ? sensitiveLabel(t) : null);
      const direct = logs.find(c => plainTag(strVal(c.args[0])) || sensitiveLabel(strVal(c.args[1])));
      if (direct) {
        out.push({ rule: 'android.dex.logging_sensitive', confidence: 'medium', evidence: `${direct.short}(${show(direct.args[0])}, ${show(direct.args[1])})`,
          description: 'A log call has a tag or message that names sensitive data. Log output is readable over adb and by other apps on older Android versions, and ends up in bug reports.' });
      } else if (this.labels.length) {
        out.push({ rule: 'android.dex.logging_sensitive', confidence: 'low', evidence: `${logs[0].short}(…) in a method that handles ${near}`,
          description: 'A log call sits in a method that also handles sensitive-looking values; the logged text is built at runtime, so this cannot be confirmed statically. Review what is logged.' });
      }
    }

    const puts = by('prefs');
    if (puts.length) {
      const direct = puts.find(c => sensitiveLabel(strVal(c.args[1])));     // args[0] is the Editor
      if (direct) {
        out.push({ rule: 'android.dex.plaintext_prefs', confidence: 'medium', evidence: `${direct.short}(${show(direct.args[1])}, …)`,
          description: 'A sensitive-looking value is written to SharedPreferences, which are plain XML files; anyone with device backup, root or a debuggable build can read them.' });
      } else if (this.labels.length) {
        out.push({ rule: 'android.dex.plaintext_prefs', confidence: 'low', evidence: `${puts[0].short}(…) in a method that handles ${near}`,
          description: 'SharedPreferences are written in a method that also handles sensitive-looking values; the key is not a constant, so this cannot be confirmed statically. Review what is stored.' });
      }
    }

    const writes = by('sql');
    if (writes.length) {
      const cv = by('cv').find(c => sensitiveLabel(strVal(c.args[1])));
      if (cv) {
        out.push({ rule: 'android.dex.plaintext_database', confidence: 'medium', evidence: `${cv.short}(${show(cv.args[1])}, …) with ${writes[0].short}`,
          description: 'A sensitive-looking column is written to a SQLite database, which is unencrypted unless SQLCipher or similar is used.' });
      } else if (this.labels.length) {
        out.push({ rule: 'android.dex.plaintext_database', confidence: 'low', evidence: `${writes[0].short}(…) in a method that handles ${near}`,
          description: 'A SQLite write sits in a method that also handles sensitive-looking values; review what is stored.' });
      }
    }
    return out;
  }
}

/** CREATE TABLE statements (hand-written or Room-generated) that define a sensitive-looking column. */
export function schemaSensitive(s) {
  if (typeof s !== 'string' || s.length < 12 || s.length > 4000) return null;
  if (!/create\s+(?:virtual\s+)?table/i.test(s)) return null;
  const m = /[`"'\s,(](passw(?:or)?d|pwd|passcode|secret|token|cvv|card_?(?:no|num\w*)|ssn|pin|otp)[`"'\s,)]/i.exec(s);
  return m ? m[1] : null;
}

// ── hardcoded credentials ───────────────────────────────────────────────────────────────────────────
const CRED_NAME = /(passw(?:or)?d|passwd|pwd|passphrase|secret|jwt|token|api[_-]?key|private[_-]?key|credential|auth[_-]?key|signing[_-]?key|encryption[_-]?key|access[_-]?key|master[_-]?key|hmac)/i;
// Constants that hold the *name* of a key / header / preference rather than a secret value.
const NAME_IS_KEY_NAME = /^(?:KEY|EXTRA|PREF|PREFS|ACTION|TAG|HEADER|FIELD|PARAM|ARG|ATTR)_|_(?:NAME|ID|PREF|PREFS|EXTRA|ACTION|TAG|URL|URI|HEADER|TYPE|ENDPOINT|PATH|FIELD|PARAM|ARG|PROP|ATTR|LABEL|TITLE|MSG|MESSAGE|TEXT|HINT|ERROR|REGEX|PATTERN|DESC|DESCRIPTION|CODE|STATUS|FORMAT)$|^(?:TOKEN|PASSWORD|PASSWD|PWD|JWT|CREDENTIALS?|AUTH|SESSION|USER|ACCESS_TOKEN|REFRESH_TOKEN)_KEY$/i;
const PLACEHOLDER = /^(?:change[_-]?me|your[_-]|x{3,}|todo|n\/a|null|none|undefined|example|sample|test(?:ing)?$|<|\$\{|%[sd]|\{)/i;

/**
 * Judges a `static final String NAME = "value"` constant.
 * @returns {{name:string}|null} non-null when the name says credential and the value looks like a real secret
 */
export function credentialConstant(name, value) {
  if (typeof name !== 'string' || typeof value !== 'string') return null;
  if (!CRED_NAME.test(name) || NAME_IS_KEY_NAME.test(name)) return null;
  if (value.length < 6 || value.length > 256 || /\s/.test(value)) return null;
  if (/^(?:https?:\/\/|\/)/i.test(value) || PLACEHOLDER.test(value)) return null;
  if (/^[a-z][a-z_.\-]*$/.test(value)) return null;                 // "access_token": a key name, not a secret
  if (/^[a-z]+(?:[A-Z][a-z0-9]*)+$/.test(value)) return null;        // "accessToken"
  if (/^[A-Z][A-Z0-9_]+$/.test(value)) return null;                  // "ERROR_TOKEN"
  if (/^[a-z][a-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_$]*){2,}$/.test(value)) return null;  // package / class names
  if (value.replace(/[^A-Za-z0-9]/g, '').toLowerCase() === name.replace(/[^A-Za-z0-9]/g, '').toLowerCase()) return null;
  const mixed = /[A-Z]/.test(value) && /[a-z]/.test(value);
  if (!(/\d/.test(value) || /[^A-Za-z0-9]/.test(value) || (mixed && value.length >= 8))) return null;
  return { name };
}

export function maskedConstant(name, value) { return `${name} = "${mask(value)}"`; }

export const JWT_LITERAL = /^eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*$/;
export const isJwtLiteral = s => typeof s === 'string' && s.length < 4096 && s.charCodeAt(0) === 101 && JWT_LITERAL.test(s);

/** Constant string/bytes passed as a signing secret. @param {any[]} args  @param {number} from first argument to consider */
export function constantSecretArg(args, from = 0) {
  for (const a of (args || []).slice(from)) {
    if (a && (a.k === 'str' || a.k === 'bytes') && String(a.v).length >= 1) return a;
  }
  return null;
}
