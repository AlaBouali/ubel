'use strict';
// coverage.js — tracks where a scan could NOT look. A "note" is information; a "gap" is a place the analysis did not cover
// (a DEX that failed to parse, a file over the size limit, a budget that ran out, an encrypted binary …). Gaps are also notes,
// but they additionally make the scan "incomplete": a clean result over incomplete coverage must not read as a pass, so the CLI
// exits 3 (like ubel-cloud) unless --allow-partial is given.

/** An array of analysis notes that also remembers which of them are coverage gaps. */
export class Notes extends Array {
  static get [Symbol.species]() { return Array; }      // .map/.filter return plain arrays
  constructor(...a) { super(...a); Object.defineProperty(this, 'gaps', { value: [], enumerable: false }); }
  gap(message) { this.push(message); this.gaps.push(message); }
}

/** Records a coverage gap on a Notes list; on a plain array (direct callers, tests) it degrades to an ordinary note. */
export function gap(notes, message) {
  if (notes && typeof notes.gap === 'function') notes.gap(message);
  else if (Array.isArray(notes)) notes.push(message);
}
