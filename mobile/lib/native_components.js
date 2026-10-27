'use strict';
// native_components.js — the software that is bundled INSIDE an app's native libraries.
//
// An APK ships lib/<abi>/*.so, an IPA ships Mach-O frameworks / dylibs, and those files carry the same kind of evidence ubel-binary reads:
// version banners of C/C++ libraries (OpenSSL, SQLite, libcurl, zlib …) → NVD CPEs, Go module build info and Rust crates → OSV.dev PURLs.
// This collector runs ubel-binary's component detection over each native binary the mobile scan already reads, and keeps the records
// (deduplicated across libraries and ABIs) so ubel-mobile can look them up like any other dependency. Nothing is executed or loaded.
//
// The reader is injected (`scanner`) instead of imported: ubel-binary itself imports from ubel-mobile, and an injected function keeps
// that dependency one-way. Without a scanner the collector is inert, which is what library callers of scanPackage() get by default.

import { gap } from './coverage.js';

const MAX_SOURCES = 5;                      // library paths remembered per component (the same OpenSSL is usually in every ABI copy and several libraries)

export class NativeComponents {
  /**
   * @param {((buf: Buffer, name: string) => ({format: string, records: object[], gaps: string[]} | null)) | null} scanner
   *        ubel-binary's `scanEmbeddedComponents`; null / undefined switches the collector off
   */
  constructor(scanner = null) {
    this.scanner = typeof scanner === 'function' ? scanner : null;
    this.byKey = new Map();
  }

  get enabled() { return this.scanner !== null; }

  /**
   * Reads the components of one native binary of the package.
   * @param {Buffer} buf
   * @param {{name: string, where: string, notes: object}} meta  `where` is the path inside the package (module prefix included), used as evidence
   */
  add(buf, { name, where, notes }) {
    if (!this.scanner) return;
    let result;
    try { result = this.scanner(buf, name); }
    catch (err) { gap(notes, `${where}: components bundled in this native binary could not be read (${err.message}); known-vulnerable libraries inside it were not looked up.`); return; }
    if (!result) return;                    // not ELF / Mach-O / PE: the caller already said so
    for (const g of result.gaps || []) gap(notes, `${where}: ${String(g).replace(new RegExp(`^${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}: `), '')}`);
    for (const r of result.records || []) {
      const key = r.purl || r.cpe || `${r.ecosystem}|${r.name}|${r.version}`;
      const own = (r.sources && r.sources[0]) || 'embedded version string';
      const source = `${where}: ${own}`;
      const known = this.byKey.get(key);
      if (!known) { this.byKey.set(key, { ...r, sources: [source], source_types: [...(r.source_types || [])] }); continue; }
      if (known.sources.length < MAX_SOURCES && !known.sources.includes(source)) known.sources.push(source);
      for (const t of r.source_types || []) if (!known.source_types.includes(t)) known.source_types.push(t);
    }
  }

  /** The deduplicated component records, in the shape ubel-binary's lookup (scanBinaryDependencies) takes. */
  get records() { return [...this.byKey.values()]; }
}
