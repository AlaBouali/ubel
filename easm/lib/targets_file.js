'use strict';
// easm/lib/targets_file.js
//
// One implementation of "load targets from a text file" for ubel-url,
// ubel-host, ubel-domain and ubel-easm, so all four agree on the file format:
//
//   - one entry per line (entries may also be space- or comma-separated, for
//     the entry points that split them — that is the caller's choice)
//   - blank lines are ignored
//   - lines whose first non-blank character is "#" are comments
//   - CRLF line endings and a leading UTF-8 byte-order mark (what Windows
//     Notepad writes) are tolerated; without the BOM strip the first entry
//     would silently become "\uFEFFexample.com" and fail validation

import fs from 'fs';
import path from 'path';

/**
 * Reads a targets file and returns its entries, in file order.
 * Throws (with the underlying fs error) when the file can't be read.
 *
 * @param {string} file  path, absolute or relative to the current directory
 * @returns {string[]}   trimmed, non-empty, non-comment lines
 */
export function readTargetsFile(file) {
  const text = fs.readFileSync(path.resolve(file), 'utf8').replace(/^\uFEFF/, '');
  const entries = [];
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim();
    if (t && !t.startsWith('#')) entries.push(t);
  }
  return entries;
}

/**
 * CLI wrapper: same as readTargetsFile(), but prints the error and exits 2
 * (this tool's "bad usage" code) instead of throwing — what parseArgs() wants.
 * A readable file that contains no entries is also a usage error: silently
 * scanning nothing would look like a clean result.
 *
 * @param {string} file  the path given to the flag
 * @param {string} flag  the flag it was given to, for the error message
 */
export function loadTargetsFileOrExit(file, flag) {
  let entries;
  try {
    entries = readTargetsFile(file);
  } catch (err) {
    console.error(`Failed to read ${flag} "${file}": ${err.message}`);
    process.exit(2);
  }
  if (!entries.length) {
    console.error(`${flag} "${file}" contains no targets (blank lines and "#" comments are ignored).`);
    process.exit(2);
  }
  return entries;
}
