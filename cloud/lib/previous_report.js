'use strict';
// previous_report.js — finds the previous cloud report of the same asset, for the
// "Diffs" tab. Same lookup as the SCA engine's loadPreviousReport: the newest
// <timestamp>.cloud.zip that precedes the current one in the asset's history folder,
// read for its report.cloud.json. Never throws: no previous report just means no diff.

import fs from 'fs';
import path from 'path';
import zlib from 'zlib';

/** Reads one entry of a zip (stored or deflate) into a Buffer; null when absent / unsupported. */
function readZipEntry(zipFile, entryName) {
  const buf = fs.readFileSync(zipFile);
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 22 - 65535); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) return null;
  const total = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16);
  for (let n = 0; n < total; n++) {
    if (p + 46 > buf.length || buf.readUInt32LE(p) !== 0x02014b50) return null;
    const method     = buf.readUInt16LE(p + 10);
    const csize      = buf.readUInt32LE(p + 20);
    const nameLen    = buf.readUInt16LE(p + 28);
    const extraLen   = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const localOff   = buf.readUInt32LE(p + 42);
    const name       = buf.toString('utf8', p + 46, p + 46 + nameLen);
    if (name === entryName) {
      const dataStart = localOff + 30 + buf.readUInt16LE(localOff + 26) + buf.readUInt16LE(localOff + 28);
      const raw = buf.subarray(dataStart, dataStart + csize);
      if (method === 0) return Buffer.from(raw);
      if (method === 8) return zlib.inflateRawSync(raw);
      return null;
    }
    p += 46 + nameLen + extraLen + commentLen;
  }
  return null;
}

/**
 * @param {string} zipPath    the zip about to be written for this scan
 * @param {string} reportTag  'cloud'
 * @param {string} entryName  report json name inside the zip (reportFileName('report', tag, 'json'))
 * @returns {{file: string, report: object} | null}
 */
function loadPreviousReport(zipPath, reportTag, entryName) {
  try {
    const dir     = path.dirname(zipPath);
    const current = path.basename(zipPath);
    const suffix  = `.${reportTag}.zip`;
    const earlier = fs.readdirSync(dir).filter(n => n.endsWith(suffix) && n < current).sort().reverse();
    for (const n of earlier) {
      try {
        const data = readZipEntry(path.join(dir, n), entryName);
        if (data) return { file: n, report: JSON.parse(data.toString('utf8')) };
      } catch { /* unreadable bundle: try the next older one */ }
    }
  } catch { /* no history folder yet: first report of this asset */ }
  return null;
}

export { loadPreviousReport, readZipEntry };