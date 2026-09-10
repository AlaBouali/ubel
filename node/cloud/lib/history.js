'use strict';
import fs from 'fs';
import path from 'path';
import { SCA_STATIC_PATH } from './sca-path.js';

/**
 * "Zipping is for history, not the live report": each run's
 * findings.json/findings.html are always written as plain files (see
 * index.js — no --format flag, both are always produced). Before either
 * one gets overwritten, whatever's already there from the previous run
 * is folded into a timestamped zip under history/ instead of being
 * clobbered, using sca's own zip module — the same shared module
 * html-report.js already pulls tailwindcss.js/chartjs.js/googlefonts.js
 * from — rather than a new zip implementation living in this package.
 *
 * NOTE: this assumes sca/zip.js exports a `createZip(entries)` returning
 * a Buffer/Uint8Array, where `entries` is `[{ name, content }]` — the
 * same shape used elsewhere in this codebase for in-memory file lists.
 * If sca's actual export name/signature differs, update the call below
 * (same spirit as the SCA_STATIC_PATH note in ./sca-path.js).
 */

import { buildZip } from '../../sca/zip_writer.js';
async function loadScaZip() {
  try {
    return await import('../../sca/zip_writer.js');
  } catch (err) {
    throw new Error(
      `history: couldn't load sca's zip module from ../../sca/zip_writer.js (${err.message}). ` +
        `Update the import in src/lib/history.js if sca's zip module lives elsewhere or exports something differently.`
    );
  }
}

/**
 * Zips up whichever of `${outputBase}.json` / `${outputBase}.html`
 * already exist into history/<base>-<timestamp>.zip, next to the
 * output. Returns the archive path, or null if there was nothing to
 * archive (first run).
 */
async function archivePreviousOutputs(outputBase) {
  const candidates = [
    { ext: '.json', filePath: `${outputBase}.json` },
    { ext: '.html', filePath: `${outputBase}.html` },
  ].filter((c) => fs.existsSync(c.filePath));

  if (candidates.length === 0) return null;

  const zipModule = await loadScaZip();
  const dir = path.dirname(outputBase);
  const base = path.basename(outputBase);
  const historyDir = path.join(dir, 'history');
  fs.mkdirSync(historyDir, { recursive: true });

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const archivePath = path.join(historyDir, `${base}-${timestamp}.zip`);

  const entries = candidates.map((c) => ({
    name: `${base}${c.ext}`,
    content: fs.readFileSync(c.filePath),
  }));
  const zipBuffer = await buildZip(entries);
  fs.writeFileSync(archivePath, zipBuffer);
  return archivePath;
}

export { archivePreviousOutputs };
