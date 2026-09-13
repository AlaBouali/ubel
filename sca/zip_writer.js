import zlib from "zlib";

// ─────────────────────────────────────────────────────────────────────────────
// Minimal, dependency-free ZIP writer.
//
// Builds a standard (non-ZIP64) .zip archive in memory from a list of named
// entries, using Node's built-in zlib for DEFLATE compression — no external
// package required. Good enough for bundling a handful of report files
// (JSON/HTML/SARIF/SBOM, each well under 4 GB); not meant as a general-purpose
// archiving library.
// ─────────────────────────────────────────────────────────────────────────────

// Standard ZIP CRC-32 (polynomial 0xEDB88320), computed directly rather than
// pulling in a crc32 dependency — the table is tiny and this only ever runs
// over report-sized buffers.
const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    }
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(buf) {
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) {
    crc = CRC_TABLE[(crc ^ buf[i]) & 0xFF] ^ (crc >>> 8);
  }
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

function dosDateTime(date) {
  const dosTime = (date.getHours() << 11) | (date.getMinutes() << 5) | (date.getSeconds() >> 1);
  const dosDate = ((date.getFullYear() - 1980) << 9) | ((date.getMonth() + 1) << 5) | date.getDate();
  return { dosTime, dosDate };
}

/**
 * Build a ZIP archive (as a Buffer) from a list of entries.
 *
 * @param {{name: string, data: (Buffer|string)}[]} entries
 *   `name` is the path stored inside the archive (e.g. "report.json").
 *   `data` is the file content — a Buffer, or a string (UTF-8 encoded).
 * @param {Date} [date] - mtime stamped on every entry; defaults to now.
 * @returns {Buffer}
 */
function buildZip(entries, date = new Date()) {
  const { dosTime, dosDate } = dosDateTime(date);

  const localChunks = [];
  const centralChunks = [];
  let offset = 0;

  for (const { name, data } of entries) {
    const raw = Buffer.isBuffer(data) ? data : Buffer.from(String(data), "utf8");
    const crc = crc32(raw);
    const deflated = zlib.deflateRawSync(raw);
    // Fall back to STORE (uncompressed) if compression didn't actually help
    // (can happen for tiny or already-compressed inputs).
    const useDeflate = deflated.length < raw.length;
    const method  = useDeflate ? 8 : 0; // 8 = DEFLATE, 0 = STORE
    const payload = useDeflate ? deflated : raw;
    const nameBuf = Buffer.from(name, "utf8");

    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0);   // local file header signature
    localHeader.writeUInt16LE(20, 4);           // version needed to extract
    localHeader.writeUInt16LE(0, 6);            // general purpose bit flag
    localHeader.writeUInt16LE(method, 8);       // compression method
    localHeader.writeUInt16LE(dosTime, 10);
    localHeader.writeUInt16LE(dosDate, 12);
    localHeader.writeUInt32LE(crc, 14);
    localHeader.writeUInt32LE(payload.length, 18); // compressed size
    localHeader.writeUInt32LE(raw.length, 22);     // uncompressed size
    localHeader.writeUInt16LE(nameBuf.length, 26);
    localHeader.writeUInt16LE(0, 28);           // extra field length

    localChunks.push(localHeader, nameBuf, payload);

    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50, 0); // central directory header signature
    centralHeader.writeUInt16LE(20, 4);         // version made by
    centralHeader.writeUInt16LE(20, 6);         // version needed to extract
    centralHeader.writeUInt16LE(0, 8);          // general purpose bit flag
    centralHeader.writeUInt16LE(method, 10);
    centralHeader.writeUInt16LE(dosTime, 12);
    centralHeader.writeUInt16LE(dosDate, 14);
    centralHeader.writeUInt32LE(crc, 16);
    centralHeader.writeUInt32LE(payload.length, 20);
    centralHeader.writeUInt32LE(raw.length, 24);
    centralHeader.writeUInt16LE(nameBuf.length, 28);
    centralHeader.writeUInt16LE(0, 30);         // extra field length
    centralHeader.writeUInt16LE(0, 32);         // file comment length
    centralHeader.writeUInt16LE(0, 34);         // disk number start
    centralHeader.writeUInt16LE(0, 36);         // internal file attributes
    centralHeader.writeUInt32LE(0, 38);         // external file attributes
    centralHeader.writeUInt32LE(offset, 42);    // relative offset of local header

    centralChunks.push(centralHeader, nameBuf);

    offset += localHeader.length + nameBuf.length + payload.length;
  }

  const centralDirOffset = offset;
  const centralDir = Buffer.concat(centralChunks);

  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);            // end of central directory signature
  eocd.writeUInt16LE(0, 4);                     // disk number
  eocd.writeUInt16LE(0, 6);                     // disk with central directory
  eocd.writeUInt16LE(entries.length, 8);        // entries on this disk
  eocd.writeUInt16LE(entries.length, 10);       // total entries
  eocd.writeUInt32LE(centralDir.length, 12);    // size of central directory
  eocd.writeUInt32LE(centralDirOffset, 16);     // offset of central directory
  eocd.writeUInt16LE(0, 20);                    // comment length

  return Buffer.concat([...localChunks, centralDir, eocd]);
}

export { buildZip };