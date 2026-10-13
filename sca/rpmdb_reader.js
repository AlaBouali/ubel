// rpmdb_reader.js
//
// Reads the RPM package database directly from disk — no `rpm` binary needed,
// so it works on Windows hosts, on extracted image rootfs trees, and on any
// machine without rpm installed.
//
// Supported on-disk formats (auto-detected by magic bytes, not file name):
//   • Berkeley DB Hash  — /var/lib/rpm/Packages      (RHEL/CentOS/Alma/Rocky ≤ 8, Amazon Linux 2)
//   • SQLite            — rpmdb.sqlite               (RHEL/Alma/Rocky ≥ 9, Fedora ≥ 33, AL2023)
// Not supported: NDB (Packages.db, SUSE) — throws a clear error.
//
// Each DB record is an RPM header blob; only the tags we need are decoded.

import fs   from "fs";
import path from "path";

// ─────────────────────────────────────────────────────────────────────────────
// RPM header blob
// ─────────────────────────────────────────────────────────────────────────────

const TAG = {
  NAME:         1000,
  VERSION:      1001,
  RELEASE:      1002,
  LICENSE:      1014,
  OLDFILENAMES: 1027,
  FILEMODES:    1030,
  REQUIRENAME:  1049,
  DIRINDEXES:   1116,
  BASENAMES:    1117,
  DIRNAMES:     1118,
};
const WANTED = new Set(Object.values(TAG));

const T_INT16 = 3, T_INT32 = 4, T_STRING = 6, T_STRING_ARRAY = 8, T_I18N = 9;

function cstr(buf, start, end) {
  let e = start;
  while (e < end && buf[e] !== 0) e++;
  return buf.toString("utf8", start, e);
}

/**
 * Parse a header blob: [il:u32be][dl:u32be][il × (tag,type,offset,count : 4×u32be)][data(dl)]
 * Returns { tags: Map<tag, value>, length } or null if the blob is not a valid header.
 */
function parseHeaderBlob(buf) {
  if (!buf || buf.length < 24) return null;
  const il = buf.readUInt32BE(0);
  const dl = buf.readUInt32BE(4);
  if (il === 0 || il > 0xffff) return null;
  const dataStart = 8 + il * 16;
  if (dataStart + dl > buf.length) return null;
  const dataEnd = dataStart + dl;

  const tags = new Map();
  for (let i = 0; i < il; i++) {
    const o      = 8 + i * 16;
    const tag    = buf.readUInt32BE(o);
    if (!WANTED.has(tag)) continue;
    const type   = buf.readUInt32BE(o + 4);
    const offset = buf.readUInt32BE(o + 8);
    const count  = buf.readUInt32BE(o + 12);
    let p = dataStart + offset;
    if (p >= dataEnd) continue;

    if (type === T_STRING || type === T_I18N) {
      tags.set(tag, cstr(buf, p, dataEnd));
    } else if (type === T_STRING_ARRAY) {
      const arr = [];
      for (let k = 0; k < count && p < dataEnd; k++) {
        const s = cstr(buf, p, dataEnd);
        arr.push(s);
        p += Buffer.byteLength(s) + 1;
      }
      tags.set(tag, arr);
    } else if (type === T_INT16) {
      if (p + count * 2 > dataEnd) continue;
      const arr = new Array(count);
      for (let k = 0; k < count; k++) arr[k] = buf.readUInt16BE(p + k * 2);
      tags.set(tag, arr);
    } else if (type === T_INT32) {
      if (p + count * 4 > dataEnd) continue;
      const arr = new Array(count);
      for (let k = 0; k < count; k++) arr[k] = buf.readUInt32BE(p + k * 4);
      tags.set(tag, arr);
    }
  }
  return { tags, length: dataEnd };
}

function headerToPackage(hdr) {
  const t       = hdr.tags;
  const name    = t.get(TAG.NAME);
  const version = t.get(TAG.VERSION);
  const release = t.get(TAG.RELEASE);
  if (!name || !version) return null;

  // File list: new-style (DIRNAMES + BASENAMES + DIRINDEXES) or legacy OLDFILENAMES.
  const files = [];
  const modes = t.get(TAG.FILEMODES) ?? [];
  const old   = t.get(TAG.OLDFILENAMES);
  if (old) {
    old.forEach((p, i) => files.push({ path: p, mode: modes[i] }));
  } else {
    const base = t.get(TAG.BASENAMES), dirs = t.get(TAG.DIRNAMES), idx = t.get(TAG.DIRINDEXES);
    if (base && dirs && idx) {
      for (let i = 0; i < base.length; i++) {
        const d = dirs[idx[i]];
        if (d === undefined) continue;
        files.push({ path: d + base[i], mode: modes[i] });
      }
    }
  }

  return {
    name,
    version:  release ? `${version}-${release}` : version,   // same shape as %{VERSION}-%{RELEASE}
    license:  t.get(TAG.LICENSE) || "",
    requires: t.get(TAG.REQUIRENAME) ?? [],
    files,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Berkeley DB (Hash) reader — little- and big-endian files
// ─────────────────────────────────────────────────────────────────────────────

const BDB_HASH_MAGIC = 0x00061561;
const P_HASH_UNSORTED = 2, P_OVERFLOW = 7, P_HASH = 13;
const H_KEYDATA = 1, H_OFFPAGE = 3;

function bdbMagic(buf) {
  if (buf.length < 512) return null;
  if (buf.readUInt32LE(12) === BDB_HASH_MAGIC) return "le";
  if (buf.readUInt32BE(12) === BDB_HASH_MAGIC) return "be";
  return null;
}

function* bdbHashBlobs(buf) {
  const le  = bdbMagic(buf) === "le";
  const u16 = o => (le ? buf.readUInt16LE(o) : buf.readUInt16BE(o));
  const u32 = o => (le ? buf.readUInt32LE(o) : buf.readUInt32BE(o));

  const pageSize = u32(20);
  if (pageSize < 512 || pageSize > 65536 || (pageSize & (pageSize - 1))) {
    throw new Error(`rpmdb: invalid Berkeley DB page size ${pageSize}`);
  }
  const nPages = Math.floor(buf.length / pageSize);

  for (let pg = 1; pg < nPages; pg++) {
    const base = pg * pageSize;
    const type = buf[base + 25];
    if (type !== P_HASH && type !== P_HASH_UNSORTED) continue;

    const entries = u16(base + 20);               // key/data items → 2 per record
    const idx     = i => u16(base + 26 + i * 2);  // item offset within page

    for (let i = 0; i + 1 < entries; i += 2) {
      const vi  = i + 1;
      const off = idx(vi);
      if (off < 26 + entries * 2 || off >= pageSize) continue;
      const itype = buf[base + off];

      if (itype === H_OFFPAGE) {
        // [type:1][pad:3][pgno:4][tlen:4]  → value lives on a chain of overflow pages
        let next      = u32(base + off + 4);
        let remaining = u32(base + off + 8);
        if (remaining === 0 || remaining > 256 * 1024 * 1024) continue;
        const parts = [];
        let hops = 0;
        while (next && remaining > 0 && next < nPages && hops++ < 1_000_000) {
          const ob = next * pageSize;
          if (buf[ob + 25] !== P_OVERFLOW) break;
          const len = Math.min(u16(ob + 22), remaining, pageSize - 26);
          parts.push(buf.subarray(ob + 26, ob + 26 + len));
          remaining -= len;
          next = u32(ob + 16);
        }
        if (remaining === 0) yield Buffer.concat(parts);
      } else if (itype === H_KEYDATA) {
        // Inline value: item runs from its offset up to the previous item's offset (or page end).
        const end = vi === 0 ? pageSize : idx(vi - 1);
        if (end > off + 1 && end <= pageSize) yield buf.subarray(base + off + 1, base + end);
      }
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// SQLite reader (table b-trees + overflow pages + committed WAL frames)
// ─────────────────────────────────────────────────────────────────────────────

const SQLITE_MAGIC = "SQLite format 3\0";

function sqliteMagic(buf) {
  return buf.length >= 100 && buf.toString("latin1", 0, 16) === SQLITE_MAGIC;
}

function readVarint(buf, pos) {
  let v = 0n;
  for (let i = 0; i < 8; i++) {
    const b = buf[pos + i];
    v = (v << 7n) | BigInt(b & 0x7f);
    if (!(b & 0x80)) return [Number(v), i + 1];
  }
  v = (v << 8n) | BigInt(buf[pos + 8]);
  return [Number(BigInt.asIntN(64, v)), 9];
}

/** Map<pgno, byteOffsetInWal> of the newest committed copy of each page. */
function readWalIndex(walPath, pageSize) {
  const map = new Map();
  let wal;
  try { wal = fs.readFileSync(walPath); } catch { return null; }
  if (wal.length < 32) return null;
  const magic = wal.readUInt32BE(0);
  if (magic !== 0x377f0682 && magic !== 0x377f0683) return null;
  if (wal.readUInt32BE(8) !== pageSize) return null;
  const salt1 = wal.readUInt32BE(16), salt2 = wal.readUInt32BE(20);

  let pending = new Map();
  const frameSize = 24 + pageSize;
  for (let o = 32; o + frameSize <= wal.length; o += frameSize) {
    if (wal.readUInt32BE(o + 8) !== salt1 || wal.readUInt32BE(o + 12) !== salt2) break;
    pending.set(wal.readUInt32BE(o), o + 24);
    if (wal.readUInt32BE(o + 4) !== 0) {             // commit frame
      for (const [k, v] of pending) map.set(k, v);
      pending = new Map();
    }
  }
  return map.size ? { map, wal } : null;
}

function* sqliteBlobs(dbPath) {
  const buf = fs.readFileSync(dbPath);
  let pageSize = buf.readUInt16BE(16);
  if (pageSize === 1) pageSize = 65536;
  const usable = pageSize - buf[20];
  const wal    = readWalIndex(dbPath + "-wal", pageSize);

  const getPage = n => {
    const w = wal?.map.get(n);
    if (w !== undefined) return wal.wal.subarray(w, w + pageSize);
    const s = (n - 1) * pageSize;
    if (s < 0 || s + pageSize > buf.length) throw new Error(`rpmdb: sqlite page ${n} out of range`);
    return buf.subarray(s, s + pageSize);
  };

  // Full payload of a table-leaf cell, following the overflow chain.
  const cellPayload = (p, pos, total) => {
    const X = usable - 35;
    if (total <= X) return p.subarray(pos, pos + total);
    const M = Math.floor(((usable - 12) * 32) / 255) - 23;
    const K = M + ((total - M) % (usable - 4));
    const local = K <= X ? K : M;
    const parts = [p.subarray(pos, pos + local)];
    let remaining = total - local;
    let next = p.readUInt32BE(pos + local);
    let hops = 0;
    while (next && remaining > 0 && hops++ < 10_000_000) {
      const op  = getPage(next);
      const len = Math.min(remaining, usable - 4);
      parts.push(op.subarray(4, 4 + len));
      remaining -= len;
      next = op.readUInt32BE(0);
    }
    return Buffer.concat(parts);
  };

  const decodeRecord = rec => {
    const [hdrSize, n0] = readVarint(rec, 0);
    const types = [];
    for (let pos = n0; pos < hdrSize;) {
      const [t, n] = readVarint(rec, pos);
      types.push(t); pos += n;
    }
    const out = [];
    let pos = hdrSize;
    for (const t of types) {
      if (t === 0)       out.push(null);
      else if (t === 8)  out.push(0);
      else if (t === 9)  out.push(1);
      else if (t >= 1 && t <= 6) {
        const size = [0, 1, 2, 3, 4, 6, 8][t];
        out.push(size === 8 ? Number(rec.readBigInt64BE(pos)) : rec.readIntBE(pos, size));
        pos += size;
      } else if (t === 7) { out.push(rec.readDoubleBE(pos)); pos += 8; }
      else if (t >= 12) {
        const len = t % 2 === 0 ? (t - 12) / 2 : (t - 13) / 2;
        out.push(t % 2 === 0 ? rec.subarray(pos, pos + len) : rec.toString("utf8", pos, pos + len));
        pos += len;
      } else throw new Error(`rpmdb: bad sqlite serial type ${t}`);
    }
    return out;
  };

  function* walk(pgno, depth = 0) {
    if (depth > 64) throw new Error("rpmdb: sqlite b-tree too deep");
    const p   = getPage(pgno);
    const h   = pgno === 1 ? 100 : 0;
    const typ = p[h];
    const n   = p.readUInt16BE(h + 3);

    if (typ === 0x0d) {                                // table leaf
      for (let i = 0; i < n; i++) {
        let pos = p.readUInt16BE(h + 8 + i * 2);
        const [total, a] = readVarint(p, pos); pos += a;
        const [rowid, b] = readVarint(p, pos); pos += b;
        yield { rowid, record: decodeRecord(cellPayload(p, pos, total)) };
      }
    } else if (typ === 0x05) {                         // table interior
      for (let i = 0; i < n; i++) {
        const pos = p.readUInt16BE(h + 12 + i * 2);
        yield* walk(p.readUInt32BE(pos), depth + 1);
      }
      yield* walk(p.readUInt32BE(h + 8), depth + 1);   // right-most child
    } else {
      throw new Error(`rpmdb: unexpected sqlite page type 0x${typ.toString(16)}`);
    }
  }

  // sqlite_master: [type, name, tbl_name, rootpage, sql]
  let root = 0;
  for (const { record } of walk(1)) {
    if (record[0] === "table" && record[1] === "Packages") { root = record[3]; break; }
  }
  if (!root) throw new Error("rpmdb: sqlite database has no Packages table");

  for (const { record } of walk(root)) {
    const blob = record[1];                            // [hnum (rowid alias → NULL), blob]
    if (Buffer.isBuffer(blob)) yield blob;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

// Where distros keep the rpmdb (Fedora/newer RHEL moved it to /usr/lib/sysimage/rpm).
const RPMDB_DIRS  = ["/var/lib/rpm", "/usr/lib/sysimage/rpm", "/usr/share/rpm"];
const RPMDB_FILES = ["rpmdb.sqlite", "Packages", "Packages.db"];

function detectFormat(file) {
  let head;
  try {
    const fd = fs.openSync(file, "r");
    try {
      head = Buffer.alloc(512);
      const n = fs.readSync(fd, head, 0, 512, 0);
      head = head.subarray(0, n);
    } finally { fs.closeSync(fd); }
  } catch { return null; }
  if (head.length < 16) return null;
  if (sqliteMagic(Buffer.concat([head, Buffer.alloc(100)]))) return "sqlite";
  if (bdbMagic(Buffer.concat([head, Buffer.alloc(512)])))    return "bdb";
  if (head.toString("latin1", 0, 4) === "RpmP")               return "ndb";
  return null;
}

export function findRpmDb(rootDir = "") {
  for (const dir of RPMDB_DIRS) {
    for (const f of RPMDB_FILES) {
      const full = rootDir ? path.join(rootDir, dir, f) : path.join(dir, f);
      try { if (!fs.statSync(full).isFile() || fs.statSync(full).size === 0) continue; } catch { continue; }
      const format = detectFormat(full);
      if (format) return { file: full, format };
    }
  }
  return null;
}

/**
 * Read every installed package from the rpm database.
 * @returns {Array<{name, version, license, requires: string[], files: {path, mode}[]}>}
 */
export function readRpmDb(rootDir = "") {
  const db = findRpmDb(rootDir);
  if (!db) {
    throw new Error(
      `rpmdb: no rpm database found${rootDir ? ` under ${rootDir}` : ""} ` +
      `(looked for ${RPMDB_FILES.join(", ")} in ${RPMDB_DIRS.join(", ")})`
    );
  }
  if (db.format === "ndb") {
    throw new Error(`rpmdb: ${db.file} is an NDB database (SUSE) — format not supported`);
  }

  const blobs = db.format === "sqlite"
    ? sqliteBlobs(db.file)
    : bdbHashBlobs(fs.readFileSync(db.file));

  const out = [];
  for (const blob of blobs) {
    const hdr = parseHeaderBlob(blob);
    if (!hdr) continue;
    const pkg = headerToPackage(hdr);
    if (pkg) out.push(pkg);
  }
  if (!out.length) throw new Error(`rpmdb: no packages decoded from ${db.file}`);
  return out;
}