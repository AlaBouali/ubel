'use strict';
// dex.js — Dalvik Executable reader (no decompiler): string/type/method/field tables, class definitions,
// static constant values (BuildConfig flags, `static final String` secrets) and a bytecode walker that
// tracks constant registers well enough to see what literal reaches a call such as
// Cipher.getInstance("DES/ECB/…"). Handles standard DEX (v035–v039); compact DEX is not supported.

const NO_INDEX = 0xffffffff;

// ── Dalvik instruction widths (in 16-bit code units) ───────────────────────────────────────────────
const OP_LEN = new Uint8Array(256).fill(1);
const setLen = (a, b, n) => { for (let i = a; i <= b; i++) OP_LEN[i] = n; };
setLen(0x02, 0x02, 2); setLen(0x03, 0x03, 3); setLen(0x05, 0x05, 2); setLen(0x06, 0x06, 3);
setLen(0x08, 0x08, 2); setLen(0x09, 0x09, 3); setLen(0x13, 0x13, 2); setLen(0x14, 0x14, 3);
setLen(0x15, 0x16, 2); setLen(0x17, 0x17, 3); setLen(0x18, 0x18, 5); setLen(0x19, 0x19, 2);
setLen(0x1a, 0x1a, 2); setLen(0x1b, 0x1b, 3); setLen(0x1c, 0x1c, 2); setLen(0x1f, 0x20, 2);
setLen(0x22, 0x23, 2); setLen(0x24, 0x26, 3); setLen(0x29, 0x29, 2); setLen(0x2a, 0x2c, 3);
setLen(0x2d, 0x3d, 2); setLen(0x44, 0x6d, 2); setLen(0x6e, 0x72, 3); setLen(0x74, 0x78, 3);
setLen(0x90, 0xaf, 2); setLen(0xd0, 0xe2, 2); setLen(0xfa, 0xfb, 4); setLen(0xfc, 0xfd, 3); setLen(0xfe, 0xff, 2);

// Which operand holds the destination register: 1 = vAA (high byte), 2 = vA (nibble), 3 = vAAAA (next unit)
const DEST = new Uint8Array(256);
const setDest = (a, b, k) => { for (let i = a; i <= b; i++) DEST[i] = k; };
setDest(0x01, 0x01, 2); setDest(0x04, 0x04, 2); setDest(0x07, 0x07, 2);
setDest(0x02, 0x02, 1); setDest(0x05, 0x05, 1); setDest(0x08, 0x08, 1);
setDest(0x03, 0x03, 3); setDest(0x06, 0x06, 3); setDest(0x09, 0x09, 3);
setDest(0x0a, 0x0d, 1); setDest(0x1c, 0x1c, 1); setDest(0x1f, 0x1f, 1);
setDest(0x20, 0x21, 2); setDest(0x22, 0x22, 1); setDest(0x23, 0x23, 2);
setDest(0x2d, 0x31, 1); setDest(0x44, 0x4a, 1); setDest(0x52, 0x58, 2); setDest(0x60, 0x66, 1);
setDest(0x7b, 0x8f, 2); setDest(0x90, 0xaf, 1); setDest(0xb0, 0xcf, 2); setDest(0xd0, 0xd7, 2);
setDest(0xd8, 0xe2, 1); setDest(0xfe, 0xff, 1);

function decodeMutf8(buf, s, e) {
  let ascii = true;
  for (let i = s; i < e; i++) if (buf[i] >= 0x80 || buf[i] === 0) { ascii = false; break; }
  if (ascii) return buf.latin1Slice(s, e);
  const units = [];
  let i = s;
  while (i < e) {
    const b = buf[i++];
    if (b < 0x80) units.push(b);
    else if ((b & 0xe0) === 0xc0) units.push(((b & 0x1f) << 6) | (buf[i++] & 0x3f));
    else if ((b & 0xf0) === 0xe0) { const b2 = buf[i++], b3 = buf[i++]; units.push(((b & 0x0f) << 12) | ((b2 & 0x3f) << 6) | (b3 & 0x3f)); }
    else units.push(0xfffd);
  }
  let out = '';
  for (let k = 0; k < units.length; k += 8192) out += String.fromCharCode.apply(null, units.slice(k, k + 8192));
  return out;
}

export function isDex(buf) { return buf.length > 0x70 && buf.toString('latin1', 0, 4) === 'dex\n'; }

export class Dex {
  constructor(buf, name = 'classes.dex') {
    if (!isDex(buf)) throw new Error('not a DEX file');
    if (buf.readUInt32LE(0x28) !== 0x12345678) throw new Error('unsupported DEX byte order');
    this.buf = buf; this.name = name;
    this.version = buf.toString('latin1', 4, 7);
    const u = o => buf.readUInt32LE(o);
    this.nStr = u(0x38); this.oStr = u(0x3c); this.nType = u(0x40); this.oType = u(0x44);
    this.nProto = u(0x48); this.oProto = u(0x4c); this.nField = u(0x50); this.oField = u(0x54); this.nMeth = u(0x58); this.oMeth = u(0x5c);
    this.nClass = u(0x60); this.oClass = u(0x64);
    const within = (o, n, sz) => o + n * sz <= buf.length;
    if (!within(this.oStr, this.nStr, 4) || !within(this.oType, this.nType, 4) || !within(this.oField, this.nField, 8) ||
        !within(this.oMeth, this.nMeth, 8) || !within(this.oProto, this.nProto, 12) || !within(this.oClass, this.nClass, 32)) throw new Error('corrupt DEX tables');
    this._str = new Array(this.nStr);
    this._mkey = new Array(this.nMeth);
  }

  string(i) {
    if (i < 0 || i >= this.nStr) return '';
    let s = this._str[i];
    if (s !== undefined) return s;
    const buf = this.buf;
    let p = buf.readUInt32LE(this.oStr + i * 4);
    if (p >= buf.length) return (this._str[i] = '');
    while (buf[p] & 0x80) p++;                       // skip the ULEB128 utf16 length
    p++;
    let e = buf.indexOf(0, p);
    if (e < 0) e = buf.length;
    return (this._str[i] = decodeMutf8(buf, p, e));
  }

  typeName(i) { return i === NO_INDEX || i >= this.nType ? '' : this.string(this.buf.readUInt32LE(this.oType + i * 4)); }

  fieldRef(i) {
    const o = this.oField + i * 8;
    return { cls: this.typeName(this.buf.readUInt16LE(o)), type: this.typeName(this.buf.readUInt16LE(o + 2)), name: this.string(this.buf.readUInt32LE(o + 4)) };
  }

  /** "Lcom/foo/Bar;->baz" for method id i. */
  methodKey(i) {
    let k = this._mkey[i];
    if (k !== undefined) return k;
    const o = this.oMeth + i * 8;
    return (this._mkey[i] = `${this.typeName(this.buf.readUInt16LE(o))}->${this.string(this.buf.readUInt32LE(o + 4))}`);
  }

  /** "Lcom/foo/Bar;->baz" for field id i (the `sget-*` / `iget-*` operand). */
  fieldKey(i) {
    if (i >= this.nField) return '';
    const o = this.oField + i * 8;
    return `${this.typeName(this.buf.readUInt16LE(o))}->${this.string(this.buf.readUInt32LE(o + 4))}`;
  }

  /** { ret, params:[type …] } of method id i, from the proto table (methodKey drops the signature). */
  methodProto(i) {
    if (i >= this.nMeth) return null;
    const pi = this.buf.readUInt16LE(this.oMeth + i * 8 + 2);
    if (pi >= this.nProto) return null;
    const po = this.oProto + pi * 12, buf = this.buf;
    const params = [];
    const off = buf.readUInt32LE(po + 8);
    if (off && off + 4 <= buf.length) {
      const n = buf.readUInt32LE(off);
      for (let k = 0; k < n && k < 32 && off + 4 + k * 2 + 2 <= buf.length; k++) params.push(this.typeName(buf.readUInt16LE(off + 4 + k * 2)));
    }
    return { ret: this.typeName(buf.readUInt32LE(po + 4)), params };
  }

  *allStrings() { for (let i = 0; i < this.nStr; i++) yield this.string(i); }

  *allFieldRefs() { for (let i = 0; i < this.nField; i++) yield this.fieldRef(i); }

  // ── classes ──────────────────────────────────────────────────────────────────────────────────────
  *classes() {
    const buf = this.buf;
    for (let k = 0; k < this.nClass; k++) {
      const o = this.oClass + k * 32;
      const def = {
        type: this.typeName(buf.readUInt32LE(o)), access: buf.readUInt32LE(o + 4),
        superType: this.typeName(buf.readUInt32LE(o + 8)), interfacesOff: buf.readUInt32LE(o + 12),
        classDataOff: buf.readUInt32LE(o + 24), staticValuesOff: buf.readUInt32LE(o + 28),
      };
      yield def;
    }
  }

  interfaces(def) {
    const off = def.interfacesOff;
    if (!off || off + 4 > this.buf.length) return [];
    const n = this.buf.readUInt32LE(off);
    const out = [];
    for (let i = 0; i < n && off + 4 + i * 2 + 2 <= this.buf.length; i++) out.push(this.typeName(this.buf.readUInt16LE(off + 4 + i * 2)));
    return out;
  }

  _uleb(p) {
    let result = 0, shift = 0, b;
    do { b = this.buf[p++]; result += (b & 0x7f) * 2 ** shift; shift += 7; } while ((b & 0x80) && shift < 35);
    this._p = p;
    return result;
  }

  /** { staticFields:[{idx}], methods:[{idx, codeOff}] } of a class definition. */
  classData(def) {
    if (!def.classDataOff || def.classDataOff >= this.buf.length) return { staticFields: [], methods: [] };
    let p = def.classDataOff;
    const sf = this._uleb(p); p = this._p; const inf = this._uleb(p); p = this._p;
    const dm = this._uleb(p); p = this._p; const vm = this._uleb(p); p = this._p;
    const staticFields = [];
    let idx = 0;
    for (let i = 0; i < sf; i++) { idx += this._uleb(p); p = this._p; this._uleb(p); p = this._p; staticFields.push({ idx }); }
    idx = 0;
    for (let i = 0; i < inf; i++) { this._uleb(p); p = this._p; this._uleb(p); p = this._p; }
    const methods = [];
    for (let group = 0; group < 2; group++) {
      idx = 0;
      const n = group === 0 ? dm : vm;
      for (let i = 0; i < n; i++) {
        idx += this._uleb(p); p = this._p;
        const access = this._uleb(p); p = this._p;
        const codeOff = this._uleb(p); p = this._p;
        methods.push({ idx, access, codeOff });
      }
    }
    return { staticFields, methods };
  }

  /** Static constants initialised in the class definition: [{ field, kind:'string'|'bool'|'int', value }]. */
  staticConstants(def, data = this.classData(def)) {
    if (!def.staticValuesOff || !data.staticFields.length || def.staticValuesOff >= this.buf.length) return [];
    const out = [];
    let p = def.staticValuesOff;
    const n = this._uleb(p); p = this._p;
    for (let i = 0; i < n; i++) {
      const r = this._value(p, 0);
      if (!r) break;
      p = r.p;
      const f = data.staticFields[i];
      if (f && r.kind) out.push({ field: this.fieldRef(f.idx).name, kind: r.kind, value: r.value });
    }
    return out;
  }

  _sized(p, n, signed) {
    let v = 0;
    for (let i = 0; i < n; i++) v += this.buf[p + i] * 2 ** (8 * i);
    if (signed && n < 7 && this.buf[p + n - 1] & 0x80) v -= 2 ** (8 * n);
    return v;
  }

  _value(p, depth) {
    if (depth > 8 || p >= this.buf.length) return null;
    const h = this.buf[p++], type = h & 0x1f, arg = h >> 5;
    const n = arg + 1;
    switch (type) {
      case 0x00: return { p: p + 1, kind: 'int', value: this._sized(p, 1, true) };
      case 0x02: return { p: p + n, kind: 'int', value: this._sized(p, n, true) };
      case 0x03: return { p: p + n, kind: 'int', value: this._sized(p, n, false) };
      case 0x04: return { p: p + n, kind: 'int', value: this._sized(p, n, true) };
      case 0x06: return { p: p + n, kind: 'int', value: this._sized(p, n, true) };
      case 0x10: case 0x11: return { p: p + n };
      case 0x15: case 0x16: case 0x18: case 0x19: case 0x1a: case 0x1b: return { p: p + n };
      case 0x17: return { p: p + n, kind: 'string', value: this.string(this._sized(p, n, false)) };
      case 0x1c: {
        const cnt = this._uleb(p); p = this._p;
        for (let i = 0; i < cnt; i++) { const r = this._value(p, depth + 1); if (!r) return null; p = r.p; }
        return { p };
      }
      case 0x1d: {
        this._uleb(p); p = this._p; const cnt = this._uleb(p); p = this._p;
        for (let i = 0; i < cnt; i++) { this._uleb(p); p = this._p; const r = this._value(p, depth + 1); if (!r) return null; p = r.p; }
        return { p };
      }
      case 0x1e: return { p };
      case 0x1f: return { p, kind: 'bool', value: arg === 1 };
      default: return null;
    }
  }

  // ── code ─────────────────────────────────────────────────────────────────────────────────────────
  /** 'return-void' | 'return-true' | 'return-false' | null — for tiny method bodies. */
  trivialKind(codeOff) {
    if (!codeOff || codeOff + 16 > this.buf.length) return null;
    const n = this.buf.readUInt32LE(codeOff + 12);
    if (n < 1 || n > 3 || codeOff + 16 + n * 2 > this.buf.length) return null;
    const U = i => this.buf.readUInt16LE(codeOff + 16 + i * 2);
    if (n === 1) return U(0) === 0x000e ? 'return-void' : null;
    const retOk = (u, reg) => (u & 0xff) === 0x0f && (u >> 8) === reg;
    if (n === 2 && (U(0) & 0xff) === 0x12) {                  // const/4 vA, #+B ; return vA
      const a = (U(0) >> 8) & 0xf, b = U(0) >> 12;
      if (retOk(U(1), a)) return b === 1 ? 'return-true' : b === 0 ? 'return-false' : null;
    }
    if (n === 3 && (U(0) & 0xff) === 0x13 && retOk(U(2), U(0) >> 8)) {  // const/16 vAA, #+BBBB ; return vAA
      return U(1) === 1 ? 'return-true' : U(1) === 0 ? 'return-false' : null;
    }
    return null;
  }

  /**
   * Linear walk of one method body. hooks.onInvoke(key, args) gets the callee ("Lcls;->name") and the
   * argument registers' known constants ({k:'str'|'int'|'bytes', v}) or undefined when unknown;
   * hooks.onString(idx) sees every const-string; hooks.onField(fieldIdx) sees every static field read (sget-*). onInvoke also gets the method index as a third argument. `watch` limits onInvoke to the keys in the Set.
   * Constant tracking is deliberately simple (straight-line, destination-killing): good precision for the
   * usual "load literal, call API" shape, silent when unsure.
   */
  walk(codeOff, hooks, watch) {
    const buf = this.buf;
    if (!codeOff || codeOff + 16 > buf.length) return;
    const size = buf.readUInt32LE(codeOff + 12), base = codeOff + 16;
    if (base + size * 2 > buf.length) return;
    const U = n => buf.readUInt16LE(base + n * 2);
    const regs = new Map();
    let pendingBytes = null;
    let i = 0;
    while (i < size) {
      const u0 = U(i), op = u0 & 0xff;
      const pb = pendingBytes; pendingBytes = null;
      if (op === 0x00 && u0 !== 0) {                           // switch / array payload pseudo-instructions
        let len = 1;
        if (u0 === 0x0100) len = U(i + 1) * 2 + 4;
        else if (u0 === 0x0200) len = U(i + 1) * 4 + 2;
        else if (u0 === 0x0300) len = Math.ceil((U(i + 1) * (U(i + 2) + U(i + 3) * 65536)) / 2) + 4;
        i += Math.max(1, len);
        continue;
      }
      const len = OP_LEN[op];
      if (i + len > size) break;
      if (op >= 0x12 && op <= 0x1b) {
        if (op === 0x12) { const b = u0 >> 12; regs.set((u0 >> 8) & 0xf, { k: 'int', v: b > 7 ? b - 16 : b }); }
        else if (op === 0x13) regs.set(u0 >> 8, { k: 'int', v: (U(i + 1) << 16) >> 16 });
        else if (op === 0x14) regs.set(u0 >> 8, { k: 'int', v: (U(i + 1) | (U(i + 2) << 16)) | 0 });
        else if (op === 0x15) regs.set(u0 >> 8, { k: 'int', v: U(i + 1) << 16 });
        else if (op >= 0x16 && op <= 0x19) { regs.delete(u0 >> 8); regs.delete((u0 >> 8) + 1); }
        else {
          const idx = op === 0x1a ? U(i + 1) : (U(i + 1) | (U(i + 2) << 16)) >>> 0;
          regs.set(u0 >> 8, { k: 'str', v: this.string(idx) });
          if (hooks.onString) hooks.onString(idx);
        }
      } else if (op >= 0x60 && op <= 0x66) {                   // sget-*: report the field, then it is an ordinary register kill
        if (hooks.onField) hooks.onField(U(i + 1));
        const r = u0 >> 8; regs.delete(r); regs.delete(r + 1);
      } else if (op === 0x0c && pb) {
        regs.set(u0 >> 8, pb);
      } else if ((op >= 0x6e && op <= 0x72) || (op >= 0x74 && op <= 0x78)) {
        const mIdx = U(i + 1);
        const key = mIdx < this.nMeth ? this.methodKey(mIdx) : '';
        const isString = key === 'Ljava/lang/String;->getBytes', isB64 = key === 'Landroid/util/Base64;->decode';
        if (isString || isB64 || (watch && watch.has(key))) {
          const args = [];
          if (op <= 0x72) {
            const count = u0 >> 12, u2 = U(i + 2);
            const list = [u2 & 0xf, (u2 >> 4) & 0xf, (u2 >> 8) & 0xf, (u2 >> 12) & 0xf, (u0 >> 8) & 0xf];
            for (let a = 0; a < count && a < 5; a++) args.push(regs.get(list[a]));
          } else {
            const count = u0 >> 8, first = U(i + 2);
            for (let a = 0; a < count && a < 8; a++) args.push(regs.get(first + a));
          }
          if ((isString || isB64) && args[0] && args[0].k === 'str') pendingBytes = { k: 'bytes', v: args[0].v };
          if (watch && watch.has(key) && hooks.onInvoke) hooks.onInvoke(key, args, mIdx);
        }
      } else {
        const d = DEST[op];
        if (d) {
          const r = d === 1 ? u0 >> 8 : d === 2 ? (u0 >> 8) & 0xf : U(i + 1);
          regs.delete(r); regs.delete(r + 1);
        }
      }
      i += len;
    }
  }
}
