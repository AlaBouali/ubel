'use strict';
// xml.js — a tolerant XML reader for .nuspec and MSBuild (.targets / .props / .csproj) files. Elements, attributes, text, CDATA and comments;
// no DTDs, no entities beyond the five predefined ones (so there is no entity-expansion attack surface), namespaces are ignored (`nu:id` → `id`).

const ENT = { '&lt;': '<', '&gt;': '>', '&amp;': '&', '&quot;': '"', '&apos;': "'" };
const decode = s => s.replace(/&(?:lt|gt|amp|quot|apos);/g, m => ENT[m]).replace(/&#(\d+);/g, (m, n) => { try { return String.fromCodePoint(Number(n)); } catch { return m; } }).replace(/&#x([0-9a-f]+);/gi, (m, n) => { try { return String.fromCodePoint(parseInt(n, 16)); } catch { return m; } });
const local = n => n.replace(/^.*:/, '');

/** @returns {{name:string, attrs:Record<string,string>, children:object[], text:string}|null} the root element */
export function parseXml(text) {
  const s = String(text).replace(/^﻿/, '');
  const root = { name: '#root', attrs: {}, children: [], text: '' };
  const stack = [root];
  let i = 0, nodes = 0;
  while (i < s.length) {
    const lt = s.indexOf('<', i);
    const top = stack[stack.length - 1];
    if (lt < 0) { top.text += decode(s.slice(i)); break; }
    if (lt > i) top.text += decode(s.slice(i, lt));
    if (s.startsWith('<!--', lt)) { const e = s.indexOf('-->', lt + 4); i = e < 0 ? s.length : e + 3; continue; }
    if (s.startsWith('<![CDATA[', lt)) { const e = s.indexOf(']]>', lt + 9); top.text += s.slice(lt + 9, e < 0 ? s.length : e); i = e < 0 ? s.length : e + 3; continue; }
    if (s[lt + 1] === '?' || s[lt + 1] === '!') { const e = s.indexOf('>', lt); i = e < 0 ? s.length : e + 1; continue; }
    if (s[lt + 1] === '/') {
      const e = s.indexOf('>', lt); i = e < 0 ? s.length : e + 1;
      const name = local(s.slice(lt + 2, e < 0 ? s.length : e).trim());
      for (let k = stack.length - 1; k > 0; k--) if (stack[k].name === name) { stack.length = k; break; }
      continue;
    }
    // open tag: read to the closing `>` honouring quotes
    let j = lt + 1, q = null;
    while (j < s.length) { const c = s[j]; if (q) { if (c === q) q = null; } else if (c === '"' || c === "'") q = c; else if (c === '>') break; j++; }
    let inner = s.slice(lt + 1, j);
    const self = inner.endsWith('/');
    if (self) inner = inner.slice(0, -1);
    const nm = /^[^\s/>]+/.exec(inner);
    i = j + 1;
    if (!nm) continue;
    const attrs = {};
    for (const m of inner.slice(nm[0].length).matchAll(/([^\s=]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g)) {
      const k = local(m[1]);
      if (k === '__proto__' || k === 'constructor') continue;
      attrs[k] = decode(m[2] ?? m[3] ?? '');
    }
    if (++nodes > 200000) break;
    const el = { name: local(nm[0]), attrs, children: [], text: '' };
    top.children.push(el);
    if (!self) { stack.push(el); if (stack.length > 200) break; }
  }
  return root.children[0] || null;
}

/** All descendants (depth-first) with the given local name (case-insensitive). */
export function findAll(el, name, out = []) {
  if (!el) return out;
  const n = name.toLowerCase();
  for (const c of el.children) { if (c.name.toLowerCase() === n) out.push(c); findAll(c, name, out); }
  return out;
}
export const childText = (el, name) => el?.children.find(c => c.name.toLowerCase() === name.toLowerCase())?.text.trim() || null;
