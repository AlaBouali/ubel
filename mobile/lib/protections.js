'use strict';
// protections.js — names the protection / obfuscation tooling an Android package was built with (the part of APKiD that matters for a
// review): packers and protectors, identifier renaming (ProGuard / R8 / Redex), and resource-path obfuscation (Redex, AndResGuard).
// Everything is a heuristic over file names, resource layout and DEX class names; each detection carries a confidence and its evidence,
// and a packer is the only kind that means part of the code could not be analysed.

/** Packers / protectors recognised by the files they ship. [name, regex on the entry path]. */
const PACKERS = [
  ['Bangcle / SecNeo',        /(^|\/)(libsecexe|libsecmain|libSecShell(-x86)?|libDexHelper(-x86)?)\.so$|(^|\/)(bangcle[^/]*|secData0\.jar)$/i],
  ['Qihoo 360 Jiagu',         /(^|\/)(libjiagu(_a64|_x86|_x64|_64)?|libprotectClass(_64)?|libjgdtc)\.so$/i],
  ['Tencent Legu',            /(^|\/)(libshella-[\d.]+|libshellx-[\d.]+|libtosprotection[^/]*|libtup)\.so$|(^|\/)(mix|mixz)\.dex$/i],
  ['Ijiami',                  /(^|\/)(libexec|libexecmain)\.so$|(^|\/)ijiami\.(dat|ajm)$/i],
  ['Baidu Protect',           /(^|\/)libbaiduprotect\.so$|(^|\/)baiduprotect[^/]*\.jar$/i],
  ['Alibaba Mobile Security', /(^|\/)libmobisec\.so$|(^|\/)aliprotect\.dat$/i],
  ['NetEase Yidun',           /(^|\/)libnesec\.so$/i],
  ['Payegis',                 /(^|\/)(libegis|libNSaferOnly)\.so$/i],
  ['Kiwisec',                 /(^|\/)(libkwscmm|libkwslinker)\.so$/i],
  ['APKProtect',              /(^|\/)libAPKProtect\.so$|(^|\/)apkprotect[^/]*\.dex$/i],
  ['DexProtector',            /(^|\/)libdexprotector[^/]*\.so$|(^|\/)assets\/dp\.[a-z0-9_.]+\.dat$|(^|\/)dpboot\.[^/]*$/i],
  ['Promon SHIELD',           /(^|\/)libshield\.so$/i],
  ['AppSealing',              /(^|\/)libcovault-appsec\.so$/i],
];

const STD_RES_DIR = /^res\/(anim|animator|color|drawable|font|interpolator|layout|menu|mipmap|navigation|raw|transition|xml)(-[^/]+)?\//i;

const REDEX_ASSET = /^assets\/secondary-program-dex-jars\//i;

/** Class-name signals gathered across the DEX files of one package. */
export class DexProtectionCollector {
  constructor() { this.total = 0; this.short = 0; this.redexClasses = []; this.r8Synthetic = 0; this.xPackage = 0; }
  add(dex) {
    for (const def of dex.classes()) {
      const t = def.type;
      this.total++;
      const slash = t.lastIndexOf('/');
      const simple = t.slice(slash + 1, -1).split('$')[0];
      if (simple.length <= 2) this.short++;
      if (t.startsWith('Lcom/facebook/redex/') || t.startsWith('Lredex/')) { if (this.redexClasses.length < 5) this.redexClasses.push(t.slice(1, -1).replace(/\//g, '.')); }
      else if (t.startsWith('LX/')) this.xPackage++;
      if (t.includes('R8$$SyntheticClass') || t.includes('$$ExternalSynthetic')) this.r8Synthetic++;
    }
  }
}

/**
 * @param {{entries:Array<{name:string,isDir?:boolean}>}} zip
 * @param {DexProtectionCollector|null} dex
 * @returns {Array<{name:string, kind:'packer'|'obfuscator'|'resource-obfuscator'|'compiler', confidence:'high'|'medium'|'low', evidence:string[], note?:string}>}
 */
export function detectProtections(zip, dex = null) {
  const out = [];
  const files = zip.entries.filter(e => !e.isDir).map(e => e.name);

  // packers / protectors
  for (const [name, re] of PACKERS) {
    const hits = files.filter(f => re.test(f));
    if (hits.length) out.push({ name, kind: 'packer', confidence: 'high', evidence: hits.slice(0, 6), note: 'The original code is decrypted at runtime; the DEX in the package is mostly a loader stub, so the code analysis covers only the stub.' });
  }
  const assetDex = files.filter(f => /^assets\/.+\.(dex|odex)$/i.test(f) && !REDEX_ASSET.test(f));
  if (assetDex.length && !out.some(p => p.kind === 'packer')) out.push({ name: 'DEX payload in assets', kind: 'packer', confidence: 'low', evidence: assetDex.slice(0, 6), note: 'Code shipped as a separate asset is loaded at runtime (a packer, a plugin framework or a dynamic-feature loader) and is not part of the DEX analysis.' });

  // resource-path obfuscation
  const res = files.filter(f => /^res\//i.test(f) && !/^res\/raw[^/]*\//i.test(f));
  const rRoot = files.filter(f => /^r\/./.test(f));
  const nonStd = res.filter(f => !STD_RES_DIR.test(f));
  const redexAsset = files.filter(f => REDEX_ASSET.test(f));
  const redexDex = dex && (dex.redexClasses.length > 0);
  const redexX = dex && dex.xPackage >= 20;
  const redexSignals = [...(redexDex ? [`class ${dex.redexClasses[0]}`] : []), ...(redexAsset.length ? [redexAsset[0]] : []), ...(redexX ? [`${dex.xPackage} classes in the X/ package`] : [])];
  const flatRenamed = res.length >= 8 && nonStd.length / res.length >= 0.5;
  const andResGuard = rRoot.length >= 5 && rRoot.length >= res.length;
  if (andResGuard) out.push({ name: 'AndResGuard (resource obfuscation)', kind: 'resource-obfuscator', confidence: 'medium', evidence: rRoot.slice(0, 5), note: 'Resources live under r/ with renamed paths, so files must be identified by content (root element), not by name.' });
  else if (flatRenamed) {
    const redex = redexSignals.length > 0;
    out.push({ name: redex ? (redexDex ? 'Redex (resource path renaming)' : 'Redex-style resource path renaming') : 'Resource path renaming (Redex / AndResGuard style)', kind: 'resource-obfuscator', confidence: redexDex ? 'high' : 'medium',
      evidence: [...nonStd.slice(0, 5), ...redexSignals].slice(0, 8),
      note: `${nonStd.length} of ${res.length} resource files sit outside the standard res/<type>/ directories, so they are identified by content (root element), not by path.` });
  }

  // identifier renaming / compiler
  if (dex && dex.total >= 50) {
    const ratio = dex.short / dex.total;
    const renamed = ratio >= 0.4;
    if (redexSignals.length && !out.some(p => p.name.startsWith('Redex'))) out.push({ name: 'Redex', kind: 'obfuscator', confidence: redexDex ? 'high' : 'medium', evidence: redexSignals });
    if (renamed) out.push({ name: redexSignals.length ? 'Identifier renaming (Redex / ProGuard / R8)' : 'Identifier renaming (ProGuard / R8)', kind: 'obfuscator', confidence: 'medium',
      evidence: [`${dex.short} of ${dex.total} classes (${Math.round(ratio * 100)}%) have a 1–2 character name`] });
    if (dex.r8Synthetic > 0) out.push({ name: 'D8 / R8 compiler', kind: 'compiler', confidence: 'medium', evidence: [`${dex.r8Synthetic} synthetic classes ($$ExternalSynthetic / R8$$SyntheticClass)`] });
  } else if (redexSignals.length && !out.some(p => p.name.startsWith('Redex'))) out.push({ name: 'Redex', kind: 'obfuscator', confidence: 'medium', evidence: redexSignals });
  return out;
}
