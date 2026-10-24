'use strict';
// resilience.js — evidence of anti-debug / anti-emulator / root-detection logic ("RASP") in DEX code.
//
// One indicator on its own means nothing: Build.MODEL is read by every analytics SDK and "su" appears in unrelated strings. So a class is
// only reported when it combines at least MIN_INDICATORS *distinct* indicators. All Build.* property reads count as ONE indicator, so
// a device-info collector cannot reach the threshold on its own. Pure (no I/O): android.js feeds it calls, static field reads and string
// literals per class; inner classes (Foo$1) are folded into their outer class because guards are often split over helper classes.

export const MIN_INDICATORS = 3;

/** Callee keys that are indicators by themselves. */
export const RESILIENCE_CALLS = new Map([
  ['Landroid/os/Debug;->isDebuggerConnected', { cat: 'debugger', id: 'Debug.isDebuggerConnected' }],
  ['Landroid/os/Debug;->waitingForDebugger', { cat: 'debugger', id: 'Debug.waitingForDebugger' }],
]);
export const RUNTIME_EXEC = 'Ljava/lang/Runtime;->exec';

const BUILD_CLASS = 'Landroid/os/Build;';
const BUILD_PROPS = new Set(['FINGERPRINT', 'MODEL', 'MANUFACTURER', 'BRAND', 'DEVICE', 'PRODUCT', 'HARDWARE', 'BOARD', 'HOST']);

const EMULATOR = /goldfish|ranchu|\/dev\/qemu_pipe|\/dev\/socket\/(?:qemud|genyd|baseband_genyd)|ro\.kernel\.qemu|qemu\.sf\.lcd_density|vbox86p?|genymotion|bluestacks|google_sdk|sdk_gphone\w*|android sdk built for|ttVM_Hdragon/i;
const ROOT = /(?:^|\/)su$|\/system\/(?:x?bin)\/(?:su|busybox)|\/sbin\/su|\/su\/bin\/su|\/data\/local\/(?:x?bin\/)?su|superuser\.apk|com\.topjohnwu\.magisk|\bmagisk\b|supersu|eu\.chainfire|com\.noshufou\.android\.su|com\.koushikdutta\.superuser|com\.thirdparty\.superuser|test-keys|which su/i;
const HOOK = /\bTracerPid\b|\bfrida(?:-server|-agent|-gadget)?\b|gum-js-loop|\bgmain\b|\blinjector\b|re\.frida\.server|:27042\b|xposedbridge|de\.robv\.android\.xposed|com\.saurik\.substrate|\/proc\/self\/maps/i;

/** Classifies a string literal; null for prose and for anything that is not a recognisable indicator. */
export function classifyResilienceString(s) {
  if (typeof s !== 'string' || s.length < 2 || s.length > 100 || s.trim().split(/\s+/).length > 5) return null;
  let m = HOOK.exec(s);
  if (m) return { cat: /tracerpid/i.test(m[0]) ? 'debugger' : 'hook', id: m[0].toLowerCase() };
  m = EMULATOR.exec(s);
  if (m) return { cat: 'emulator', id: m[0].toLowerCase() };
  m = ROOT.exec(s);
  if (m) return { cat: 'root', id: m[0].toLowerCase() };
  return null;
}

const outerClass = t => String(t).replace(/\$.*$/, ';');

export class ResilienceCollector {
  constructor() { this.classes = new Map(); this._type = null; this._key = null; }
  /** Starts attributing indicators to the outer class of `type`. Nothing is allocated until the class records an indicator: nearly none do. */
  begin(type) { this._type = type; this._key = null; }
  _add(cat, id) {
    if (this._type === null) return;
    const key = this._key ??= outerClass(this._type);
    let c = this.classes.get(key);
    if (!c) this.classes.set(key, c = { ids: new Map() });
    if (!c.ids.has(id)) c.ids.set(id, cat);
  }
  call(key, args) {
    const c = RESILIENCE_CALLS.get(key);
    if (c) return this._add(c.cat, c.id);
    if (key === RUNTIME_EXEC) {
      const a = (args || []).find(x => x && x.k === 'str');
      // exec("su") runs the very literal the string pass already counted, so it shares that indicator's id: one check is one indicator
      if (a && /^(?:su\b|which su|\/system\/(?:x?bin)\/su)/.test(a.v)) { const s = classifyResilienceString(a.v); this._add('root', s && s.cat === 'root' ? s.id : 'su'); }
    }
  }
  /** key = "Landroid/os/Build;->MODEL" */
  field(key) {
    const i = key.indexOf('->');
    if (i < 0 || key.slice(0, i) !== BUILD_CLASS) return;
    const name = key.slice(i + 2);
    if (BUILD_PROPS.has(name)) this._add('emulator', 'Build.* properties');
    else if (name === 'TAGS') this._add('root', 'test-keys');          // Build.TAGS is read to compare it with "test-keys": same indicator as that literal
  }
  string(info) { if (info) this._add(info.cat, info.id); }

  /** @returns {{cls:string, indicators:string[], categories:string[], text:string}[]} classes that reach the threshold */
  results() {
    const out = [];
    for (const [cls, c] of this.classes) {
      if (c.ids.size < MIN_INDICATORS) continue;
      const byCat = new Map();
      for (const [id, cat] of c.ids) (byCat.get(cat) || byCat.set(cat, []).get(cat)).push(id);
      out.push({ cls, indicators: [...c.ids.keys()], categories: [...byCat.keys()].sort(),
        text: [...byCat].sort((a, b) => a[0].localeCompare(b[0])).map(([cat, ids]) => `${cat} (${ids.slice(0, 4).join(', ')})`).join('; ') });
    }
    return out;
  }
}
