'use strict';
// behavior.js — an inventory of what the code *does* (file access, network, IPC, processes, reflection, native code, sensitive device
// APIs), counted per API reference and split by class origin (app / unknown / library). It is not a list of findings: nearly every app does
// all of this, so the output is a summary on the app record (`app.behavior`), never a rule hit.
//
// Same mechanism as the call rules: the DEX walker reports an API reference, this module counts it. Implicit intents are read from the
// Intent(String …) constructor, whose first parameter type is checked in the DEX proto table, so Intent(Context, Class) is not mistaken
// for an action-based intent.

const CTX = ['Landroid/content/Context;', 'Landroid/content/ContextWrapper;', 'Landroid/app/Activity;', 'Landroid/app/Service;', 'Landroid/app/Application;'];

export const BEHAVIOR = new Map();           // callee key -> { cat, short }
const add = (cat, cls, methods) => {
  const simple = cls.replace(/^L|;$/g, '').split('/').pop().replace(/\$/g, '.');
  for (const m of methods) BEHAVIOR.set(`${cls}->${m}`, { cat, short: `${simple}.${m}` });
};
for (const c of ['Ljava/io/File;', 'Ljava/io/FileOutputStream;', 'Ljava/io/FileInputStream;', 'Ljava/io/FileWriter;', 'Ljava/io/FileReader;', 'Ljava/io/RandomAccessFile;']) add('file_io', c, ['<init>']);
add('file_io', 'Ljava/io/File;', ['delete']);
for (const c of CTX) add('file_io', c, ['openFileOutput', 'openFileInput', 'deleteFile']);
add('network', 'Ljava/net/URL;', ['<init>', 'openConnection', 'openStream']);
add('network', 'Ljava/net/URLConnection;', ['connect']);
add('network', 'Ljava/net/HttpURLConnection;', ['getResponseCode']);
add('network', 'Ljavax/net/ssl/HttpsURLConnection;', ['getResponseCode']);
for (const c of ['Ljava/net/Socket;', 'Ljava/net/ServerSocket;', 'Ljava/net/DatagramSocket;']) add('network', c, ['<init>']);
add('network', 'Lokhttp3/OkHttpClient;', ['newCall']);
add('network', 'Landroid/webkit/WebView;', ['loadUrl', 'loadDataWithBaseURL']);
for (const c of CTX) add('ipc', c, ['startActivity', 'startActivityForResult', 'startService', 'startForegroundService', 'bindService', 'sendBroadcast', 'sendOrderedBroadcast', 'registerReceiver']);
add('ipc', 'Landroid/content/Intent;', ['<init>', 'setAction']);
add('process', 'Ljava/lang/Runtime;', ['exec']);
add('process', 'Ljava/lang/ProcessBuilder;', ['<init>', 'start']);
add('reflection', 'Ljava/lang/Class;', ['forName', 'getDeclaredMethod', 'getMethod', 'getDeclaredField']);
add('reflection', 'Ljava/lang/reflect/Method;', ['invoke']);
add('reflection', 'Ljava/lang/ClassLoader;', ['loadClass']);
add('native_code', 'Ljava/lang/System;', ['loadLibrary', 'load']);
add('device_access', 'Landroid/location/LocationManager;', ['getLastKnownLocation', 'requestLocationUpdates']);
add('device_access', 'Lcom/google/android/gms/location/FusedLocationProviderClient;', ['getLastLocation', 'requestLocationUpdates']);
add('device_access', 'Landroid/hardware/Camera;', ['open']);
add('device_access', 'Landroid/hardware/camera2/CameraManager;', ['openCamera']);
add('device_access', 'Landroid/media/AudioRecord;', ['<init>']);
add('device_access', 'Landroid/media/MediaRecorder;', ['setAudioSource']);
add('device_access', 'Landroid/telephony/SmsManager;', ['sendTextMessage', 'sendMultipartTextMessage']);
add('device_access', 'Landroid/content/ClipboardManager;', ['getPrimaryClip', 'setPrimaryClip']);
add('device_access', 'Landroid/content/pm/PackageManager;', ['getInstalledPackages', 'getInstalledApplications']);

export const BEHAVIOR_LABELS = {
  file_io: 'File access', network: 'Network', ipc: 'Inter-app communication', process: 'Process execution', reflection: 'Reflection / dynamic lookup',
  native_code: 'Native code loading', device_access: 'Sensitive device APIs',
};
const ORIGINS = ['app', 'unknown', 'library'];
const INTENT_INIT = 'Landroid/content/Intent;-><init>', INTENT_SET_ACTION = 'Landroid/content/Intent;->setAction';
const MAX_APIS = 40, MAX_ACTIONS = 100;
const strArg = a => (a && a.k === 'str' ? a.v : null);

export class BehaviorCollector {
  constructor() { this.cats = {}; this.actions = { app: new Map(), unknown: new Map(), library: new Map() }; this.explicit = { app: 0, unknown: 0, library: 0 }; }

  /** @param {string} key callee  @param {any[]} args  @param {'app'|'unknown'|'library'} origin  @param {()=>({params:string[]}|null)} [proto] lazily reads the callee's proto */
  call(key, args, origin, proto) {
    const b = BEHAVIOR.get(key);
    if (!b) return;
    const o = ORIGINS.includes(origin) ? origin : 'app';
    let short = b.short;
    if (key === INTENT_INIT) {
      const p = proto ? proto() : null;
      if (p && p.params[0] === 'Ljava/lang/String;') {                       // Intent(String action[, Uri]) — an action-based (implicit) intent
        short = 'Intent.<init>(action)';
        const action = strArg(args[1]);
        if (action) this._action(o, action);
      } else if (p && p.params[0] === 'Landroid/content/Context;') { this.explicit[o]++; short = 'Intent.<init>(Context, Class)'; }
    } else if (key === INTENT_SET_ACTION) { const action = strArg(args[1]); if (action) this._action(o, action); }
    const c = ((this.cats[b.cat] ||= {})[o] ||= { total: 0, apis: new Map() });
    c.total++;
    c.apis.set(short, (c.apis.get(short) || 0) + 1);
  }
  _action(o, a) { const m = this.actions[o]; if (a.length <= 200) m.set(a, (m.get(a) || 0) + 1); }

  summary() {
    const categories = {};
    for (const cat of Object.keys(BEHAVIOR_LABELS)) {
      if (!this.cats[cat]) continue;
      categories[cat] = {};
      for (const o of ORIGINS) {
        const c = this.cats[cat][o];
        if (c) categories[cat][o] = { calls: c.total, apis: Object.fromEntries([...c.apis].sort((x, y) => y[1] - x[1] || x[0].localeCompare(y[0])).slice(0, MAX_APIS)) };
      }
    }
    const intent_actions = {};
    for (const o of ORIGINS) intent_actions[o] = [...this.actions[o].keys()].sort().slice(0, MAX_ACTIONS);
    return { categories, intent_actions, intent_actions_total: Object.fromEntries(ORIGINS.map(o => [o, this.actions[o].size])), explicit_intents: { ...this.explicit } };
  }
}

/** Folds the behavior summary of another bundle module into the base module's summary (counts add up, action lists are unioned). */
export function mergeBehavior(a, b) {
  if (!a) return b || null;
  if (!b) return a;
  const out = { categories: {}, intent_actions: {}, intent_actions_total: {}, explicit_intents: {} };
  for (const cat of new Set([...Object.keys(a.categories), ...Object.keys(b.categories)])) {
    out.categories[cat] = {};
    for (const o of ORIGINS) {
      const x = a.categories[cat]?.[o], y = b.categories[cat]?.[o];
      if (!x && !y) continue;
      const apis = { ...(x?.apis || {}) };
      for (const [k, n] of Object.entries(y?.apis || {})) apis[k] = (apis[k] || 0) + n;
      out.categories[cat][o] = { calls: (x?.calls || 0) + (y?.calls || 0), apis: Object.fromEntries(Object.entries(apis).sort((p, q) => q[1] - p[1] || p[0].localeCompare(q[0])).slice(0, MAX_APIS)) };
    }
  }
  for (const o of ORIGINS) {
    const all = [...new Set([...(a.intent_actions[o] || []), ...(b.intent_actions[o] || [])])].sort();
    out.intent_actions[o] = all.slice(0, MAX_ACTIONS);
    out.intent_actions_total[o] = Math.max(all.length, a.intent_actions_total?.[o] || 0, b.intent_actions_total?.[o] || 0);   // lower bound: lists are capped
    out.explicit_intents[o] = (a.explicit_intents?.[o] || 0) + (b.explicit_intents?.[o] || 0);
  }
  return out;
}
