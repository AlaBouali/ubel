'use strict';
// inspector.js — live inspection of a running Node.js process through its own V8 inspector (the Chrome DevTools Protocol).
//
// What it does, in order:
//   1. Safety checks. The process must be Node.js, owned by us (or we are root), and it must have a SIGUSR1 handler installed
//      (SigCgt in /proc/<pid>/status). A process without one would be TERMINATED by SIGUSR1, so it is never signalled.
//   2. If no inspector is listening yet, sends SIGUSR1 — the documented way to start the inspector of a running Node.js process —
//      and watches the process's own sockets for the port that appears (it is not assumed to be 9229).
//   3. Connects to 127.0.0.1:<port>, enables the Debugger domain only long enough for V8 to replay Debugger.scriptParsed for every
//      script it has already compiled (CommonJS *and* ES modules — the authoritative "what code is loaded" list), and evaluates one
//      read-only expression that returns process.versions, execArgv and the list of loaded built-in modules. Nothing is paused,
//      modified or written, and no environment value is read.
//   4. If WE opened the inspector, closes it again (process._debugEnd) and checks that the port is gone. An inspector that was
//      already open (--inspect) is left as it was.
//
// This executes one expression inside the target process, which is why it is opt-in (--inspect) and local only.

import http from 'node:http';
import { wsConnect, Cdp } from './ws.js';
import { isNodeExe } from './util.js';
import { signalSet, isLoopbackAddr, isAnyAddr } from './procfs.js';

const SIGUSR1 = 10;
const MAX_SCRIPTS = 100000;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** --inspect[=[host:]port] / --inspect-brk / --inspect-wait / --inspect-port on the command line or in NODE_OPTIONS. */
export function explicitInspector(proc, env) {
  const nodeOptions = env ? (env.find(([k]) => k === 'NODE_OPTIONS') || [null, ''])[1] : '';
  const args = [...(proc.cmdline || []).slice(1), ...String(nodeOptions || '').split(/\s+/).filter(Boolean)];
  let found = null, port = null, host = null;
  for (const a of args) {
    const m = a.match(/^--inspect(?:-brk|-wait)?(?:=(.*))?$/);
    if (m) { found = a.split('=')[0]; if (m[1]) { const hp = m[1].match(/^(?:\[?([^\]]*?)\]?:)?(\d+)$/); if (hp) { host = hp[1] || null; port = Number(hp[2]); } else host = m[1]; } }
    const p = a.match(/^--inspect-port=(?:(.*):)?(\d+)$/);
    if (p) { host = p[1] || host; port = Number(p[2]); }
    if (a === '--') break;
  }
  return found ? { flag: found, host: host || '127.0.0.1', port: port === null ? 9229 : port, wildcard: !!host && (host === '0.0.0.0' || host === '::' || host === '[::]') } : null;
}

function getJson(host, port, path, timeout = 3000) {
  return new Promise((resolve, reject) => {
    const req = http.get({ host, port, path, timeout, headers: { Host: `${host}:${port}` } }, (res) => {
      let b = ''; res.on('data', (d) => { b += d; if (b.length > 1e6) req.destroy(new Error('response too large')); });
      res.on('end', () => { try { resolve(JSON.parse(b)); } catch (e) { reject(new Error('inspector returned invalid JSON')); } });
    });
    req.on('timeout', () => req.destroy(new Error('timed out')));
    req.on('error', reject);
  });
}

// V8 only replays the scripts that are still alive, and the Script of a CommonJS module that finished loading can already be collected — so the
// CommonJS module cache (read-only: its keys) is read as well; the two lists together cover CommonJS and ES modules.
const SUMMARY_EXPR = `(function(){try{var p=process;var cjs=[];try{var M=(p.getBuiltinModule&&p.getBuiltinModule('module'))||(p.mainModule&&p.mainModule.constructor);cjs=Object.keys((M&&M._cache)||{}).slice(0,20000)}catch(e){}var l=(p.moduleLoadList||[]).filter(function(x){return x.indexOf('NativeModule ')===0}).map(function(x){return x.slice(13)});
return JSON.stringify({version:p.version,versions:p.versions,execArgv:p.execArgv,title:p.title,platform:p.platform,arch:p.arch,uptime:p.uptime(),cwd:p.cwd(),
nodeOptions:(p.env.NODE_OPTIONS||null),builtins:l,permissionModel:!!p.permission,cjs:cjs})}catch(e){return JSON.stringify({error:String(e&&e.message)})}})()`;

/**
 * @param {object} ctx   RuntimeContext (procs: ProcFs)
 * @param {object} proc  a process from ProcFs.process()
 * @returns {Promise<{ok:true, port:number, opened:boolean, leftOpen:boolean, node:object, scripts:{url:string,module:boolean}[]} | {ok:false, reason:string}>}
 */
export async function inspectNode(ctx, proc, { timeoutMs = 8000, log = () => {} } = {}) {
  const fail = (reason) => ({ ok: false, reason });
  if (!isNodeExe(proc)) return fail('not a Node.js process');
  const me = typeof process.getuid === 'function' ? process.getuid() : null;
  if (me !== 0 && me !== proc.uid) return fail(`the process belongs to uid ${proc.uid}; run ubel-runtime as that user or as root`);
  const env = ctx.procs.environ(proc.pid);
  const explicit = explicitInspector(proc, env);
  const own = () => ctx.procs.listenersOf(proc);
  const isInspectorPort = (l) => (explicit && explicit.port ? l.port === explicit.port : (l.port >= 9229 && l.port <= 9300));
  let before = own();
  let insp = before.find(isInspectorPort) || null;
  let opened = false;

  if (!insp) {
    if (/--disable-sigusr1/.test(`${(proc.cmdline || []).join(' ')} ${env ? (env.find(([k]) => k === 'NODE_OPTIONS') || [0, ''])[1] : ''}`)) return fail('started with --disable-sigusr1: the inspector cannot be opened with a signal');
    if (signalSet(proc.sigCgt, SIGUSR1) !== true) return fail('the process has no SIGUSR1 handler, so a SIGUSR1 would terminate it — it was not signalled (start it with --inspect, or leave it uninspected)');
    try { process.kill(proc.pid, 'SIGUSR1'); } catch (e) { return fail(`could not signal pid ${proc.pid}: ${e.code || e.message}`); }
    opened = true;
    log(`  pid ${proc.pid}: SIGUSR1 sent, waiting for the inspector port`);
    const seen = new Set(before.map((l) => l.port));
    for (let t = 0; t < 40 && !insp; t++) {
      await sleep(100);
      insp = own().find((l) => !seen.has(l.port) && (isLoopbackAddr(l.addr) || isAnyAddr(l.addr))) || null;
    }
    if (!insp) return fail('the process did not open an inspector port within 4 s (the application may handle SIGUSR1 itself, or run with --disable-sigusr1)');
  }

  const host = isLoopbackAddr(insp.addr) || isAnyAddr(insp.addr) ? '127.0.0.1' : insp.addr;
  let cdp = null;
  try {
    const list = await getJson(host, insp.port, '/json/list');
    const t = Array.isArray(list) && list.find((x) => x.webSocketDebuggerUrl);
    if (!t) throw new Error('the inspector listed no debuggable target');
    const wsUrl = t.webSocketDebuggerUrl.replace(/^ws:\/\/[^/]+/, `ws://${host}:${insp.port}`);
    cdp = new Cdp(await wsConnect(wsUrl, { timeout: 4000 }));
    const scripts = [];
    cdp.on('Debugger.scriptParsed', (p) => { if (scripts.length < MAX_SCRIPTS) scripts.push({ url: p.url || '', module: !!p.isModule }); });
    await cdp.call('Debugger.enable', {}, timeoutMs);
    await sleep(200);                                                                // V8 replays scriptParsed for existing scripts around the response
    await cdp.call('Debugger.disable', {}, 3000).catch(() => {});
    const ev = await cdp.call('Runtime.evaluate', { expression: SUMMARY_EXPR, returnByValue: true, timeout: 3000 }, timeoutMs);
    let node = {};
    try { node = JSON.parse(ev.result && ev.result.value); } catch { /* summary unavailable: scripts are still useful */ }
    if (node.error) node = {};
    if (Array.isArray(node.cjs)) {
      const have = new Set(scripts.map((x) => x.url));
      for (const f of node.cjs) if (typeof f === 'string' && f.startsWith('/') && !have.has(f) && scripts.length < MAX_SCRIPTS) scripts.push({ url: f, module: false });
      delete node.cjs;
    }
    let leftOpen = false;
    if (opened) {
      await cdp.call('Runtime.evaluate', { expression: "typeof process._debugEnd==='function'&&(setImmediate(function(){process._debugEnd()}),true)", returnByValue: true }, 3000).catch(() => {});
      cdp.close(); cdp = null;
      for (let t = 0; t < 20; t++) { await sleep(100); if (!own().some((l) => l.port === insp.port)) break; }
      leftOpen = own().some((l) => l.port === insp.port);
    }
    return { ok: true, port: insp.port, opened, leftOpen, node, scripts };
  } catch (e) {
    return fail(`inspector session failed: ${e.message}${opened ? ' (the inspector this scan opened may still be listening on port ' + insp.port + ')' : ''}`);
  } finally { if (cdp) { try { cdp.close(); } catch { /* ignore */ } } }
}
