'use strict';
// context.js — the lazily evaluated view of the running machine that ubel-runtime's rules read from.
//
// Everything comes from /proc, the application's files on disk (node_modules, package.json) and, only when asked for, the local
// container engine socket, a loopback HTTP probe and the Node.js inspector. Each accessor is memoised, so a rule that needs the
// listener table or the npm advisory lookup asks for it and every other rule shares the result. Nothing is executed or changed.

import fs from 'node:fs';
import path from 'node:path';
import { ProcFs } from './procfs.js';
import { isNodeExe, scriptOf, procLabel, baseName, mapLimit } from './util.js';
import { findProjectRoot, readInstalledPackages, readRootPackage, packagesFromScripts } from './components.js';
import { listContainers } from './docker.js';
import { inspectNode } from './inspector.js';
import { probeListeners } from './probe.js';

const SYSTEM_LIB = /^\/(?:usr\/)?(?:lib|lib32|lib64|libx32|libexec)\/|^\/usr\/lib\//;
const MAX_EXE_MB = 512;

export class RuntimeContext {
  /**
   * @param {object} o
   * @param {string} [o.procRoot]        procfs directory (tests point it at a fixture)
   * @param {number[]} [o.pids] @param {string[]} [o.names] @param {boolean} [o.nodeOnly] @param {boolean} [o.includeSelf]
   * @param {'app'|'all'|'none'} [o.libs] @param {number} [o.maxLibs]
   * @param {boolean} [o.inspect] @param {boolean} [o.probe] @param {boolean} [o.noLookups] @param {boolean} [o.threatIntel]
   * @param {(m:string)=>void} [o.log]
   */
  constructor(o = {}) {
    this.opts = { libs: 'app', maxLibs: 150, threatIntel: true, ...o };
    this.log = o.log || (() => {});
    this.procs = new ProcFs({ root: o.procRoot || '/proc' });
    this.notes = [];
    this.inspections = new Map();            // pid → result of inspectNode()
    this._memo = new Map();
    this.selfMnt = null;
    try { this.selfMnt = fs.readlinkSync(path.join(this.procs.root, 'self', 'ns', 'mnt')).match(/\[(\d+)\]/)?.[1] ?? null; } catch { /* no namespace info */ }
  }

  memo(key, fn) { if (!this._memo.has(key)) this._memo.set(key, fn()); return this._memo.get(key); }
  get live() { return this.procs.supported(); }

  // ── processes ──────────────────────────────────────────────────────────────
  get allProcesses() { return this.memo('all', () => this.procs.processes()); }

  matchesName(p, names) {
    const hay = `${p.comm || ''}\n${baseName(p.exe)}\n${p.cmdline.join(' ')}`.toLowerCase();
    return names.some((n) => { const m = n.match(/^\/(.+)\/([a-z]*)$/); if (m) { try { return new RegExp(m[1], m[2]).test(hay); } catch { return false; } } return hay.includes(n.toLowerCase()); });
  }

  /** The processes under assessment: user-space processes, minus this scanner, narrowed by --pid / --name / --node-only. */
  get targets() {
    return this.memo('targets', () => {
      const o = this.opts;
      return this.allProcesses.filter((p) => {
        if (p.kernelThread) return false;
        if (!o.includeSelf && p.pid === process.pid) return false;
        if (o.pids && o.pids.length && !o.pids.includes(p.pid)) return false;
        if (o.names && o.names.length && !this.matchesName(p, o.names)) return false;
        if (o.nodeOnly && !isNodeExe(p)) return false;
        return true;
      });
    });
  }
  get nodeTargets() { return this.memo('node', () => this.targets.filter(isNodeExe)); }
  get targetPids() { return this.memo('tpids', () => new Set(this.targets.map((p) => p.pid))); }
  byPid(pid) { return this.allProcesses.find((p) => p.pid === pid) || null; }

  /** A path as the process sees it → a path this scanner can open (through /proc/<pid>/root for another mount namespace). */
  fsPath(proc, p) {
    if (!proc || !proc.ns.mnt || !this.selfMnt || proc.ns.mnt === this.selfMnt) return p;
    return path.join(this.procs.root, String(proc.pid), 'root', p);
  }

  // ── sockets ────────────────────────────────────────────────────────────────
  get listeners() { return this.memo('listeners', () => this.procs.listeners(this.allProcesses)); }
  get targetListeners() { return this.listeners.filter((l) => l.pid != null && this.targetPids.has(l.pid)); }
  get orphanListeners() { return this.listeners.filter((l) => l.pid == null); }           // sockets whose owner could not be identified (other users' processes)
  connectionsOf(proc) { return this.memo(`conn:${proc.pid}`, () => this.procs.connections(proc)); }
  mapsOf(proc) { return this.memo(`maps:${proc.pid}`, () => this.procs.maps(proc.pid)); }
  environOf(proc) { return this.memo(`env:${proc.pid}`, () => this.procs.environ(proc.pid)); }

  // ── containers ─────────────────────────────────────────────────────────────
  containers() { return this.memo('containers', () => listContainers()); }

  // ── live inspection (--inspect) ────────────────────────────────────────────
  async runInspections() {
    if (!this.opts.inspect) return;
    const nodes = this.nodeTargets.slice(0, this.opts.inspectMax || 25);
    if (this.nodeTargets.length > nodes.length) this.notes.push(`Live inspection covered the first ${nodes.length} of ${this.nodeTargets.length} Node.js processes (--inspect-max).`);
    for (const p of nodes) {
      this.log(`  inspecting pid ${p.pid} (${procLabel(p)})`);
      this.inspections.set(p.pid, await inspectNode(this, p, { log: this.log }));
    }
  }
  inspectionOf(proc) { return this.inspections.get(proc.pid) || null; }

  // ── Node.js applications ───────────────────────────────────────────────────
  /** Project, installed packages and (when inspected) loaded packages of one Node.js process. Shared between processes of the same project. */
  appOf(proc) {
    const script = scriptOf(proc);
    const fsPath = (x) => this.fsPath(proc, x);
    const root = findProjectRoot([script && script.startsWith('/') ? script : null, proc.cwd], fsPath);
    const key = `app:${proc.ns.mnt || ''}:${root}`;
    const base = root ? this.memo(key, () => ({ root, rootPackage: readRootPackage(root, fsPath), installed: readInstalledPackages(root, fsPath) })) : null;
    const insp = this.inspectionOf(proc);
    const loaded = insp && insp.ok ? this.memo(`loaded:${proc.pid}`, () => packagesFromScripts(insp.scripts, fsPath)) : null;
    return { script, root, ...(base || {}), loaded };
  }

  /** Every distinct npm package installed under the Node.js applications in scope, looked up once. */
  npmAdvisories() {
    return this.memo('npm-adv', async () => {
      const pkgs = new Map();
      for (const p of this.nodeTargets) { const a = this.appOf(p); if (a.installed) for (const [k, v] of a.installed.packages) pkgs.set(k, { name: v.name, version: v.version }); }
      if (!pkgs.size) return { packages: 0, byPackage: new Map(), intel: null };
      const { lookupNpm } = await import('./lookups.js');
      const r = await lookupNpm([...pkgs.values()], { threatIntel: this.opts.threatIntel, log: this.log });
      const byPackage = new Map();
      for (const v of r.vulnerabilities) { const k = `${v.affected_dependency}@${v.affected_dependency_version}`; if (!byPackage.has(k)) byPackage.set(k, []); byPackage.get(k).push(v); }
      return { packages: pkgs.size, byPackage, intel: r.intel };
    });
  }

  // ── native code ────────────────────────────────────────────────────────────
  /** Executables and libraries to read for embedded component versions, by distinct file (device:inode), honouring --libs. */
  libraryCandidates() {
    return this.memo('libs', () => {
      const mode = this.opts.libs;
      if (mode === 'none') return [];
      const seen = new Map();
      const add = (proc, file, kind) => {
        if (!file || !file.startsWith('/')) return;
        const key = `${proc.ns.mnt || ''}:${file}`;
        if (!seen.has(key)) seen.set(key, { path: file, kind, procs: [], mnt: proc.ns.mnt });
        const e = seen.get(key); if (e.procs.length < 20) e.procs.push(proc.pid);
      };
      for (const p of this.targets) {
        if (p.exe && !p.exeMemfd) add(p, p.exe, 'executable');
        const m = this.mapsOf(p);
        if (m) for (const f of m.files) if (f.exec && !f.deleted && f.path !== p.exe && (mode === 'all' || !SYSTEM_LIB.test(f.path))) add(p, f.path, 'library');
      }
      const list = [...seen.values()];
      if (list.length > this.opts.maxLibs) { this.notes.push(`${list.length} distinct executables / libraries are mapped; only the first ${this.opts.maxLibs} were read (--max-libs).`); list.length = this.opts.maxLibs; }
      return list;
    });
  }

  /** Component records found inside the candidates (version banners, Go modules, Rust crates, bundled npm / Python), per file. */
  nativeComponents() {
    return this.memo('native', async () => {
      const { scanEmbeddedComponents } = await import('../../binary/index.js');
      const out = [], gaps = [], unreadable = [];
      for (const c of this.libraryCandidates()) {
        const proc = this.byPid(c.procs[0]);
        const file = this.fsPath(proc, c.path);
        let buf;
        try {
          const st = fs.statSync(file);
          if (!st.isFile()) continue;
          if (st.size > MAX_EXE_MB * 1024 * 1024) { gaps.push(`${c.path}: larger than ${MAX_EXE_MB} MB, not read`); continue; }
          buf = fs.readFileSync(file);
        } catch (e) { unreadable.push(`${c.path}: ${e.code || e.message}`); continue; }
        try {
          const r = scanEmbeddedComponents(buf, path.basename(c.path));
          if (!r) continue;                                                  // not ELF / Mach-O / PE
          for (const g of r.gaps) gaps.push(`${c.path}: ${g}`);
          out.push({ ...c, format: r.format, records: r.records });
        } catch (e) { gaps.push(`${c.path}: ${e.message}`); }
      }
      return { files: out, gaps, unreadable };
    });
  }

  /** Looks up every component of the native files plus the runtime each inspected Node.js process reports; returns dependency records with advisories. */
  componentAdvisories() {
    return this.memo('comp-adv', async () => {
      const { nodeRuntimeRecords, lookupComponents } = await import('./lookups.js');
      const native = await this.nativeComponents();
      const byKey = new Map();
      const key = (r) => r.purl || r.cpe;
      for (const f of native.files) for (const r of f.records) { if (!byKey.has(key(r))) byKey.set(key(r), { record: r, sources: [] }); byKey.get(key(r)).sources.push({ file: f.path, pids: f.procs }); }
      for (const [pid, insp] of this.inspections) {
        if (!insp.ok || !insp.node || !insp.node.versions) continue;
        for (const r of nodeRuntimeRecords(insp.node.versions)) { if (!byKey.has(key(r))) byKey.set(key(r), { record: r, sources: [] }); byKey.get(key(r)).sources.push({ file: `process.versions of pid ${pid}`, pids: [pid] }); }
      }
      const records = [...byKey.values()].map((x) => x.record);
      if (!records.length) return { dependencies: [], byKey, native };
      const r = await lookupComponents(records, { log: this.log });
      return { dependencies: r.dependencies, byKey, native, summary: r.summary };
    });
  }

  // ── active probe (--probe) ─────────────────────────────────────────────────
  probes() { return this.memo('probes', () => (this.opts.probe ? probeListeners(this.targetListeners, { log: this.log }) : null)); }
}

export { mapLimit };
