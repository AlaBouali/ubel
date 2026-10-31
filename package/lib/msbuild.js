'use strict';
// msbuild.js — what a MSBuild file (.targets / .props / .csproj / .nuspec build file) does when it is imported into a consumer's build:
// `Exec` commands, `DownloadFile` tasks, inline C# tasks (CodeTaskFactory / RoslynCodeTaskFactory), Pre/PostBuildEvent properties and the
// targets that hook them into the build. Same result shape as sourcebehavior.analyzeSource, plus `targets`.

import { parseXml, findAll } from './xml.js';
import { analyzeSource, snip } from './sourcebehavior.js';

const HOOK_POINTS = /^(?:Build|Rebuild|Restore|CoreCompile|BeforeBuild|AfterBuild|Compile|ResolveReferences|PrepareForBuild|BeforeCompile|AfterCompile|CoreBuild|_GenerateRestoreGraph|Pack|Publish|CoreClean|Clean|BeforeResolveReferences)$/;

function lineOf(text, needle) {
  const i = text.indexOf(needle.slice(0, 60));
  if (i < 0) return 0;
  let n = 1;
  for (let k = 0; k < i; k++) if (text.charCodeAt(k) === 10) n++;
  return n;
}

export function analyzeMsbuild(text) {
  const behaviors = new Map();
  const risks = [];
  const targets = [];
  const mergeBehaviors = (m, line, prefix) => {
    for (const [, b] of m) {
      const k = `${b.cat}\0${prefix}${b.label}`;
      const e = behaviors.get(k);
      if (e) e.count += b.count; else behaviors.set(k, { ...b, label: `${prefix}${b.label}`, line: line || b.line });
    }
  };
  const mergeRisks = (rs, line) => { for (const r of rs) if (risks.filter(x => x.id === r.id).length < 5) risks.push({ ...r, line: line || r.line }); };
  let root = null;
  try { root = parseXml(text); } catch { root = null; }
  if (!root) return { behaviors, risks, targets, stats: { lines: String(text).split('\n').length, longest: 0 }, parsed: false };
  const add = (cat, label, line, snippet) => {
    const k = `${cat}\0${label}`;
    const e = behaviors.get(k);
    if (e) e.count++; else behaviors.set(k, { cat, label, count: 1, line, snippet: snip(snippet) });
  };
  const runCommand = (cmd, where) => {
    const line = lineOf(text, cmd);
    const r = analyzeSource(cmd, 'sh');
    mergeBehaviors(r.behaviors, line, '');
    mergeRisks(r.risks.map(x => ({ ...x, snippet: snip(cmd) })), line);
    add('process', 'MSBuild Exec / build event', line, cmd);
    return line;
  };
  for (const t of findAll(root, 'Target')) {
    const name = t.attrs.Name || '(unnamed)';
    const hook = { name, before: t.attrs.BeforeTargets || null, after: t.attrs.AfterTargets || null, condition: t.attrs.Condition || null, commands: [], downloads: [], inline: false };
    for (const ex of findAll(t, 'Exec')) {
      if (ex.attrs.Command) { hook.commands.push(ex.attrs.Command); runCommand(ex.attrs.Command, name); }
    }
    for (const d of findAll(t, 'DownloadFile')) {
      const url = d.attrs.SourceUrl || '';
      hook.downloads.push(url);
      add('network', 'MSBuild DownloadFile task', lineOf(text, url), `DownloadFile ${url}`);
      if (/^http:\/\//i.test(url)) risks.push({ id: 'remote_fetch', label: 'MSBuild downloads over unencrypted HTTP', line: lineOf(text, url), snippet: snip(url), confidence: 'medium' });
      else risks.push({ id: 'remote_fetch', label: 'MSBuild target downloads a file during the build', line: lineOf(text, url), snippet: snip(url), confidence: 'low' });
    }
    for (const w of [...findAll(t, 'WebDownload'), ...findAll(t, 'GetFileFromUrl')]) { hook.downloads.push(w.attrs.FileUri || w.attrs.Url || ''); add('network', 'MSBuild download task', 0, w.name); }
    for (const rd of findAll(t, 'RemoveDir')) if (/\$\((?:USERPROFILE|HOME)\)|[A-Za-z]:\\|^\/(?:$|[a-z])/.test(rd.attrs.Directories || '')) risks.push({ id: 'destructive', label: 'RemoveDir outside the project', line: lineOf(text, rd.attrs.Directories || ''), snippet: snip(rd.attrs.Directories || ''), confidence: 'low' });
    for (const k of [...findAll(t, 'Task'), ...findAll(t, 'Code')]) { if (k.text.trim()) hook.inline = true; }
    targets.push(hook);
  }
  for (const u of findAll(root, 'UsingTask')) {
    const factory = u.attrs.TaskFactory || '';
    if (/CodeTaskFactory|RoslynCodeTaskFactory/i.test(factory)) {
      const code = findAll(u, 'Code').map(c => c.text).join('\n');
      add('dynamic_loading', 'inline MSBuild task (compiled and run during the build)', lineOf(text, u.attrs.TaskName || factory), `UsingTask ${u.attrs.TaskName || ''} ${factory}`);
      risks.push({ id: 'shell_inline', label: 'inline C# task that is compiled and run by MSBuild', line: lineOf(text, u.attrs.TaskName || factory), snippet: snip(`UsingTask ${u.attrs.TaskName || ''}`), confidence: 'medium' });
      if (code.trim()) { const r = analyzeSource(code, 'cs'); mergeBehaviors(r.behaviors, 0, 'inline task: '); mergeRisks(r.risks.map(x => ({ ...x, line: lineOf(text, x.snippet) || 0 })), 0); }
    }
    if (u.attrs.AssemblyFile && /^https?:/i.test(u.attrs.AssemblyFile)) risks.push({ id: 'remote_fetch', label: 'task assembly is loaded from a URL', line: lineOf(text, u.attrs.AssemblyFile), snippet: snip(u.attrs.AssemblyFile), confidence: 'high' });
  }
  for (const ev of [...findAll(root, 'PreBuildEvent'), ...findAll(root, 'PostBuildEvent'), ...findAll(root, 'PreLinkEvent')]) {
    const cmd = ev.text.trim();
    if (cmd) { runCommand(cmd, ev.name); targets.push({ name: ev.name, before: null, after: 'Build', condition: null, commands: [cmd], downloads: [], inline: false }); }
  }
  for (const im of findAll(root, 'Import')) if (/^https?:\/\//i.test(im.attrs.Project || '')) risks.push({ id: 'remote_fetch', label: 'imports a build file from a URL', line: lineOf(text, im.attrs.Project), snippet: snip(im.attrs.Project), confidence: 'high' });
  return { behaviors, risks, targets, parsed: true, stats: { lines: String(text).split('\n').length, longest: 0 }, hookPoints: targets.filter(t => HOOK_POINTS.test(t.before || '') || HOOK_POINTS.test(t.after || '') || /^(?:Build|Restore|CoreCompile)$/.test(t.name)).length };
}
