'use strict';
// kubeconfig.js — resolves how ubel-k8s reaches the API server, using only the standard library.
//
// Sources, in order: --kubeconfig <file>, $KUBECONFIG (first existing file of the list), ~/.kube/config, then the
// in-cluster service account (/var/run/secrets/kubernetes.io/serviceaccount + KUBERNETES_SERVICE_HOST/PORT).
// Supported credentials: client certificate + key, bearer token (inline, token file, --token-file, $KUBE_TOKEN) and
// the OIDC id-token a kubeconfig already holds. `exec` credential plugins (aws eks get-token, gke-gcloud-auth-plugin,
// kubelogin …) are NOT supported: they work by running another program, which ubel-k8s deliberately never does.
// Pass a token instead (e.g. --token-file, or $KUBE_TOKEN).

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parseYaml } from '../../package/lib/yaml.js';

class KubeConfigError extends Error {}

const b64 = (s) => Buffer.from(String(s), 'base64');

function readIf(p) { try { return fs.readFileSync(p); } catch { return null; } }

function pick(list, name) { return (Array.isArray(list) ? list : []).find((x) => x && x.name === name); }

/**
 * @param {{kubeconfig?:string, context?:string, token?:string, tokenFile?:string, insecure?:boolean}} opts
 * @returns {{server:string, ca:Buffer|null, cert:Buffer|null, key:Buffer|null, token:string|null, insecure:boolean, clusterName:string, contextName:string|null, user:string|null, source:string, warnings:string[]}}
 */
function resolveConnection(opts = {}) {
  const env = process.env;
  const warnings = [];
  const tokenOverride = opts.token || (opts.tokenFile ? String(readIf(opts.tokenFile) || '').trim() : '') || env.KUBE_TOKEN || null;
  if (opts.tokenFile && !readIf(opts.tokenFile)) throw new KubeConfigError(`--token-file ${opts.tokenFile} cannot be read`);

  let file = opts.kubeconfig || null;
  if (!file && env.KUBECONFIG) file = env.KUBECONFIG.split(path.delimiter).find((f) => f && fs.existsSync(f)) || null;
  if (!file && fs.existsSync(path.join(os.homedir(), '.kube', 'config'))) file = path.join(os.homedir(), '.kube', 'config');

  if (file) {
    const raw = readIf(file);
    if (!raw) throw new KubeConfigError(`kubeconfig ${file} cannot be read`);
    let cfg;
    try { cfg = parseYaml(raw.toString('utf8')); } catch (e) { throw new KubeConfigError(`kubeconfig ${file} is not valid YAML: ${e.message}`); }
    const dir = path.dirname(path.resolve(file));
    const ctxName = opts.context || cfg['current-context'];
    const ctx = ctxName ? pick(cfg.contexts, ctxName) : (cfg.contexts || [])[0];
    if (!ctx || !ctx.context) throw new KubeConfigError(opts.context ? `context "${opts.context}" not found in ${file}` : `${file} has no current-context (use --context)`);
    const cl = pick(cfg.clusters, ctx.context.cluster);
    if (!cl || !cl.cluster || !cl.cluster.server) throw new KubeConfigError(`cluster "${ctx.context.cluster}" has no server in ${file}`);
    const us = ctx.context.user ? pick(cfg.users, ctx.context.user) : null;
    const u = (us && us.user) || {};
    const c = cl.cluster;
    const rel = (p) => (path.isAbsolute(p) ? p : path.join(dir, p));
    const ca = c['certificate-authority-data'] ? b64(c['certificate-authority-data']) : (c['certificate-authority'] ? readIf(rel(c['certificate-authority'])) : null);
    const cert = u['client-certificate-data'] ? b64(u['client-certificate-data']) : (u['client-certificate'] ? readIf(rel(u['client-certificate'])) : null);
    const key = u['client-key-data'] ? b64(u['client-key-data']) : (u['client-key'] ? readIf(rel(u['client-key'])) : null);
    let token = tokenOverride || u.token || (u.tokenFile ? String(readIf(rel(u.tokenFile)) || '').trim() : null);
    if (!token && u['auth-provider'] && u['auth-provider'].config) {
      const cfgp = u['auth-provider'].config;
      token = cfgp['id-token'] || cfgp['access-token'] || null;
      if (token) warnings.push('Using the cached token from the kubeconfig auth-provider; it may be expired.');
    }
    if (!token && !cert && u.exec) {
      throw new KubeConfigError(`The kubeconfig user "${ctx.context.user}" authenticates through an exec plugin (${u.exec.command || 'unknown'}). ubel-k8s never runs other programs. ` +
        'Provide a bearer token instead: --token-file <file> or $KUBE_TOKEN (for example a token of a read-only ServiceAccount), or a kubeconfig with a client certificate.');
    }
    if (c['proxy-url']) warnings.push('The kubeconfig sets proxy-url, which ubel-k8s does not use; connecting directly.');
    return {
      server: String(c.server).replace(/\/+$/, ''), ca, cert, key, token, insecure: !!(opts.insecure || c['insecure-skip-tls-verify']),
      clusterName: ctx.context.cluster, contextName: ctx.name, user: ctx.context.user || null, source: `kubeconfig ${file}`, warnings,
      tlsServerName: c['tls-server-name'] || null,
    };
  }

  // in-cluster
  const host = env.KUBERNETES_SERVICE_HOST, port = env.KUBERNETES_SERVICE_PORT || '443';
  const sa = '/var/run/secrets/kubernetes.io/serviceaccount';
  if (host && fs.existsSync(`${sa}/token`)) {
    return {
      server: `https://${host.includes(':') ? `[${host}]` : host}:${port}`, ca: readIf(`${sa}/ca.crt`), cert: null, key: null,
      token: tokenOverride || String(readIf(`${sa}/token`)).trim(), insecure: !!opts.insecure, clusterName: 'in-cluster', contextName: null, user: 'serviceaccount',
      source: 'in-cluster service account', warnings, tlsServerName: null,
    };
  }
  if (tokenOverride && env.KUBE_SERVER) {
    return { server: env.KUBE_SERVER.replace(/\/+$/, ''), ca: null, cert: null, key: null, token: tokenOverride, insecure: !!opts.insecure, clusterName: env.KUBE_SERVER, contextName: null, user: null, source: '$KUBE_SERVER + token', warnings, tlsServerName: null };
  }
  throw new KubeConfigError('No cluster connection found: pass --kubeconfig <file>, set $KUBECONFIG, create ~/.kube/config, run inside a pod, or audit manifest files with --manifests <path>.');
}

export { resolveConnection, KubeConfigError };
