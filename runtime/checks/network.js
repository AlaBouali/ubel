'use strict';
import { rule, needLive } from './util.js';
import { na } from '../../vm/lib/engine.js';
import { procLabel, scopeOf, downgrade } from '../lib/util.js';
import { isLoopbackAddr, isAnyAddr } from '../lib/procfs.js';

// port → [label, severity, why]  (the same judgement as ubel-vm's listening-service check, applied to the owning process)
const RISKY = {
  21: ['FTP', 'high', 'sends credentials and data in clear text'], 23: ['Telnet', 'high', 'sends credentials and data in clear text'], 69: ['TFTP', 'high', 'has no authentication'],
  111: ['rpcbind', 'medium', 'exposes RPC services'], 445: ['SMB', 'medium', 'exposes file sharing'], 873: ['rsync', 'medium', 'often runs without authentication'],
  1433: ['Microsoft SQL Server', 'medium', 'a database should not be reachable from every network'], 1521: ['Oracle DB', 'medium', 'a database should not be reachable from every network'],
  2049: ['NFS', 'medium', 'exposes file systems'], 2375: ['Docker API (unencrypted)', 'critical', 'gives unauthenticated root-equivalent control of the host'],
  2379: ['etcd', 'high', 'holds cluster secrets and is often unauthenticated'], 3306: ['MySQL/MariaDB', 'medium', 'a database should not be reachable from every network'],
  5432: ['PostgreSQL', 'medium', 'a database should not be reachable from every network'], 5984: ['CouchDB', 'medium', 'a database should not be reachable from every network'],
  6379: ['Redis', 'high', 'is unauthenticated by default and allows code execution'], 9042: ['Cassandra', 'medium', 'a database should not be reachable from every network'],
  9200: ['Elasticsearch', 'high', 'is frequently exposed without authentication'], 11211: ['Memcached', 'high', 'has no authentication and is used for amplification'],
  27017: ['MongoDB', 'high', 'is frequently exposed without authentication'], 5900: ['VNC', 'high', 'remote desktop with weak authentication'],
  9229: ['Node.js inspector', 'critical', 'allows unauthenticated code execution in the process'],
};

const PROBE = {
  inspector: ['Node.js inspector answers HTTP', 'critical', 'The Node.js inspector (/json/version) is reachable: anyone who can connect can run code inside the process.', 'Start the application without --inspect, or bind the inspector to loopback behind an SSH tunnel.'],
  'env-file': ['Environment file is served over HTTP', 'critical', 'GET /.env returns a file of NAME=value settings, which normally contains credentials.', 'Remove the file from the web root, block dotfiles in the server, and rotate every secret it contained.'],
  'git-dir': ['Git repository is served over HTTP', 'high', 'GET /.git/HEAD succeeds: the whole source history can be downloaded.', 'Deploy a build artifact instead of a working copy, block /.git, and rotate secrets that were ever committed.'],
  'actuator-env': ['Spring Boot Actuator /env is open', 'high', 'GET /actuator/env returns the application\'s configuration properties.', 'Restrict management endpoints to a separate port / authenticated users (management.endpoints.web.exposure.include).'],
  'actuator-heapdump': ['Spring Boot heap dump is downloadable', 'critical', 'GET /actuator/heapdump returns the process memory, which contains secrets and session data.', 'Disable the heapdump endpoint or require authentication.'],
  pprof: ['Go pprof profiler is open', 'medium', 'GET /debug/pprof/ is reachable: it discloses internals and allows costly profiling requests.', 'Serve pprof on a separate loopback-only listener.'],
  'server-status': ['Apache server-status is open', 'medium', 'GET /server-status discloses client addresses and requests in flight.', 'Restrict /server-status to localhost or remove it.'],
  phpinfo: ['phpinfo() page is reachable', 'medium', 'GET /phpinfo.php discloses the PHP build, paths and environment.', 'Delete the file.'],
  metrics: ['Metrics endpoint is open', 'low', 'GET /metrics returns Prometheus metrics without authentication.', 'Restrict the metrics port to the monitoring network.'],
};

export default [
  rule({
    id: 'rt-net-risky-service', area: 'exposure', severity: 'medium', title: 'Sensitive or clear-text service listens on a non-loopback address',
    description: 'A service known to be unauthenticated, clear-text or frequently attacked accepts connections on an address other than loopback. Whether it is reachable from the internet depends on the surrounding firewall.',
    remediation: 'Bind the service to 127.0.0.1 or a private interface, put it behind authentication and TLS, and restrict the port with a host firewall or security group.',
    cap: 100,
    evaluate(ctx) {
      const n = needLive(ctx); if (n) return n;
      const out = [], seen = new Set();
      for (const l of ctx.targetListeners) {
        const r = RISKY[l.port];
        if (!r || isLoopbackAddr(l.addr)) continue;
        const p = ctx.byPid(l.pid);
        const k = `${p ? procLabel(p) : l.pid}:${l.port}`;
        if (seen.has(k)) continue; seen.add(k);
        out.push({ resource: `${p ? procLabel(p) : 'pid ' + l.pid} :${l.port}`, scope: p ? scopeOf(p) : 'host', severity: r[1], title: `${r[0]} listens on a non-loopback address`, detail: `pid ${l.pid} listens on ${l.addr}:${l.port}; ${r[0]} ${r[2]}.` });
      }
      return out;
    },
  }),
  rule({
    id: 'rt-net-wildcard-bind', area: 'exposure', severity: 'info', title: 'Application is bound to all network interfaces',
    description: 'The process accepts connections on every interface (0.0.0.0 / ::) rather than on one address. Informational: it is the normal default, but each such port is attack surface that a host firewall or a narrower bind address would reduce.',
    remediation: 'If the service is only used locally or through a reverse proxy, bind it to 127.0.0.1 (or the private interface) instead.',
    cap: 100,
    evaluate(ctx) {
      const n = needLive(ctx); if (n) return n;
      const out = [], seen = new Set();
      for (const l of ctx.targetListeners) {
        if (!isAnyAddr(l.addr) || RISKY[l.port]) continue;
        const p = ctx.byPid(l.pid);
        const k = `${p ? procLabel(p) : l.pid}:${l.port}`;
        if (seen.has(k)) continue; seen.add(k);
        out.push({ resource: `${p ? procLabel(p) : 'pid ' + l.pid} :${l.port}`, scope: p ? scopeOf(p) : 'host', detail: `pid ${l.pid} listens on ${l.addr}:${l.port}.` });
      }
      return out;
    },
  }),
  rule({
    id: 'rt-net-probe-exposed', area: 'exposure', severity: 'medium', title: 'A listening service exposes a sensitive endpoint',
    description: 'A loopback GET request to a well-known path succeeded: a debug interface, an environment dump, a source-control directory, a profiler or an unauthenticated metrics page. Severity drops one level when the port is bound to loopback only.',
    remediation: 'See the finding: remove or protect the endpoint, and rotate any secret it disclosed.',
    cap: 100,
    async evaluate(ctx) {
      const n = needLive(ctx); if (n) return n;
      if (!ctx.opts.probe) return na('local HTTP probe not requested (--probe)');
      const probes = await ctx.probes();
      const out = [];
      for (const pr of probes) {
        const ls = ctx.targetListeners.filter((l) => l.port === pr.port);
        const reachable = ls.some((l) => !isLoopbackAddr(l.addr));
        const p = ctx.byPid(ls[0] && ls[0].pid);
        for (const e of pr.exposed) {
          const d = PROBE[e.id]; if (!d) continue;
          out.push({ resource: `${p ? procLabel(p) : 'port ' + pr.port} :${pr.port}${e.path}`, scope: p ? scopeOf(p) : 'host', severity: reachable ? d[1] : downgrade(d[1]), title: d[0],
            detail: `${d[2]} The port is bound to ${reachable ? 'a non-loopback address' : 'loopback only'}.`, remediation: d[3] });
        }
      }
      return out;
    },
  }),
];
