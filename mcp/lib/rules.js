'use strict';
// rules.js — the rule catalog of ubel-mcp, registered into the shared rule table (mobile/lib/rules.js) so Findings, the gate and the report treat
// MCP findings like every other UBEL finding. Importing this module is what registers them.
//
// masvs = the AREA a finding is filed under in the report (there is no MASVS control for an MCP server):
//   MCP-CONFIG   what a client configuration says (credentials, auto-approval, trust of project servers)
//   MCP-LAUNCH   how a local (stdio) server is started: command line, package pinning, container flags, files it runs
//   MCP-REMOTE   a server reached over HTTP: authentication, Origin/Host/CORS handling, TLS, network exposure, sessions
//   MCP-TOOLS    what a server tells the model: tool / resource / prompt definitions and the server instructions
//   MCP-SOURCE   the source of a local server or client, read statically
//   MCP-PROCESS  a running server process as seen from /proc (Linux)

import { RULES } from '../../mobile/lib/rules.js';

const R = (severity, title, area, cwe, remediation) => ({ severity, title, masvs: area, cwe, remediation });
const C = 'MCP-CONFIG', L = 'MCP-LAUNCH', N = 'MCP-REMOTE', T = 'MCP-TOOLS', S = 'MCP-SOURCE', P = 'MCP-PROCESS';
const REVIEW_DEF = 'Do not connect a client to this server until its definitions have been reviewed. A tool description is read by the model as an instruction; treat it as code.';

export const MCP_RULES = {
  // ── client configuration ──────────────────────────────────────────────────────────────────────────────────────────────────────
  'mcp.config.hardcoded_secret':      R('high',     'Credential written in plain text in an MCP configuration', C, 798, 'Keep credentials out of the file: reference an environment variable (${env:NAME} / ${input:id}), use the client\'s secret prompt or the operating system\'s secret store, and rotate the value that was written here.'),
  'mcp.config.secret_in_url':         R('high',     'Credential embedded in an MCP server URL', C, 598, 'Send credentials in an Authorization header (from an environment variable), never in the URL: URLs end up in logs, proxies and history. Rotate the value.'),
  'mcp.config.file_permissions':      R('medium',   'MCP configuration that holds credentials can be read by other users', C, 732, 'chmod 600 the file (and its directory 700), and move the credentials out of it.'),
  'mcp.config.auto_approve':          R('medium',   'Tool calls are approved without asking the user', C, 862, 'Remove the auto-approve list, or restrict it to read-only tools. A tool that is approved in advance can be driven by anything the model reads, including a poisoned tool description or web page.'),
  'mcp.config.trust_project_servers': R('medium',   'Servers declared by a project are trusted automatically', C, 829, 'Do not enable project-declared MCP servers without a prompt. A cloned repository can ship a configuration that starts a command on the developer\'s machine.'),
  'mcp.config.project_runs_repo_code':R('medium',   'Project-scoped MCP server runs code from the repository', C, 829, 'Review the script before opening the project in an MCP-enabled client. A repository that declares its own server runs that code with the developer\'s privileges as soon as the client starts it.'),

  // ── launch (stdio) ────────────────────────────────────────────────────────────────────────────────────────────────────────────
  'mcp.launch.download_exec':         R('critical', 'Server command downloads and runs code', L, 494, 'Remove the download-and-run from the server command. Install a reviewed, pinned release and start that.'),
  'mcp.launch.obfuscated':            R('high',     'Server command contains an encoded payload', L, 506, 'Replace the encoded command with a readable one that points at a reviewed file.'),
  'mcp.launch.suspicious_command':    R('high',     'Server command does something a server launcher should not', L, 506, 'Review the command. Launchers start a server; they do not read credential stores, persist, delete files or open shells.'),
  'mcp.launch.shell_wrapper':         R('low',      'Server is started through a shell', L, 78, 'Start the server directly (command + args) rather than through `sh -c` / `cmd /c`: a shell interprets everything in the string, including variables and substitutions.'),
  'mcp.launch.unpinned':              R('medium',   'Server package is fetched from a registry without an exact version', L, 1357, 'Pin an exact version (npx pkg@1.2.3, uvx pkg==1.2.3) and review upgrades. An unpinned launcher runs whatever was published last, with the client\'s privileges, every time the server starts.'),
  'mcp.launch.non_registry':          R('medium',   'Server package comes from outside the registry', L, 829, 'Pin the git revision (a full commit hash) or publish the package; avoid plain-HTTP sources entirely.'),
  'mcp.launch.docker_unpinned':       R('low',      'Server container image is not pinned to a digest', L, 1357, 'Reference the image by digest (image@sha256:…), not by a tag that can be moved.'),
  'mcp.launch.docker_privileged':     R('high',     'Server container runs with elevated privileges', L, 250, 'Drop --privileged, extra capabilities and disabled security profiles; a tool server does not need them.'),
  'mcp.launch.docker_host_mount':     R('high',     'Server container mounts sensitive host paths', L, 552, 'Mount only the project directory the server needs, read-only where possible. Never mount the root, the home directory, credential directories or the Docker socket.'),
  'mcp.launch.docker_host_namespace': R('medium',   'Server container shares a host namespace', L, 250, 'Remove --network host / --pid host / --ipc host unless the server cannot work without it.'),
  'mcp.launch.broad_filesystem':      R('high',     'Filesystem server is given the whole disk or the home directory', L, 552, 'Pass only the project directories the model should work in. Everything under an allowed directory is readable and writable by the model, and by anything that can steer it.'),
  'mcp.launch.writable_target':       R('high',     'Server runs a file or directory that other users can modify', L, 732, 'Restrict the file and its directory to the owner (chmod go-w) or move the server out of shared locations such as /tmp.'),

  // ── remote (HTTP / SSE) ───────────────────────────────────────────────────────────────────────────────────────────────────────
  'mcp.remote.cleartext':             R('high',     'MCP server is reached over unencrypted HTTP', N, 319, 'Use https://. Over plain HTTP anyone on the path can read every tool call and its credentials, and can change tool definitions and results in transit.'),
  'mcp.remote.tls_invalid':           R('medium',   'MCP server\'s TLS certificate does not validate', N, 295, 'Serve a certificate that chains to a trusted CA and matches the host name. Clients that accept an invalid certificate can be intercepted.'),
  'mcp.remote.tls_expiring':          R('low',      'MCP server\'s TLS certificate expires soon', N, 298, 'Renew the certificate.'),
  'mcp.remote.unauthenticated':       R('high',     'MCP server accepts requests without authentication', N, 306, 'Require authentication (OAuth 2.1 per the MCP authorization specification, or at least a bearer token) on every request. Anyone who can reach this endpoint can list and call its tools.'),
  'mcp.remote.auth_metadata_weak':    R('medium',   'MCP server\'s OAuth metadata is weak', N, 287, 'Serve HTTPS endpoints only, advertise PKCE with S256, and make the issuer in the metadata match the server it was fetched from.'),
  'mcp.remote.origin_not_validated':  R('high',     'MCP server does not validate the Origin header (DNS rebinding)', N, 346, 'Reject requests whose Origin is not on an allow-list (the MCP transport specification requires this). A web page can otherwise reach a local server through DNS rebinding or a cross-origin request.'),
  'mcp.remote.host_not_validated':    R('medium',   'MCP server does not validate the Host header', N, 346, 'Reject requests whose Host header is not one of the server\'s own names; this is the second half of DNS-rebinding protection.'),
  'mcp.remote.cors_permissive':       R('medium',   'MCP server allows cross-origin requests from any website', N, 942, 'Do not answer CORS preflights with * or a reflected Origin; allow-list the origins that need browser access.'),
  'mcp.remote.network_exposed':       R('medium',   'Server meant for this machine is reachable from the network', N, 668, 'Bind to 127.0.0.1 (or a unix socket) instead of 0.0.0.0, and require authentication if network access is intended.'),
  'mcp.remote.weak_session_id':       R('medium',   'MCP session identifiers are predictable', N, 330, 'Generate session IDs with a cryptographically secure random generator, at least 128 bits (a UUIDv4 or longer), and never from a counter.'),
  'mcp.remote.session_in_url':        R('low',      'Session identifier is carried in the URL', N, 598, 'Use the Mcp-Session-Id header of the Streamable HTTP transport rather than the legacy SSE transport that puts a session in the message URL.'),
  'mcp.remote.redirect_cross_origin': R('medium',   'MCP endpoint redirects to another origin', N, 601, 'Point the client at the final URL. A redirect to a different origin hands the client\'s requests, and any credentials it attaches, to that origin.'),
  'mcp.remote.endpoint_foreign':      R('medium',   'Legacy SSE server tells the client to POST to another origin', N, 918, 'The SSE `endpoint` event must stay on the server\'s own origin. Treat the server as hostile until explained.'),

  // ── what the server tells the model ───────────────────────────────────────────────────────────────────────────────────────────
  'mcp.tool.poisoning':               R('high',     'Definition contains instructions aimed at the model (tool poisoning)', T, 1427, REVIEW_DEF),
  'mcp.tool.hidden_unicode':          R('high',     'Definition contains invisible or direction-changing characters', T, 176, 'Invisible characters (zero-width, bidirectional controls, Unicode tag characters) hide text from the person approving a tool while the model still reads it. Reject the server or strip them and review what they said.'),
  'mcp.tool.homoglyph_name':          R('high',     'Tool name contains look-alike or non-ASCII characters', T, 1007, 'A tool name that imitates another one is used to shadow it. Reject the server; legitimate tool names are plain ASCII.'),
  'mcp.tool.invalid_name':            R('low',      'Tool name does not follow the specification', T, 20, 'Use 1–128 characters from A–Z a–z 0–9 _ - .'),
  'mcp.tool.duplicate_name':          R('medium',   'Server lists the same tool name more than once', T, 694, 'Which definition a client keeps differs between clients; the one the user approved may not be the one that runs.'),
  'mcp.tool.shadowing':               R('low',      'The same tool name is offered by more than one server', T, 694, 'Namespace the servers in the client, or remove one: a second server can shadow a trusted tool of the same name.'),
  'mcp.tool.changed':                 R('high',     'A tool definition changed since the previous scan', T, 345, 'Review the new definition before using the server again. A server that changes its descriptions after they were approved (a "rug pull") is a known attack on MCP clients.'),
  'mcp.tool.added':                   R('medium',   'A tool was added since the previous scan', T, 345, 'Review the new tool before approving it.'),
  'mcp.tool.dangerous_capability':    R('medium',   'Server exposes tools that execute commands or change the system', T, 749, 'Expose only what the use case needs, require confirmation for the rest, and never offer these tools on an endpoint that does not authenticate.'),
  'mcp.tool.annotation_mismatch':     R('medium',   'Tool annotations contradict what the tool does', T, 1104, 'Annotations such as readOnlyHint are trusted by clients to skip confirmation. A tool that claims to be read-only but runs commands or writes data defeats that protection.'),
  'mcp.tool.unconstrained_sink':      R('low',      'Tool takes a command, path, URL or query as a free-form string', T, 20, 'Constrain the parameter in the schema (enum, pattern, maxLength) and validate it in the server; a free-form string that reaches a shell, a file path or a request is an injection point.'),
  'mcp.tool.identity_override_param': R('medium',   'Tool takes a parameter that lets the caller act as another user', T, 639, 'Remove the parameter, or enforce on the server that the caller may act for the user it names. An authorization check that trusts the session\'s identity is bypassed by passing another one; a parameter that is not described in the schema is also invisible to the person reviewing the tool.'),
  'mcp.tool.long_description':        R('low',      'Definition text is unusually long', T, 400, 'Very long descriptions hide instructions below what a user reads. Shorten it and review the whole text.'),
  'mcp.resource.sensitive':           R('medium',   'Server offers resources that point at credential or system files', T, 538, 'Do not expose credential stores, private keys or system files as resources.'),

  // ── local source ───────────────────────────────────────────────────────────────────────────────────────────────────────────────
  'mcp.source.risky_code':            R('medium',   'Server source contains risky behaviour', S, 506, 'Review the code. A tool server should not open shells, collect secrets, persist or hide what it does.'),
  'mcp.source.hardcoded_secret':      R('high',     'Server source contains a hardcoded secret', S, 798, 'Remove the secret, rotate it and read it from the environment at run time.'),
  'mcp.source.tool_command_injection':R('high',     'Tool handler builds a shell command or evaluates code from a value that may come from the model', S, 78, 'Pass an argument vector (execFile / subprocess without a shell), validate the value against an allow-list, and never evaluate model-supplied text.'),
  'mcp.source.tool_sql_injection':    R('high',     'Tool handler builds an SQL statement by string concatenation', S, 89, 'Use parameterised queries.'),
  'mcp.source.tool_path_traversal':   R('medium',   'Tool handler uses a file path from its arguments without a containment check', S, 22, 'Resolve the path and require that it stays inside an allowed directory (path.resolve + startsWith, Path.is_relative_to); reject symlinks that leave it.'),
  'mcp.source.tool_ssrf':             R('medium',   'Tool handler requests a URL from its arguments without an allow-list', S, 918, 'Allow-list hosts, refuse private and link-local addresses after DNS resolution, and do not follow redirects blindly.'),
  'mcp.source.tool_secret_exposure':  R('high',     'Tool handler puts secrets into what it returns', S, 200, 'Never return credentials, tokens, signing keys or the process environment from a tool or resource: the result goes into the model\'s context and from there to whoever can steer the model. Return a status, and keep secrets server-side.'),
  'mcp.source.jwt_weak':              R('high',     'Token verification is weak or the signing secret is short', S, 347, 'Verify the signature, the algorithm (never "none") and the expiry on every token; sign with a random secret of at least 256 bits read from the environment, and rotate the one in the source.'),
  'mcp.source.bind_all':              R('medium',   'Server source binds to all network interfaces', S, 668, 'Bind to 127.0.0.1 unless remote access is intended, and authenticate if it is.'),
  'mcp.source.dns_rebinding':         R('medium',   'HTTP transport without Origin / Host validation', S, 346, 'Enable the SDK\'s DNS-rebinding protection (allowed hosts and origins) or validate the Origin and Host headers yourself.'),
  'mcp.source.cors_wildcard':         R('medium',   'Server source allows cross-origin requests from any origin', S, 942, 'Allow-list the origins that need browser access.'),
  'mcp.source.auto_approve':          R('medium',   'Client code approves tool calls automatically', S, 862, 'Ask the user before calling a tool that changes anything, and never approve with a wildcard.'),

  // ── running process (Linux) ───────────────────────────────────────────────────────────────────────────────────────────────────
  'mcp.process.root':                 R('medium',   'MCP server process runs as root', P, 250, 'Run MCP servers as an unprivileged user; a tool server running as root turns a poisoned prompt into a root compromise.'),
  'mcp.process.deleted_binary':       R('high',     'MCP server process runs from a deleted file', P, 506, 'A process whose executable was removed after it started is a sign of a dropped or replaced payload. Investigate before trusting the server.'),
  'mcp.process.suspicious_child':     R('medium',   'MCP server process has network-tool or shell children', P, 506, 'Check what the server was asked to run. Children such as nc, curl or socat started by a tool server are a typical result of a successful injection.'),
};

Object.assign(RULES, MCP_RULES);
export const MCP_RULE_IDS = Object.keys(MCP_RULES);
