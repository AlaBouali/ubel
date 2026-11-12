# ubel-mcp-client / ubel-mcp-server

Security scanners for the **Model Context Protocol (MCP)**, in two binaries:

| Binary | Scans | Contacts anything? |
| --- | --- | --- |
| `ubel-mcp-client` | how MCP **clients** are set up: configuration files (Claude Desktop / Code, Cursor, VS Code, Windsurf, Cline / Roo, Zed, Gemini CLI, Codex, Amazon Q, LM Studio, plus project files), credentials, auto-approval, project trust, and how each local server is launched. Optionally the source of an app that embeds an MCP client. | No. Reads files only. |
| `ubel-mcp-server` | MCP **servers**: running HTTP / SSE endpoints (initialize + list), what a server tells the model (tool, resource and prompt definitions, server instructions), the packages a launcher would fetch, local server source, and running server processes (Linux). | Yes: the endpoints you point it at, package registries and OSV.dev / NVD. Details [below](#what-leaves-the-machine). |

Both are written against the Node standard library only: **no third-party package, no external binary, no subprocess**. Neither ever starts an MCP server and neither ever calls a tool. Findings, the `--fail-on` gate, report id, asset identity and history bundle are the same as in every other UBEL scanner.

```bash
ubel-mcp-client                                   # this user's client configs + the working directory's project files
ubel-mcp-client --project ./repo --fail-on high   # a repository you are about to open in an MCP-enabled client
ubel-mcp-client --source ./my-agent               # an app that embeds an MCP client

ubel-mcp-server https://mcp.example.com/mcp       # probe one endpoint (Streamable HTTP, falling back to legacy SSE)
ubel-mcp-server --from-config                     # probe / analyse every server the client configs declare
ubel-mcp-server --discover --ports 3000,8000-8100 # servers running on this machine that no config declares
ubel-mcp-server --source ./my-server              # local server source
ubel-mcp-server --package npm:@scope/mcp-server@1.2.3   # a server package, downloaded and read (never installed or run)
```

`node mcp/client.js` and `node mcp/server.js` run the same code from a checkout.

---

## ubel-mcp-client

Static and offline. It reads the configuration files of the MCP clients on this machine and, for every server they declare, checks the configuration and the launch command. Nothing is executed and nothing is contacted.

### Where it looks

A file that does not exist is skipped silently; one that exists but cannot be read or parsed is an analysis gap (exit 3). The locations are the ones the clients document or are known to use and they move between client versions, so `--config <file>` reads any file with the same shape (JSON, JSONC or TOML) and `--project <dir>` looks for the project-scoped files of another directory.

| Client | User level | Project level |
| --- | --- | --- |
| Claude Desktop | `claude_desktop_config.json` in `~/Library/Application Support/Claude` (macOS), `%APPDATA%\Claude` (Windows), `~/.config/Claude` (Linux) | — |
| Claude Code | `~/.claude.json` (user and per-project tables), `~/.claude/settings.json` (flags only), `managed-mcp.json` (`/etc/claude-code`, `/Library/Application Support/ClaudeCode`, `C:\Program Files\ClaudeCode`) | `.mcp.json`, `.claude/settings.json`, `.claude/settings.local.json` |
| Cursor | `~/.cursor/mcp.json` | `.cursor/mcp.json` |
| VS Code, Insiders, VSCodium | `User/mcp.json`, and `mcp.servers` in `User/settings.json` | `.vscode/mcp.json` |
| Cline, Roo (VS Code extensions) | `globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`, `globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json` | `.roo/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` | — |
| Zed | `settings.json` (`context_servers`) | `.zed/settings.json` |
| Gemini CLI | `~/.gemini/settings.json` | `.gemini/settings.json` |
| Codex | `$CODEX_HOME` or `~/.codex`, `config.toml` (`[mcp_servers.*]`) | — |
| Amazon Q | `~/.aws/amazonq/mcp.json` | `.amazonq/mcp.json` |
| LM Studio | `~/.lmstudio/mcp.json` | — |

### What it reports

- **Credentials in the file** — in `env`, headers, arguments and URLs. A value that is a reference (`${env:NAME}`, `${input:id}`, `$NAME`, `%NAME%`) is not a credential; a literal one is reported masked (the secrets engine of `ubel-secrets` for vendor formats, plus a name-and-entropy check). Reported again as `mcp.config.file_permissions` when the file is readable by other users.
- **Approval** — `autoApprove` / `alwaysAllow` lists and Gemini `trust: true`; wildcards and command-like tool names raise the severity.
- **Project trust** — `enableAllProjectMcpServers` in Claude Code settings, and project-scoped servers that run a script from the repository or a shell string.
- **Launch command** of each stdio server, looking through `sh -c`, `cmd /c`, `env`, `sudo`:
  - download-and-run, encoded payloads, reverse shells, credential reads, persistence (the command analyser of `ubel-package`);
  - packages fetched without an exact version (`npx`, `bunx`, `pnpm dlx`, `yarn dlx`, `npm exec`, `uvx`, `pipx run`, `deno run npm:`), and sources outside the registry (git without a commit, URLs, plain HTTP);
  - Docker / Podman flags: `--privileged`, dangerous capabilities, disabled security profiles, host mounts of `/`, the home directory, credential directories or `docker.sock`, host namespaces, image not pinned to a digest;
  - the reference filesystem server given `/`, `~` or the home directory;
  - a launched file or directory that other users can write.
- **Plain-HTTP remote servers** (`mcp.remote.cleartext`).
- With `--source`: auto-approval in client code (`autoApprove`, `requireApproval: "never"`, `--dangerously-skip-permissions` …), risky behaviour and hardcoded secrets.

It does **not** probe the declared servers, analyse their packages or read their source. That is `ubel-mcp-server --from-config`.

### Options

| Option | |
| --- | --- |
| `--config <file>` | another client configuration file; repeatable |
| `--project <dir>` | look for project-scoped configuration here; repeatable (default: the working directory) |
| `--home <dir>` | locate user-level configuration under this directory |
| `--no-configs` | read only the files given with `--config` |
| `--source <dir\|file>` | source of an app that embeds an MCP client; repeatable |

Output options are shared: see [Output and exit codes](#output-and-exit-codes).

---

## ubel-mcp-server

At least one target is required: an endpoint URL, `--from-config` (or `--config` / `--project`), `--discover`, `--source` or `--package`.

### Probing a running HTTP / SSE server

The probe speaks just enough of the protocol to initialise and list. It never calls a tool.

1. **Unauthenticated `initialize`** over Streamable HTTP, falling back to the legacy HTTP + SSE transport. Same-origin redirects are followed; a redirect to another origin is reported, not followed.
2. **`401` → OAuth discovery.** Protected-resource and authorization-server metadata are read and checked for HTTP endpoints, missing PKCE `S256` and an issuer that does not match. Metadata URLs that point at a more internal address than the server itself are not fetched.
3. **Authenticated listing** only when you supplied credentials (`--token`, `--header`, or `--use-config-headers` for a declared server's own headers): `tools/list`, `resources/list`, `resources/templates/list` and `prompts/list`, following pagination.
4. **Checks that only mean something when anyone can talk to the endpoint** (skipped when authentication is required):
   - **Origin** — a request with a hostile `Origin` that is served like any other is DNS-rebinding exposure; **Host** — the same for a foreign `Host`; a **CORS** preflight answered with `*` or a reflected origin;
   - **session ids** — entropy, numeric or sequential ids, identical ids across sessions (three sessions are opened);
   - **network exposure** — a server declared on loopback that also answers on the machine's other addresses;
   - plus TLS validity and expiry, plain HTTP, and (legacy SSE) a session id in the message URL or an `endpoint` event that names another origin.
5. **Definitions** are analysed (below) and their hashes are stored in the report.

An unauthenticated endpoint is rated by where it is: public address → high, private network → medium, loopback → low (the Origin check decides whether a web page can reach it).

### What a server tells the model

Tool, resource and prompt definitions and the `instructions` of the initialize reply are read as the model reads them: every string, including every string in the input schema.

- **Poisoning** — wording addressed to the model rather than describing the tool: override-instructions, concealment from the user, pseudo-system tags, references to credential files, secrecy wording, data sent to a URL, markdown images to a URL, redirection of other tools, hidden HTML comments, whitespace padding, encoded blobs. A single strong signal is a finding; weak ones alone are not.
- **Invisible characters** — zero-width, bidirectional controls, control characters and Unicode tag characters; tag characters are decoded so the hidden text is shown.
- **Names** — non-ASCII or look-alike tool names, names outside the specification, duplicates, and the same name offered by more than one server in the scan.
- **Capabilities** — tools that run commands (always reported), and tools that write files, run SQL, read secrets, fetch URLs or send messages (reported when the endpoint is unauthenticated); annotations such as `readOnlyHint` that contradict the tool; free-form `command` / `path` / `url` / `query` string parameters; resources that point at credential or system files.
- **Rug pulls** — each tool's definition is hashed. When `.ubel/reports/latest.mcp_server.json` from the previous scan has the same server, a changed description or schema (`mcp.tool.changed`, high) or a new tool (`mcp.tool.added`) is reported. A server that changes its definitions between two scans is only visible this way; scan on a schedule.

Hostile input is bounded: responses are capped at 1 MB, whitespace runs are collapsed before the pattern checks, a very long string is read at its head and tail, and one scan has a total character budget (reported as a gap when exceeded).

### Declared servers (`--from-config`, `--config`, `--project`)

For every server the configurations declare, `ubel-mcp-server` does what `ubel-mcp-client` deliberately does not: it probes remote ones, downloads and reads the **package** a launcher would fetch (below), reads the **source** of a local script, and looks at the **running process** (below). The configuration hygiene checks stay in `ubel-mcp-client`.

A server declared by a **project** file (a repository you may not have written) that points at a loopback or private address is **not probed** unless you pass `--trust-project`, so a cloned repository cannot make the scan contact internal hosts.

### Packages (`--package`, and the packages launchers fetch)

`npx` / `uvx` / `pipx run` / `bunx` / `pnpm dlx` packages are run through [`ubel-package`](../package/README.md): the release is downloaded from its registry, checked against the registry's digest and **read**, never installed or run — install hooks and what they do, source behaviour, secrets, bundled binaries, known-vulnerable and known-malicious versions (OSV.dev). An unpinned package is analysed at the version the registry serves now, which is what the next start of the server would run. `--no-packages` / `--offline` skip this (reported as a note); `--max-packages` bounds it.

### Local server source (`--source`, and declared scripts)

The behaviour analyser and the secrets engine of `ubel-package` / `ubel-secrets`, plus MCP-specific reading:

- the tools the code registers (`server.tool`, `registerTool`, `addTool`, Python `@mcp.tool()` decorators, Go `NewTool`);
- tool handlers that run a shell command or evaluate code, build SQL, use a file path or request a URL that is not a literal;
- binding to `0.0.0.0`, wildcard CORS, and an HTTP transport with no Origin / Host validation.

**These are text-level heuristics, not data-flow analysis.** They look at the lines after a tool registration, carry low confidence (which lowers the severity one level) and point at where to read; they do not prove an injection. Symlinks are never followed and a file is read up to 768 KB.

### Running servers (Linux `/proc`)

Without `ps`, `lsof` or `ss`: a declared stdio server is matched to its running process by package name, script path, module or image. Reported: a process running as root, a process whose executable was deleted, shell or network-tool descendants (`nc`, `socat`, `curl`, `ssh` …), and listening on every interface. Established outbound connections are listed in the report. Processes of other users are readable only as root; what cannot be read is skipped.

`--discover` also finds servers nobody declared: listening sockets owned by something that looks like an MCP server (plus `--ports` and a few common ports) are probed on `/mcp`, `/sse` and `/`; anything that does not answer as MCP is dropped. Elsewhere than Linux, `--discover` only tries ports on `127.0.0.1`. Discovery sends a JSON-RPC `initialize` POST to local ports, so it is opt-in.

### Options

| Option | |
| --- | --- |
| `url ...` / `--url <url>` | an endpoint to probe; repeatable |
| `--from-config` | the servers declared by this user's client configs and the working directory's project files |
| `--config <file>` / `--project <dir>` / `--home <dir>` | declared servers from another file / directory; user-level configs under another home |
| `--discover` / `--ports <list>` | undeclared running servers; extra ports, e.g. `3000,8000-8100` |
| `--source <dir\|file>` | local server source; repeatable |
| `--package <spec>` | `npm:name[@version]` or `pypi:name[==version]`; repeatable |
| `--token <t>` (or `UBEL_MCP_TOKEN`) / `--header "Name: value"` | credentials for the url targets |
| `--use-config-headers` | send a declared server's own headers to its own URL (default: probe without credentials) |
| `--trust-project` | also probe project-scoped servers on loopback / private addresses |
| `--insecure` | continue when a TLS certificate does not validate (the invalid certificate is still reported) |
| `--timeout <ms>` | per-request timeout (default 8000) |
| `--static-only` | contact nothing and read no `/proc`: configurations, launch commands and source only |
| `--no-packages` / `--max-packages <n>` / `--no-source` / `--offline` | skip or bound package and source analysis; `--offline` also skips advisory lookups |

---

## Output and exit codes

Shared by both binaries:

| Option | |
| --- | --- |
| `--working-dir <dir>` | where `.ubel/reports` is written (default: the current directory) |
| `--min-severity <s>` | hide findings below this severity in the report (`critical` … `info`; default `info`) |
| `--fail-on <s>` | `none`, a severity, or `<count>:<severity>` (default `critical`); counts every finding, whatever `--min-severity` hides |
| `--allow-partial` | exit 0 even when part of the analysis could not be done |
| `--quiet` / `--verbose` | |

Reports: `report.mcp_client.json` / `.html` and `report.mcp_server.json` / `.html`, copied to `.ubel/reports/latest.mcp_*.{json,html}` and bundled in the history zip like every other UBEL report; schema `ubel-mcp/1`. The HTML report escapes everything a server or configuration said and carries a content-security policy that forbids scripts and remote content; console output strips control characters.

Exit codes: `0` passed and complete · `1` scan failed · `2` the gate tripped, or bad arguments · `3` nothing tripped the gate but part of the analysis could not be done (an unparseable config, an unreachable `--url` target, a package that could not be fetched, a failed advisory lookup, a truncated source tree). A clean result over partial coverage is not a pass. A *declared* server that is simply not running is a note, not a gap.

## What leaves the machine

- `ubel-mcp-client`: nothing.
- `ubel-mcp-server`: JSON-RPC requests (and, for OAuth, metadata `GET`s) to the endpoints you target or that your configs declare; **credentials only if you supply them** (`--token`, `--header`, `--use-config-headers`), and only to that server's own URL; package archives from the registry (public by default) and package URLs / names and versions to OSV.dev and NVD (`UBEL_OSV_ENDPOINT` / `UBEL_NVD_ENDPOINT` mirror them), unless `--offline`. Never the content of a config file, a source tree or a tool.
- Do not build targets from anything less trusted than the workflow's own configuration (a PR title, an issue body): the targets decide which hosts the runner contacts.

## Limits

- **Client file locations** are from the clients' documentation and from memory of their behaviour; they change between versions. `--config` covers anything that differs.
- **stdio servers are not interrogated live.** That needs a process of its own, which these scanners do not start. A running stdio server gets process observation and static analysis only; a server that builds its tool list at run time, or changes it after approval, is visible only through the rug-pull diff of an HTTP / SSE server.
- **Source checks are heuristics** (see above). Tool extraction is regex-based.
- **Process observation is Linux-only.** Windows and macOS get `--discover` by port, no process attribution.
- **Container images and native binaries** a server runs are not analysed here (see `ubel-docker`, `ubel-binary`).
- An unauthenticated probe says what an anonymous client can do. What a server exposes to an authenticated client needs credentials.

## Rules

The default severity is shown; some findings are rated by context (for example `mcp.remote.unauthenticated` by where the endpoint is, `mcp.tool.poisoning` by how many signals it carries, `mcp.launch.unpinned` by how loose the pin is, anything from the source heuristics one level lower). Findings from the launcher-package analysis use the `package.*` and `binary.*` rules of [`ubel-package`](../package/README.md).

#### MCP-CONFIG — client

| Rule | Severity | Finding |
| --- | --- | --- |
| `mcp.config.hardcoded_secret` | high | Credential written in plain text in an MCP configuration |
| `mcp.config.secret_in_url` | high | Credential embedded in an MCP server URL |
| `mcp.config.file_permissions` | medium | MCP configuration that holds credentials can be read by other users |
| `mcp.config.auto_approve` | medium | Tool calls are approved without asking the user |
| `mcp.config.trust_project_servers` | medium | Servers declared by a project are trusted automatically |
| `mcp.config.project_runs_repo_code` | medium | Project-scoped MCP server runs code from the repository |

#### MCP-LAUNCH — client

| Rule | Severity | Finding |
| --- | --- | --- |
| `mcp.launch.download_exec` | critical | Server command downloads and runs code |
| `mcp.launch.obfuscated` | high | Server command contains an encoded payload |
| `mcp.launch.suspicious_command` | high | Server command does something a server launcher should not |
| `mcp.launch.shell_wrapper` | low | Server is started through a shell |
| `mcp.launch.unpinned` | medium | Server package is fetched from a registry without an exact version |
| `mcp.launch.non_registry` | medium | Server package comes from outside the registry |
| `mcp.launch.docker_unpinned` | low | Server container image is not pinned to a digest |
| `mcp.launch.docker_privileged` | high | Server container runs with elevated privileges |
| `mcp.launch.docker_host_mount` | high | Server container mounts sensitive host paths |
| `mcp.launch.docker_host_namespace` | medium | Server container shares a host namespace |
| `mcp.launch.broad_filesystem` | high | Filesystem server is given the whole disk or the home directory |
| `mcp.launch.writable_target` | high | Server runs a file or directory that other users can modify |

#### MCP-REMOTE — server (and client for plain-HTTP URLs)

| Rule | Severity | Finding |
| --- | --- | --- |
| `mcp.remote.cleartext` | high | MCP server is reached over unencrypted HTTP |
| `mcp.remote.tls_invalid` | medium | MCP server's TLS certificate does not validate |
| `mcp.remote.tls_expiring` | low | MCP server's TLS certificate expires soon |
| `mcp.remote.unauthenticated` | high | MCP server accepts requests without authentication |
| `mcp.remote.auth_metadata_weak` | medium | MCP server's OAuth metadata is weak |
| `mcp.remote.origin_not_validated` | high | MCP server does not validate the Origin header (DNS rebinding) |
| `mcp.remote.host_not_validated` | medium | MCP server does not validate the Host header |
| `mcp.remote.cors_permissive` | medium | MCP server allows cross-origin requests from any website |
| `mcp.remote.network_exposed` | medium | Server meant for this machine is reachable from the network |
| `mcp.remote.weak_session_id` | medium | MCP session identifiers are predictable |
| `mcp.remote.session_in_url` | low | Session identifier is carried in the URL |
| `mcp.remote.redirect_cross_origin` | medium | MCP endpoint redirects to another origin |
| `mcp.remote.endpoint_foreign` | medium | Legacy SSE server tells the client to POST to another origin |

#### MCP-TOOLS — server

| Rule | Severity | Finding |
| --- | --- | --- |
| `mcp.tool.poisoning` | high | Definition contains instructions aimed at the model (tool poisoning) |
| `mcp.tool.hidden_unicode` | high | Definition contains invisible or direction-changing characters |
| `mcp.tool.homoglyph_name` | high | Tool name contains look-alike or non-ASCII characters |
| `mcp.tool.invalid_name` | low | Tool name does not follow the specification |
| `mcp.tool.duplicate_name` | medium | Server lists the same tool name more than once |
| `mcp.tool.shadowing` | low | The same tool name is offered by more than one server |
| `mcp.tool.changed` | high | A tool definition changed since the previous scan |
| `mcp.tool.added` | medium | A tool was added since the previous scan |
| `mcp.tool.dangerous_capability` | medium | Server exposes tools that execute commands or change the system |
| `mcp.tool.annotation_mismatch` | medium | Tool annotations contradict what the tool does |
| `mcp.tool.unconstrained_sink` | low | Tool takes a command, path, URL or query as a free-form string |
| `mcp.tool.long_description` | low | Definition text is unusually long |
| `mcp.resource.sensitive` | medium | Server offers resources that point at credential or system files |

#### MCP-SOURCE — server (client for `mcp.source.auto_approve`)

| Rule | Severity | Finding |
| --- | --- | --- |
| `mcp.source.risky_code` | medium | Server source contains risky behaviour |
| `mcp.source.hardcoded_secret` | high | Server source contains a hardcoded secret |
| `mcp.source.tool_command_injection` | high | Tool handler builds a shell command or evaluates code from a value that may come from the model |
| `mcp.source.tool_sql_injection` | high | Tool handler builds an SQL statement by string concatenation |
| `mcp.source.tool_path_traversal` | medium | Tool handler uses a file path from its arguments without a containment check |
| `mcp.source.tool_ssrf` | medium | Tool handler requests a URL from its arguments without an allow-list |
| `mcp.source.bind_all` | medium | Server source binds to all network interfaces |
| `mcp.source.dns_rebinding` | medium | HTTP transport without Origin / Host validation |
| `mcp.source.cors_wildcard` | medium | Server source allows cross-origin requests from any origin |
| `mcp.source.auto_approve` | medium | Client code approves tool calls automatically |

#### MCP-PROCESS — server

| Rule | Severity | Finding |
| --- | --- | --- |
| `mcp.process.root` | medium | MCP server process runs as root |
| `mcp.process.deleted_binary` | high | MCP server process runs from a deleted file |
| `mcp.process.suspicious_child` | medium | MCP server process has network-tool or shell children |

## Use as a library

```js
import { scanMcp, parseArgs } from '@arcane-spark/ubel-node/mcp';
const args = parseArgs(['--from-config', '--offline', '--quiet'], 'server');   // or 'client'
const { servers, findings, notes } = await scanMcp(args);
```

`scanMcp` writes nothing; the binaries add the report files, the gate and the console summary.
