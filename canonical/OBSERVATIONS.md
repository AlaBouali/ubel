# Observations in the canonical report

An **observation** is a finding for something normal or merely informative: a capability the code has, a remote host a file names, a socket
that listens, a check that passed, a part of the scan that could not be assessed. Its `details.observation` is `true`; it never violates the
policy and never marks a component vulnerable. Types: `behavior`, `exposure`, `coverage`, and the passed checks of a baseline scan
(`hardening` / `misconfig`).

Observations are filed **one per thing observed**, and the thing observed is **an inventory entry of its own**. Nothing is lumped into one
record any more: a dashboard can triage, assign and close each observation on its own, and an inventory entry's page lists exactly what
was seen on it. SAST, SCA and cloud reports are not affected.

## What each module files

| Module | Observation (one finding each) | `rule_id` | Affected artifact (inventory `type`) | `finding_id` derives from |
|---|---|---|---|---|
| mobile · binary · package · mcp | an API / function the code references, per origin (app code, library …) | `behavior.<category>` | the API, per app and category (`api`) | app, category, origin, API |
| | a remote host the files name | `exposure.remote_host` | the host (`domain` / `ip`), shared by every app that names it | app, host |
| | a capability of an MCP tool (one finding for a tool with none) | `behavior.mcp.tool.<capability>` / `behavior.mcp.tool` | the tool (`tool`) | app, tool, capability |
| | an MCP server process seen running | `behavior.mcp.process` | the process (`process`) | app, command line (not the pid) |
| | a socket such a process listens on | `exposure.listener.<port>` | the socket (`network_service`) | app, address, port |
| | a part of the artifact that could not be read | `coverage.gap` | the app, when the report has exactly one | app, text of the gap |
| | the module cut a list off (more than it lists) | `coverage.behavior_apis`, `coverage.remote_hosts` | the app | app (, category, origin) |
| runtime | a program running | `behavior.process` | the program (`application`) | scope, program |
| | a listening socket | `exposure.listener.<port>` | the socket (`network_service`) | address, port, program |
| | a container; the container engine not inspected | `behavior.container`, `coverage.containers` | `container`, `container_engine` | name, socket |
| | a Node.js process inspected / not inspected | `behavior.inspection`, `coverage.inspection` | the program (`application`) | scope, program |
| vm · k8s · runtime | a passed / not-assessed check | the check id | the audited host (`host`) or cluster (`kubernetes_cluster`) | check, subject |
| easm | an open port on a host | `exposure.port.<port>` | the port (`network_service`, id `host:port`) | host, port |

`finding_id` is derived from what the observation is about, never from a pid, a count or a position, so the same observation has the same
id in the next scan (a dashboard keeps its triage state). It is unique within a report.

## Severity

* Behavior: the category's rating (`BEHAVIOR_SEV` in `adapters/appscan.js`); an API only library code references is one level lower.
  Common capabilities are `info`, and an observation never violates the policy whatever its severity.
* MCP tool capability: `exec` medium; `file_write`, `sql`, `secrets`, `messaging` low; anything else info.
* Remote host: `info`; `low` when the files reach it over a clear-text scheme or the module flagged it.
* Listening socket / open port: by what normally listens there (`portRisk` in `common.js`); a socket bound to loopback is always `info`.
* Coverage: `low` for a part of the scan that was not assessed, `info` for a list the module cut short.

## Changes a consumer of the canonical JSON will see

* `affected_component_id` / `_name` / `_type` of an observation is now the artifact itself (API, host, tool, process, socket, program), not
  the app. The app is in `details.app` / `details.application`.
* `behavior.<category>` findings no longer carry `origins`, `functions`, `calls` totals or an `evidence` list for the whole category; they
  carry `origin`, `api`, `calls` and a one-line `evidence`.
* `exposure.remote_hosts` ("Remote hosts referenced (N)") is replaced by one `exposure.remote_host` finding per host.
* `behavior.mcp.tool` is replaced by `behavior.mcp.tool.<capability>` for a tool that declares capabilities.
* EASM open-port findings: `affected_component_id` is `host:port` (an IPv6 address is bracketed), and `finding_id` now includes the host.
  Before, every host with port 80 open shared one `finding_id`.
* ubel-vm / ubel-k8s / ubel-runtime: passed and not-assessed checks point at the host or cluster, which is now in the inventory (it was
  missing for runtime, and the k8s checks had no component at all).
* New inventory types: `api`, `tool`, `process`, `container_engine`, `kubernetes_cluster`; `network_service` also for MCP and EASM; `host`
  also for runtime. Reports show them in `stats.inventory.by_type`.

## Not changed on purpose

* A program running as several instances (runtime) is one observation: the payload has no per-instance attributes beyond the pid list, and
  a pid does not survive to the next scan, so a per-pid finding could not be tracked.
* An EASM misconfiguration is still one finding per rule, anchored on its first target, with every occurrence in `details`: the EASM report
  rebuilds its grouped table from them. Splitting it per target needs that report changed with it.
* The module's own vulnerabilities / secrets / misconfigurations lists of the app scanners (including `hardening` and `integrity` rules
  from the catalogs) are findings already, one per rule firing.

Tests: `node --test tests/canonical-observations.test.js`
