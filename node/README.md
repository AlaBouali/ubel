# ubel-node

Safe Node.js policy-driven supply-chain firewall — Node.js CLI port of [Ubel](https://github.com/AlaBouali/ubel).

Scans npm/yarn/pnpm/bun projects against [OSV.dev](https://osv.dev), enforces a local policy, and generates **identical JSON + PDF reports** to the Python edition.

---

## Installation

```bash
npm install -g .
# or, from the repo root:
npm install
```

---

## Commands

| Command | Description |
|---|---|
| `ubel-npm <mode> [args]`  | npm projects |
| `ubel-yarn <mode> [args]` | yarn projects |
| `ubel-pnpm <mode> [args]` | pnpm projects |
| `ubel-bun <mode> [args]`  | bun projects  |

### Modes

| Mode | Description |
|---|---|
| `health`  | Scan all **installed** packages (`node_modules` must exist) |
| `check`   | Dry-run the given packages against the policy without installing |
| `install` | Dry-run then install if the policy passes |
| `init`    | Initialise the local policy file and exit |
| `allow`   | Set severity levels to `allow` in the policy |
| `block`   | Set severity levels to `block` in the policy |

### Examples

```bash
# Scan everything currently installed
ubel-npm health

# Check specific packages (dry-run, no install)
ubel-npm check express@4.18.2 lodash@4.17.21

# Check then install if policy passes
ubel-npm install express@4.18.2

# Block medium vulns too
ubel-npm block medium

# Allow high vulns (not recommended)
ubel-npm allow high
```

---

## Policy

Default policy (created at `.ubel/local/policy/config.json`):

```json
{
  "infections": "block",
  "severity": {
    "critical": "block",
    "high":     "block",
    "medium":   "allow",
    "low":      "allow",
    "unknown":  "allow"
  }
}
```

Edit the file directly or use `allow`/`block` sub-commands.

---

## Reports

Reports are written to:

```
.ubel/local/reports/npm/<mode>/YYYY/MM/DD/
  npm_<mode>_<engine>__<timestamp>.pdf
  npm_<mode>_<engine>__<timestamp>.json
  npm_<mode>_<engine>__<timestamp>__artifact.npm
```

The JSON and PDF structure is **identical** to the Python Ubel output.

---

## CVSS Support

| Version | Status |
|---|---|
| CVSS v2   | ✅ Full base-score calculation |
| CVSS v3.0 | ✅ Full base-score calculation |
| CVSS v3.1 | ✅ Full base-score calculation |
| CVSS v4.0 | ✅ Base-score via EQ lookup table |
| Ubuntu labels (`critical`, `high`, `medium`, `low`) | ✅ Pass-through |

---

## Environment Variables

| Variable | Description |
|---|---|
| `UBEL_API_KEY`  | (future) Remote API key |
| `UBEL_ASSET_ID` | (future) Remote asset ID |
| `UBEL_ENDPOINT` | (future) Remote endpoint URL |
| `DEBUG=1`       | Print full stack traces on errors |

---

## Dependencies

- **pdfkit** — PDF generation
- **dotenv** — `.env` support (minimal built-in implementation; no extra dep needed)

No other runtime dependencies. OSV queries use Node's built-in `https` module.
