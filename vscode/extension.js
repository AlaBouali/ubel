// extension.js — UBEL VS Code Extension entry point (no bundler, pure CJS)

"use strict";

const vscode = require("vscode");
const path   = require("path");
const os     = require("os");

// Resolve ubel source relative to this file
const ubelRoot = path.join(__dirname, "node", "src");

// Per-scan-type flags to prevent concurrent scans of the same type
let scanningProject     = false;
let scanningExtensions  = false;
let scanningPlatform    = false;

// ─────────────────────────────────────────────────────────────────────────────
// Editor Detection
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Detected editor identity.
 * @typedef {"vscode" | "cursor" | "vscodium" | "unknown"} EditorKind
 */

/**
 * Detects which editor is hosting this extension.
 *
 * Signal priority (most → least reliable):
 *
 *   1. vscode.env.uriScheme   — explicitly set per product: "vscode" | "cursor" | "vscodium"
 *                               This is the definitive signal; all forks change it.
 *
 *   2. vscode.env.appName     — human-readable product name set by each fork:
 *                               "Visual Studio Code" | "Cursor" | "VSCodium"
 *                               Reliable but a fork could theoretically keep VS Code's name.
 *
 *   3. vscode.env.appRoot     — install path; contains the product name as a directory segment.
 *                               Checked before execPath because appRoot is the editor's own
 *                               resource directory, whereas execPath may be a shared helper
 *                               binary (e.g. Cursor's internal electron helper is still named
 *                               "code" on some platforms, which broke the old regex).
 *
 *   4. process.execPath       — last resort; Cursor and VSCodium name their main executables
 *                               distinctly, but helper/renderer processes may not.
 *                               We only test for cursor/codium here — we never test for
 *                               "code" because that substring appears in Cursor's paths too.
 *
 * @returns {{ kind: EditorKind, label: string, extensionsDir: string }}
 */
function detectEditor() {
  // --- 1. uriScheme (definitive) ------------------------------------------
  // VS Code  → "vscode"
  // Cursor   → "cursor"
  // VSCodium → "vscodium"
  const scheme = (vscode.env.uriScheme || "").toLowerCase();

  if (scheme === "cursor")   return buildEditorInfo("cursor");
  if (scheme === "vscodium") return buildEditorInfo("vscodium");
  if (scheme === "vscode")   return buildEditorInfo("vscode");

  // --- 2. appName ---------------------------------------------------------
  const appName = (vscode.env.appName || "").toLowerCase();

  if (appName.includes("cursor"))              return buildEditorInfo("cursor");
  if (appName.includes("codium"))              return buildEditorInfo("vscodium");
  if (appName.includes("visual studio code") ||
      appName.includes("vscode"))              return buildEditorInfo("vscode");

  // --- 3. appRoot path ----------------------------------------------------
  const appRoot = (vscode.env.appRoot || "").toLowerCase();

  if (appRoot.includes("cursor"))              return buildEditorInfo("cursor");
  if (appRoot.includes("codium"))              return buildEditorInfo("vscodium");
  // Deliberately NOT testing appRoot for "code" — too broad and matches Cursor paths.

  // --- 4. execPath (narrow patterns only) ---------------------------------
  // We only match cursor/codium explicitly; we never use "code" as a positive
  // signal because Cursor's Electron helper is named "code" on Linux/macOS.
  const execName = path.basename(process.execPath).toLowerCase();

  if (/cursor/i.test(execName))   return buildEditorInfo("cursor");
  if (/codium/i.test(execName))   return buildEditorInfo("vscodium");

  // If all signals say nothing distinctive, assume VS Code.
  return buildEditorInfo("vscode");
}

/**
 * Returns the canonical info object for the detected editor.
 *
 * `version` is read from `vscode.version` — a top-level property exported by
 * the VS Code API module that every fork (Cursor, VSCodium, …) sets to its own
 * release string (e.g. "1.89.1").  This is always available inside the extension
 * host process and requires no shell exec or PATH lookup.
 *
 * Directory conventions:
 *   VS Code   : ~/.vscode/extensions
 *   Cursor    : ~/.cursor/extensions
 *   VSCodium  : ~/.vscode-oss/extensions
 *
 * @param {EditorKind} kind
 * @returns {{ kind: EditorKind, label: string, version: string, extensionsDir: string }}
 */
function buildEditorInfo(kind) {
  const home = os.homedir();

  const dirMap = {
    vscode  : path.join(home, ".vscode",     "extensions"),
    cursor  : path.join(home, ".cursor",     "extensions"),
    vscodium: path.join(home, ".vscode-oss", "extensions"),
  };

  const labelMap = {
    vscode  : "Visual Studio Code",
    cursor  : "Cursor",
    vscodium: "VSCodium",
  };

  return {
    kind,
    label        : labelMap[kind],
    // vscode.version is the authoritative editor version available in the
    // extension host — no shell exec or PATH lookup required.
    version      : vscode.version,
    extensionsDir: dirMap[kind],
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Extension activation
// ─────────────────────────────────────────────────────────────────────────────

function activate(context) {

  // ─────────────────────────────────────────────
  // Command 1: Scan current workspace
  // ─────────────────────────────────────────────
  const scanWorkspaceCmd = vscode.commands.registerCommand("ubel.scan", async () => {
    if (scanningProject) {
      vscode.window.showWarningMessage("UBEL: A project scan is already in progress. Please wait.");
      return;
    }

    let main, PolicyViolationError;

    try {
      ({ main }                 = require(path.join(ubelRoot, "main.js")));
      ({ PolicyViolationError } = require(path.join(ubelRoot, "engine.js")));
    } catch (err) {
      vscode.window.showErrorMessage(`❌ UBEL failed to load: ${err.message}`);
      return;
    }

    const folders = vscode.workspace.workspaceFolders;
    if (!folders || folders.length === 0) {
      vscode.window.showErrorMessage("UBEL: No workspace folder open.");
      return;
    }

    const projectRoot = folders[0].uri.fsPath;

    const reportUri = vscode.Uri.file(
      path.join(projectRoot, ".ubel", "reports", "latest.html")
    );

    // Detect editor so the report can surface it as the host environment.
    const editor = detectEditor();

    try {
      scanningProject = true;
      await runScan({
        main,
        PolicyViolationError,
        scanOptions: {
          projectRoot,
          engine             : "npm",
          mode               : "health",
          is_script          : true,
          save_reports       : true,
          scan_os            : false,
          full_stack         : true,
          scan_node          : true,
          is_vscanned_project: true,
          scan_scope         : "repository",
          editor_kind        : editor.kind,
          editor_label       : editor.label,
          editor_version     : editor.version,
        },
        reportUri,
        title: "UBEL: Scanning project…",
      });
    } finally {
      scanningProject = false;
    }
  });

  // ─────────────────────────────────────────────
  // Command 2: Scan host editor's extensions
  // ─────────────────────────────────────────────
  const scanExtensionsCmd = vscode.commands.registerCommand("ubel.scanExtensions", async () => {
    if (scanningExtensions) {
      vscode.window.showWarningMessage("UBEL: An extensions scan is already in progress. Please wait.");
      return;
    }

    let main, PolicyViolationError;

    try {
      ({ main }                 = require(path.join(ubelRoot, "main.js")));
      ({ PolicyViolationError } = require(path.join(ubelRoot, "engine.js")));
    } catch (err) {
      vscode.window.showErrorMessage(`❌ UBEL failed to load: ${err.message}`);
      return;
    }

    // Detect which editor we are running inside and pick the right directory.
    const editor = detectEditor();

    const extensionsDir = editor.extensionsDir;

    const reportUri = vscode.Uri.file(
      path.join(extensionsDir, ".ubel", "reports", "latest.html")
    );

    try {
      scanningExtensions = true;
      await runScan({
        main,
        PolicyViolationError,
        scanOptions: {
          projectRoot        : extensionsDir,
          engine             : "npm",
          mode               : "health",
          is_script          : true,
          save_reports       : true,
          scan_os            : false,
          full_stack         : true,
          scan_node          : true,
          is_vscanned_project: true,
          // Tag the report with the editor that was scanned so the HTML
          // report header can display "Scanned: Cursor extensions" etc.
          scan_scope         : "editor_extension",
          editor_kind        : editor.kind,
          editor_label       : editor.label,
          // vscode.version is resolved here in extension.js where the vscode
          // API is available, so engine.js never needs to shell out for it.
          editor_version     : editor.version,
        },
        reportUri,
        title: `UBEL: Scanning ${editor.label} extensions…`,
      });
    } finally {
      scanningExtensions = false;
    }
  });

  // ─────────────────────────────────────────────
  // Command 3: Scan host platform (ctrl+alt+p)
  // ─────────────────────────────────────────────
  const scanPlatformCmd = vscode.commands.registerCommand("ubel.scanPlatform", async () => {
    if (scanningPlatform) {
      vscode.window.showWarningMessage("UBEL: A platform scan is already in progress. Please wait.");
      return;
    }

    let main, PolicyViolationError;

    try {
      ({ main }                 = require(path.join(ubelRoot, "main.js")));
      ({ PolicyViolationError } = require(path.join(ubelRoot, "engine.js")));
    } catch (err) {
      vscode.window.showErrorMessage(`❌ UBEL failed to load: ${err.message}`);
      return;
    }

    const platformRoot = os.homedir();

    const reportUri = vscode.Uri.file(
      path.join(platformRoot, ".ubel", "reports", "latest.html")
    );

    // Detect editor so the report can surface it as the host environment.
    const editor = detectEditor();

    try {
      scanningPlatform = true;
      await runScan({
        main,
        PolicyViolationError,
        scanOptions: {
          projectRoot        : platformRoot,
          engine             : "npm",
          mode               : "health",
          is_script          : true,
          save_reports       : true,
          scan_os            : true,
          full_stack         : false,
          scan_node          : false,
          is_vscanned_project: true,
          scan_scope         : "developer_platform",
          editor_kind        : editor.kind,
          editor_label       : editor.label,
          editor_version     : editor.version,
        },
        reportUri,
        title: "UBEL: Scanning host platform…",
      });
    } finally {
      scanningPlatform = false;
    }
  });

  context.subscriptions.push(scanWorkspaceCmd, scanExtensionsCmd, scanPlatformCmd);
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared scan runner
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Calls main() with a pre-built options object and handles all three outcome
 * states: clean, PolicyViolationError, and unexpected error.
 */
async function runScan({ main, PolicyViolationError, scanOptions, reportUri, title }) {
  await vscode.window.withProgress(
    {
      location   : vscode.ProgressLocation.Notification,
      title,
      cancellable: false,
    },
    async () => {
      try {
        await main(scanOptions);

        const choice = await vscode.window.showInformationMessage(
          "✅ UBEL scan complete — no policy violations.",
          "Open Report"
        );

        if (choice === "Open Report") {
          await vscode.env.openExternal(reportUri);
        }

      } catch (err) {
        if (err instanceof PolicyViolationError) {
          const choice = await vscode.window.showWarningMessage(
            `⚠️ UBEL: ${err.message}`,
            "Open Report"
          );

          if (choice === "Open Report") {
            await vscode.env.openExternal(reportUri);
          }

        } else {
          const choice = await vscode.window.showErrorMessage(
            `❌ UBEL scan error: ${err.message}`,
            "Open Report"
          );

          if (choice === "Open Report") {
            await vscode.env.openExternal(reportUri);
          }
        }
      }
    }
  );
}

function deactivate() {}

module.exports = { activate, deactivate };