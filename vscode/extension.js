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

/**
 * Extension activation
 */
function activate(context) {

  // ─────────────────────────────────────────────
  // Command 1: Scan current workspace
  // ─────────────────────────────────────────────
  const scanWorkspaceCmd = vscode.commands.registerCommand("ubel.scan", async () => {
    // Prevent multiple project scans at once
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
        },
        reportUri,
        title: "UBEL: Scanning project…",
      });
    } finally {
      scanningProject = false;
    }
  });

  // ─────────────────────────────────────────────
  // Command 2: Scan VS Code extensions directory
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

    const extensionsDir = path.join(os.homedir(), ".vscode", "extensions");

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
          scan_scope         : "vs_code_extension",
        },
        reportUri,
        title: "UBEL: Scanning VS Code extensions…",
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

    try {
      scanningPlatform = true;
      await runScan({
        main,
        PolicyViolationError,
        scanOptions: {
          projectRoot : platformRoot,
          engine      : "npm",
          mode        : "health",
          is_script   : true,
          save_reports: true,
          scan_os     : true,
          full_stack  : false,
          scan_node   : false,
          scan_scope  : "developer_platform",
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

/**
 * Shared scan runner — calls main() with a pre-built options object.
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