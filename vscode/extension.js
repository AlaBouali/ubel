// extension.js — UBEL VS Code Extension entry point (no bundler, pure CJS)

"use strict";

const vscode = require("vscode");
const path   = require("path");
const os     = require("os");

// Resolve ubel source relative to this file
const ubelRoot = path.join(__dirname, "node", "src");

/**
 * Extension activation
 */
function activate(context) {

  // ─────────────────────────────────────────────
  // Command 1: Scan current workspace
  // ─────────────────────────────────────────────
  const scanWorkspaceCmd = vscode.commands.registerCommand("ubel.scan", async () => {
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
  });

  // ─────────────────────────────────────────────
  // Command 2: Scan VS Code extensions directory
  // ─────────────────────────────────────────────
  const scanExtensionsCmd = vscode.commands.registerCommand("ubel.scanExtensions", async () => {
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
  });

  // ─────────────────────────────────────────────
  // Command 3: Scan host platform (ctrl+alt+p)
  //
  // Scans system-level software on the developer's machine: OS, runtimes
  // (Python, Node, .NET, Go, PHP, JRE), browsers, Docker, Git, and
  // security tools.  Does NOT scan npm packages.
  //
  // Report is written to ~/.ubel/reports/ so it has a stable, project-
  // independent location regardless of whether a workspace is open.
  //
  // Note: On Linux, dpkg/apk/rpm reads require the relevant package DB to
  // be readable by the current user.  Coverage may be partial without
  // elevated privileges.  On Windows all probes (registry + PowerShell)
  // run fine as a standard user.
  // ─────────────────────────────────────────────
  const scanPlatformCmd = vscode.commands.registerCommand("ubel.scanPlatform", async () => {
    let main, PolicyViolationError;

    try {
      ({ main }                 = require(path.join(ubelRoot, "main.js")));
      ({ PolicyViolationError } = require(path.join(ubelRoot, "engine.js")));
    } catch (err) {
      vscode.window.showErrorMessage(`❌ UBEL failed to load: ${err.message}`);
      return;
    }

    // Use homedir as the projectRoot for platform scans — mirrors bin/platform.js.
    // Report lands at ~/.ubel/reports/latest.html, independent of any workspace.
    const platformRoot = os.homedir();

    const reportUri = vscode.Uri.file(
      path.join(platformRoot, ".ubel", "reports", "latest.html")
    );

    await runScan({
      main,
      PolicyViolationError,
      scanOptions: {
        projectRoot : platformRoot,
        engine      : "npm",
        mode        : "health",
        is_script   : true,
        save_reports: true,
        scan_os     : true,   // enumerate host system software
        full_stack  : false,  // no lockfile dry-run
        scan_node   : false,  // not scanning npm packages
        scan_scope  : "developer_platform",
      },
      reportUri,
      title: "UBEL: Scanning host platform…",
    });
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