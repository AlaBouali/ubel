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
    let scan_project, PolicyViolationError;

    try {
      ({ scan_project }         = require(path.join(ubelRoot, "main.js")));
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
      scan_project,
      PolicyViolationError,
      targetPath: projectRoot,
      reportUri,
      title: "UBEL: Scanning project…"
    });
  });

  // ─────────────────────────────────────────────
  // Command 2: Scan VS Code extensions directory
  // ─────────────────────────────────────────────
  const scanExtensionsCmd = vscode.commands.registerCommand("ubel.scanExtensions", async () => {
    let scan_project, PolicyViolationError;

    try {
      ({ scan_project }         = require(path.join(ubelRoot, "main.js")));
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
      scan_project,
      PolicyViolationError,
      targetPath: extensionsDir,
      reportUri,
      title: "UBEL: Scanning VS Code extensions…"
    });
  });

  context.subscriptions.push(scanWorkspaceCmd, scanExtensionsCmd);
}

/**
 * Shared scan runner
 */
async function runScan({ scan_project, PolicyViolationError, targetPath, reportUri, title }) {
  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title,
      cancellable: false,
    },
    async () => {
      try {
        await scan_project(targetPath, {
          is_script: true,
          save_reports: true,
          os_scan: false,
          full_stack: true,
          is_vscanned_project: true,
        });

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