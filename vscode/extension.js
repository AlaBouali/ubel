// extension.js — UBEL VS Code Extension entry point (no bundler, pure CJS)
//
// VS Code loads this file directly via require(). Ubel's source tree lives at
// ../node/src/ relative to this file and is loaded at runtime by Node — no
// build step, no bundler, zero dependencies.

"use strict";

const vscode = require("vscode");
const path   = require("path");

// Resolve ubel source relative to this file so the paths work regardless of
// where VS Code installs the extension.
const ubelRoot = path.join(__dirname, "node", "src");

/**
 * Called once by VS Code when the extension activates.
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
  const disposable = vscode.commands.registerCommand("ubel.scan", async () => {
    // ── Lazy-load ubel so any startup errors surface as scan errors ───────
    let scan_project, PolicyViolationError;
    try {
      ({ scan_project }        = require(path.join(ubelRoot, "main.js")));
      ({ PolicyViolationError } = require(path.join(ubelRoot, "engine.js")));
    } catch (loadErr) {
      vscode.window.showErrorMessage(`❌ UBEL failed to load: ${loadErr.message}`);
      return;
    }

    // ── Resolve project root ──────────────────────────────────────────────
    const folders = vscode.workspace.workspaceFolders;
    if (!folders || folders.length === 0) {
      vscode.window.showErrorMessage("UBEL: No workspace folder open.");
      return;
    }
    const projectRoot = folders[0].uri.fsPath;
    const reportUri   = vscode.Uri.file(
      path.join(projectRoot, ".ubel", "reports", "latest.html")
    );

    // ── Run scan with progress indicator ─────────────────────────────────
    await vscode.window.withProgress(
      {
        location:    vscode.ProgressLocation.Notification,
        title:       "UBEL: Scanning dependencies…",
        cancellable: false,
      },
      async () => {
        try {
          await scan_project(projectRoot, {
            is_script:    true,
            save_reports: true,
            os_scan:      false,
            full_stack:   true,
          });

          // ── Clean scan ────────────────────────────────────────────────
          const choice = await vscode.window.showInformationMessage(
            "✅ UBEL scan complete — no policy violations.",
            "Open Report"
          );
          if (choice === "Open Report") {
            await vscode.env.openExternal(reportUri);
          }

        } catch (err) {
          if (err instanceof PolicyViolationError) {
            // ── Policy blocked — vulnerabilities found, report written ────
            const choice = await vscode.window.showWarningMessage(
              `⚠️ UBEL: ${err.message}`,
              "Open Report"
            );
            if (choice === "Open Report") {
              await vscode.env.openExternal(reportUri);
            }
          } else {
            // ── Genuine crash ─────────────────────────────────────────────
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
  });

  context.subscriptions.push(disposable);
}

function deactivate() {}

module.exports = { activate, deactivate };