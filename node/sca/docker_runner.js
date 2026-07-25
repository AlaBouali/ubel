/**
 * docker_runner.js — pulls a Docker/OCI image and extracts its root
 * filesystem to a local temp directory, WITHOUT ever running the image.
 *
 * `docker create` only materializes a container from an image's layers; it
 * never invokes ENTRYPOINT/CMD. That's what makes this safe to point at an
 * untrusted or unvetted base image pre-deploy — nothing in the image gets a
 * chance to execute on the scanning host.
 *
 * Extraction is done by a small in-process tar reader (extractTarPure
 * below) rather than shelling out to the system `tar`. This is the same
 * approach tools like Trivy use: never ask the OS to materialize a symlink
 * on disk. On Windows, creating a symlink requires
 * SeCreateSymbolicLinkPrivilege (admin or Developer Mode) — Alpine-based
 * images are full of them (BusyBox's applets are all symlinks to one
 * binary), so a plain `tar -xf` fails on the large majority of entries for
 * any non-elevated user. extractTarPure sidesteps this: symlinks and hard
 * links are resolved to plain content copies of their in-archive target
 * (when the target is itself a regular file we extracted), never via
 * fs.symlinkSync. Devices/fifos/sockets are skipped outright — no scanner
 * in this codebase touches them.
 *
 * The extracted rootDir can then be handed to anything in this codebase that
 * already takes a project root: NodeModulesScanner, the Python/PHP/Rust/Go/
 * C#/Java/Ruby scanners (all path-based, no changes needed), and
 * LinuxHostScanner (patched in linux_runner.js to accept rootDir).
 *
 * Requires `docker` on PATH. No `tar` binary, no npm dependencies —
 * consistent with the rest of the SCA engine (uses only Node built-ins:
 * fs, os, path, child_process).
 */

import fs from "fs";
import { randomUUID } from "crypto";
import path from "path";
import { spawnSync } from "child_process";

const SUBPROCESS_TIMEOUT = 10 * 60 * 1000; // 10 min — image pulls/exports can be slow/large

function run(cmd, args, opts = {}) {
  const result = spawnSync(cmd, args, {
    encoding: "utf8",
    timeout: SUBPROCESS_TIMEOUT,
    ...opts,
  });
  if (result.error) {
    if (result.error.code === "ENOENT") {
      throw new Error(`'${cmd}' not found on PATH — is it installed?`);
    }
    throw new Error(`${cmd} ${args.join(" ")} failed to start: ${result.error.message}`);
  }
  return result;
}

function readString(buf, start, len) {
  let end = start;
  while (end < start + len && buf[end] !== 0) end++;
  return buf.toString("utf8", start, end);
}
function readOctal(buf, start, len) {
  const s = readString(buf, start, len).trim();
  return s ? parseInt(s, 8) : 0;
}

/**
 * Minimal in-process reader for the POSIX ustar / GNU tar format that
 * `docker export` produces. Handles regular files, directories, GNU
 * long-name/long-linkname entries ('L'/'K', used for archive paths over
 * the 100-char ustar field — common under node_modules with scoped
 * packages), and PAX extended headers ('x'/'g') as a fallback for the same
 * case on tars built with a PAX-preferring writer. Symlinks and hard links
 * ('2'/'1') are never created as real OS links — their target is resolved
 * against what's already been extracted from the same archive and copied
 * in as plain file content instead. Anything else (devices, fifos,
 * sockets) is skipped. No third-party tar library — built-in Buffer
 * parsing only.
 *
 * @param {string} tarPath  Path to the tar file on disk.
 * @param {string} destDir  Directory to extract into (must already exist).
 * @returns {{regularCount:number, dirCount:number, linkCount:number, resolvedLinks:number, skipCount:number, writeFailCount:number, writeFailures:Array<{relPath:string,reason:string}>}}
 */
function extractTarPure(tarPath, destDir) {
  const buf = fs.readFileSync(tarPath);
  let offset = 0;
  let overrideName = null;
  let overrideLinkname = null;
  const links = []; // { relPath, linkname, hard }
  let regularCount = 0, dirCount = 0, linkCount = 0, skipCount = 0;
  let writeFailCount = 0;
  const writeFailures = []; // sample of {relPath, reason}, capped for logging

  while (offset + 512 <= buf.length) {
    let allZero = true;
    for (let i = 0; i < 512; i++) { if (buf[offset + i] !== 0) { allZero = false; break; } }
    if (allZero) break; // end-of-archive marker

    const h = offset;
    let name = readString(buf, h, 100);
    const size = readOctal(buf, h + 124, 12);
    const typeflag = String.fromCharCode(buf[h + 156] || 48);
    let linkname = readString(buf, h + 157, 100);
    const magic = readString(buf, h + 257, 6);
    const prefix = magic.startsWith("ustar") ? readString(buf, h + 345, 155) : "";

    const dataStart = h + 512;
    const dataEnd = dataStart + size;
    const paddedEnd = dataStart + Math.ceil(size / 512) * 512;

    if (overrideName) { name = overrideName; overrideName = null; }
    else if (prefix) { name = prefix + "/" + name; }
    if (overrideLinkname) { linkname = overrideLinkname; overrideLinkname = null; }

    if (typeflag === "L") { // GNU long name — payload is the *next* entry's real name
      overrideName = buf.toString("utf8", dataStart, dataStart + size).replace(/\0+$/, "");
      offset = paddedEnd; continue;
    }
    if (typeflag === "K") { // GNU long linkname
      overrideLinkname = buf.toString("utf8", dataStart, dataStart + size).replace(/\0+$/, "");
      offset = paddedEnd; continue;
    }
    if (typeflag === "x" || typeflag === "g") { // PAX extended header
      // Parsed directly off the buffer, not a decoded string: PAX record
      // format is "<byte-length> <key>=<value>\n", and that length prefix
      // is a BYTE count. A record's value can contain multi-byte UTF-8
      // (accented filenames are common in ca-certificates packages) — if
      // we decode the whole block to a JS string first and then slice by
      // character index, one multi-byte char makes every subsequent slice
      // in the block land on the wrong byte, and the corruption silently
      // carries into every entry parsed after this header. Slicing the
      // buffer directly and only UTF-8-decoding each already-correct
      // byte range avoids that entirely.
      let p = dataStart;
      let paxPath = null, paxLink = null;
      while (p < dataEnd) {
        let sp = p;
        while (sp < dataEnd && buf[sp] !== 0x20 /* ' ' */) sp++;
        if (sp >= dataEnd) break;
        const len = parseInt(buf.toString("ascii", p, sp), 10);
        if (!len || len <= 0) break;
        const recordEnd = p + len; // exclusive; includes the record's own trailing \n
        if (recordEnd > dataEnd) break; // truncated/corrupt — stop rather than misread
        const eq = buf.indexOf(0x3d /* '=' */, sp + 1);
        if (eq === -1 || eq >= recordEnd) { p = recordEnd; continue; }
        const key = buf.toString("utf8", sp + 1, eq);
        const val = buf.toString("utf8", eq + 1, recordEnd - 1); // -1 drops the trailing \n
        if (key === "path") paxPath = val;
        if (key === "linkpath") paxLink = val;
        p = recordEnd;
      }
      if (paxPath) overrideName = paxPath;
      if (paxLink) overrideLinkname = paxLink;
      offset = paddedEnd; continue;
    }

    const relPath = name.replace(/^\.?\/+/, "");
    // Guard against path traversal from a hostile/corrupt archive.
    if (!relPath || relPath.split(/[/\\]/).includes("..")) { offset = paddedEnd; continue; }
    const destPath = path.join(destDir, relPath);

    // Any single write below can fail for reasons that have nothing to do
    // with the archive being malformed: Windows rejects ':', '*', '?', '"',
    // '<', '>', '|' in filenames (Debian's man pages routinely have '::' in
    // Perl module names — Dpkg::Arch.3perl.gz is a real one), reserved
    // device names (CON, NUL, ...), and paths past MAX_PATH in some
    // configurations. None of that should take down extraction of the
    // other several thousand entries in the archive — those files are
    // irrelevant to manifest-based scanning anyway. Skip and count instead
    // of throwing.
    try {
      if (typeflag === "5") {
        fs.mkdirSync(destPath, { recursive: true });
        dirCount++;
      } else if (typeflag === "0" || typeflag === "\0") {
        fs.mkdirSync(path.dirname(destPath), { recursive: true });
        fs.writeFileSync(destPath, buf.subarray(dataStart, dataEnd));
        regularCount++;
      } else if (typeflag === "1" || typeflag === "2") {
        links.push({ relPath, linkname, hard: typeflag === "1" });
        linkCount++;
      } else {
        skipCount++; // device/fifo/socket — irrelevant to manifest-based scanning
      }
    } catch (err) {
      writeFailCount++;
      if (writeFailures.length < 20) writeFailures.push({ relPath, reason: err.message });
    }

    offset = paddedEnd;
  }

  // Second pass: resolve link entries to plain content copies now that
  // every regular file from the archive has been written. Done as a
  // fixed-point loop, not a single pass — a symlink can point at another
  // symlink (e.g. usr/bin/ash -> bin/busybox_link -> bin/busybox), and if
  // the outer one is resolved before its target exists, resolution fails
  // even though the chain is fully satisfiable. Each round resolves
  // whatever it can; we stop when a round makes no progress (chain fully
  // resolved, or the remainder is genuinely broken/circular).
  //
  // SECURITY: relPath (the link's own destination) is already validated
  // against '..' traversal above, but the link's *target* was not — a
  // symlink can point anywhere via '../../../etc/passwd'-style relative
  // paths, and path.join() happily resolves those upward. Since resolution
  // here means "read this path and copy its bytes into the scan output",
  // an unvalidated target is an arbitrary-file-read primitive: a hostile
  // image can read anything the scanning process's user can read on the
  // HOST — SSH keys, cloud credentials, whatever — and have it copied
  // straight into the extracted rootfs, which then gets scanned/reported
  // (and, for AI-assisted analysis modes, potentially read by an LLM).
  // Every target is resolved and required to stay within destDir before
  // it's ever opened.
  const destDirResolved = path.resolve(destDir);
  const blockedTraversals = []; // { relPath, linkname } — malicious/escaping targets, kept for reporting

  let resolvedLinks = 0;
  let pending = links;
  for (let round = 0; round < links.length + 1 && pending.length; round++) {
    const stillPending = [];
    for (const entry of pending) {
      const { relPath, linkname } = entry;
      const destPath = path.join(destDir, relPath);
      if (fs.existsSync(destPath)) { resolvedLinks++; continue; }

      const targetAbs = linkname.startsWith("/")
        ? path.join(destDir, linkname)
        : path.join(destDir, path.dirname(relPath), linkname);

      const targetResolved = path.resolve(targetAbs);
      const rel = path.relative(destDirResolved, targetResolved);
      const escapesRoot = rel === ".." || rel.startsWith(".." + path.sep) || path.isAbsolute(rel);
      if (escapesRoot) {
        blockedTraversals.push({ relPath, linkname });
        continue; // never read it — not even a stat — and don't re-queue
      }

      try {
        if (fs.existsSync(targetAbs) && fs.statSync(targetAbs).isFile()) {
          fs.mkdirSync(path.dirname(destPath), { recursive: true });
          fs.copyFileSync(targetAbs, destPath);
          resolvedLinks++;
        } else {
          stillPending.push(entry);
        }
      } catch (err) {
        writeFailCount++;
        if (writeFailures.length < 20) writeFailures.push({ relPath, reason: err.message });
        // Don't re-queue — the destination path itself is the problem
        // (same class of Windows-illegal-name issue as the main pass), so
        // retrying it in the next round won't change the outcome.
      }
    }
    if (stillPending.length === pending.length) break; // no progress this round — give up
    pending = stillPending;
  }

  return { regularCount, dirCount, linkCount, resolvedLinks, skipCount, writeFailCount, writeFailures, blockedTraversals };
}

export class DockerImageScanner {
  /**
   * @param {string} image  Any reference `docker pull`/`docker create` accepts:
   *                        "node:20-alpine", "myregistry.io/team/app@sha256:...", etc.
   */
  constructor(image) {
    // Every docker invocation below places this positionally where an image
    // reference is expected. A string starting with '-' could otherwise be
    // parsed as a CLI flag instead of the image — '--' is added on each
    // call as defense in depth, but that relies on Docker's CLI (Cobra/
    // pflag) honoring '--' the way most Go CLIs do, which isn't something
    // I can verify without a docker binary to test against. This check is:
    // reject it outright before it ever reaches a docker invocation.
    if (typeof image !== "string" || image.startsWith("-")) {
      throw new Error(`Invalid image reference '${image}': must not start with '-'`);
    }
    this.image        = image;
    this.containerId  = null;
    this.rootDir       = null;
    this._tarPath      = null;
  }

  /**
   * Pulls the image (unless skipped), creates a stopped container from it,
   * and extracts its filesystem into a fresh temp directory.
   *
   * @param {object}  [opts]
   * @param {boolean} [opts.pull=true]  Run `docker pull` first. Set false to
   *                                    scan an image that only exists locally
   *                                    (e.g. just built with `docker build`,
   *                                    not yet pushed).
   * @returns {Promise<string>} Absolute path to the extracted rootfs.
   */
  async extract({ pull = true } = {}) {
    if (pull) {
      console.log(`[docker] Pulling ${this.image} ...`);
      const pullRes = run("docker", ["pull", "--", this.image], { stdio: "inherit" });
      if (pullRes.status !== 0) {
        throw new Error(`docker pull failed for '${this.image}' (exit ${pullRes.status})`);
      }
    }

    console.log(`[docker] Creating container from ${this.image} (not starting it) ...`);
    const createRes = run("docker", ["create", "--", this.image]);
    if (createRes.status !== 0) {
      throw new Error(`docker create failed for '${this.image}': ${(createRes.stderr || createRes.stdout || "").trim()}`);
    }
    this.containerId = createRes.stdout.trim();

    const uuid = randomUUID();
    this.rootDir  = path.join(process.cwd(), ".ubel", uuid);
    fs.mkdirSync(this.rootDir, { recursive: true });
    this._tarPath = path.join(process.cwd(), ".ubel", `${uuid}.tar`);

    try {
      console.log("[docker] Exporting filesystem ...");
      const exportRes = run("docker", ["export", "-o", this._tarPath, this.containerId]);
      if (exportRes.status !== 0) {
        throw new Error(`docker export failed: ${(exportRes.stderr || exportRes.stdout || "").trim()}`);
      }

      console.log(`[docker] Extracting to ${this.rootDir} ...`);
      const stats = extractTarPure(this._tarPath, this.rootDir);
      console.log(
        `[docker] extracted ${stats.regularCount} files, ${stats.dirCount} dirs, ` +
        `resolved ${stats.resolvedLinks}/${stats.linkCount} symlinks/hardlinks to content copies` +
        (stats.skipCount ? `, skipped ${stats.skipCount} device/fifo/socket entries` : "")
      );
      if (stats.writeFailCount) {
        console.warn(
          `[docker] ${stats.writeFailCount} entries could not be written (continuing — ` +
          `these are almost always OS-illegal filenames, e.g. ':' in Debian man pages, ` +
          `irrelevant to manifest-based scanning; run with DEBUG=1 for the list)`
        );
        if (process.env.DEBUG) {
          for (const { relPath, reason } of stats.writeFailures) {
            console.warn(`  - ${relPath}: ${reason}`);
          }
          if (stats.writeFailCount > stats.writeFailures.length) {
            console.warn(`  ...and ${stats.writeFailCount - stats.writeFailures.length} more`);
          }
        }
      }
      if (stats.blockedTraversals.length) {
        // Not routine noise — this means the image contains a symlink whose
        // target was deliberately crafted (or, less likely, accidentally
        // pathological) to point outside its own extracted rootfs. Always
        // printed, never gated behind DEBUG.
        console.warn(
          `[docker] SECURITY: blocked ${stats.blockedTraversals.length} symlink(s)/hardlink(s) whose target ` +
          `pointed outside the extraction root — image may be attempting a path-traversal / host-file-read attack:`
        );
        for (const { relPath, linkname } of stats.blockedTraversals) {
          console.warn(`  - ${relPath} -> ${linkname}`);
        }
      }
    } catch (err) {
      // Extraction failed outright — clean up before propagating so we don't
      // leak the container/tar/tempdir on a failed run.
      this.cleanup();
      throw err;
    }

    return this.rootDir;
  }

  /**
   * Copies <rootDir>/.ubel (if the image has one) to ./ubel in the current
   * working directory, preserving the directory structure and overwriting
   * anything already there. Must run before cleanup() deletes rootDir.
   */
  _exportUbelDir() {
    if (!this.rootDir) return;
    const src = path.join(this.rootDir, ".ubel");
    if (!fs.existsSync(src)) return;

    const dest = path.join(process.cwd(), ".ubel");
    fs.cpSync(src, dest, { recursive: true, force: true });
    console.log(`[docker] copied .ubel from image to ${dest}`);
  }

  /**
   * Removes the pulled image itself (`docker rmi`) — separate from cleanup(),
   * which only tears down the scan's scratch space (container/tar/rootfs).
   * Used by `check` (always, after scanning) and `install` (only when the
   * scan results in a policy block) to decide whether the image stays on
   * the local machine after the scan is done.
   */
  removeImage() {
    const res = run("docker", ["rmi", "-f", "--", this.image]);
    if (res.status !== 0) {
      console.warn(`[docker] could not remove image '${this.image}': ${(res.stderr || res.stdout || "").trim()}`);
    } else {
      console.log(`[docker] removed image ${this.image}`);
    }
  }

  /** Removes the container, the intermediate tar file, and the extracted rootfs. */
  cleanup() {
    if (this.containerId) {
      run("docker", ["rm", "-f", this.containerId]);
      this.containerId = null;
    }
    if (this._tarPath && fs.existsSync(this._tarPath)) {
      fs.rmSync(this._tarPath, { force: true });
    }
    if (this.rootDir && fs.existsSync(this.rootDir)) {
      this._exportUbelDir();
      fs.rmSync(this.rootDir, { recursive: true, force: true });
    }
  }
}

export default DockerImageScanner;