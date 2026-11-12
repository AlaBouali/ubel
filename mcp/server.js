#!/usr/bin/env node
'use strict';
// ubel-mcp-server — security scan of MCP servers: live probing, definitions, packages, source, processes. See index.js.
import { pathToFileURL } from 'node:url';
import { runCli } from './index.js';

export const main = () => runCli('server');

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(err => { console.error('Fatal error:', err.stack || err.message); process.exitCode = 1; });
}
