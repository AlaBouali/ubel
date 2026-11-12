#!/usr/bin/env node
'use strict';
// ubel-mcp-client — security scan of how MCP clients are set up. Static and offline. See index.js.
import { pathToFileURL } from 'node:url';
import { runCli } from './index.js';

export const main = () => runCli('client');

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(err => { console.error('Fatal error:', err.stack || err.message); process.exitCode = 1; });
}
