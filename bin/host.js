#!/usr/bin/env node
'use strict';
import('../easm/host.js').then(({ main }) => main()).catch((err) => {
  console.error('Fatal error:', err.stack || err.message);
  process.exitCode = 1;
});
