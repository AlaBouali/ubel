'use strict';

// ─── Concurrency pool ──────────────────────────────────────────────────────────

async function runPool(tasks, concurrency) {
  const results = new Array(tasks.length);
  let index = 0;
  async function worker() {
    while (true) {
      const i = index++;
      if (i >= tasks.length) break;
      results[i] = await tasks[i]();
    }
  }
  await Promise.all(Array.from({ length: concurrency }, () => worker()));
  return results;
}

export { runPool };