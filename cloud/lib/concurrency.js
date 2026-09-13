'use strict';

/**
 * Run `fn(item, index)` over `items` with at most `limit` in flight at
 * once, returning results in input order. Stdlib-only replacement for
 * something like p-limit/p-map — used to parallelize per-bucket,
 * per-user, and per-region work that was previously a strictly
 * sequential `for (const x of xs) await ...` loop (see item 10: large
 * accounts with thousands of buckets/security groups/IAM users were
 * slow to scan because every check awaited one at a time).
 *
 * A failure in one item does not stop the others — mapLimit resolves
 * once every item has settled, and each result is either
 * `{ ok: true, value }` or `{ ok: false, error }` so callers can log
 * per-item failures without aborting the whole batch (this mirrors the
 * existing try/catch-per-item pattern in checks/*.js).
 */
async function mapLimit(items, limit, fn) {
  const results = new Array(items.length);
  let nextIndex = 0;
  const effectiveLimit = Math.max(1, Math.min(limit, items.length || 1));

  async function worker() {
    while (true) {
      const i = nextIndex++;
      if (i >= items.length) return;
      try {
        results[i] = { ok: true, value: await fn(items[i], i) };
      } catch (error) {
        results[i] = { ok: false, error };
      }
    }
  }

  const workers = Array.from({ length: effectiveLimit }, () => worker());
  await Promise.all(workers);
  return results;
}

export { mapLimit };
