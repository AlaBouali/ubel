// Regression tests: a vulnerability lookup that cannot be completed must FAIL
// the scan, never look like "0 findings".
//
// The bug these guard against: when api.osv.dev answered with a non-200 (blocked
// egress, rate limit, outage), submitToOsv() logged the error and `continue`d,
// the scan reported 0 vulnerabilities, and the install firewall printed
// "Policy Decision: ALLOW" with exit code 0. The same pattern existed for failed
// OSV advisory fetches (getVulnById returned null and the finding was dropped)
// and for NVD errors (skipped).
//
// A local mock stands in for OSV/NVD via UBEL_OSV_ENDPOINT / UBEL_NVD_ENDPOINT.
//
// Run: node --test tests/lookup-fail-closed.test.js

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';

let server;
let osvMode = 'ok';
let vulnMode = 'ok';
let nvdMode = 'ok-empty';
let engine;

const ADVISORY = {
  id: 'GHSA-aaaa-bbbb-cccc',
  summary: 'test advisory',
  details: 'test advisory details',
  aliases: ['CVE-2020-0001'],
  modified: '2020-01-01T00:00:00Z',
  published: '2020-01-01T00:00:00Z',
  severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
  affected: [{
    package: { ecosystem: 'npm', name: 'lodash' },
    ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }],
  }],
  database_specific: { cwe_ids: ['CWE-79'] },
};

before(async () => {
  server = http.createServer((req, res) => {
    const send = (status, body) => {
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(typeof body === 'string' ? body : JSON.stringify(body));
    };

    if (req.url.startsWith('/v1/querybatch')) {
      let raw = '';
      req.on('data', (c) => { raw += c; });
      req.on('end', () => {
        const { queries } = JSON.parse(raw || '{"queries":[]}');
        if (osvMode === '403') return send(403, { error: 'forbidden' });
        if (osvMode === 'malformed') return send(200, {});
        if (osvMode === 'short') return send(200, { results: queries.slice(1).map(() => ({})) });
        return send(200, { results: queries.map(() => ({ vulns: [{ id: ADVISORY.id }] })) });
      });
      return;
    }

    if (req.url.startsWith('/v1/vulns/')) {
      if (vulnMode === '404') return send(404, { code: 5, message: 'Bug not found.' });
      return send(200, ADVISORY);
    }

    if (req.url.startsWith('/nvd')) {
      if (nvdMode === '403') return send(403, 'Forbidden');
      if (nvdMode === '404') return send(404, 'Invalid cpeName parameter');
      if (nvdMode === 'reset') return req.socket.destroy();
      return send(200, { vulnerabilities: [] });
    }

    send(500, 'unexpected path');
  });

  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  process.env.UBEL_OSV_ENDPOINT = base;
  process.env.UBEL_NVD_ENDPOINT = `${base}/nvd`;
  engine = await import('../sca/engine.js');
});

after(() => new Promise((r) => server.close(r)));

const PURLS = ['pkg:npm/lodash@4.17.20', 'pkg:npm/left-pad@1.3.0'];
const CPE_ITEM = { id: 'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*', name: 'product', version: '1.0', ecosystem: 'unknown' };

test('submitToOsv: healthy answer returns the advisory ids', async () => {
  osvMode = 'ok';
  const ids = await engine.submitToOsv(PURLS);
  assert.equal(ids.length, 2);
  assert.equal(ids[0].vulnerability_id, ADVISORY.id);
});

test('submitToOsv: no purls means no network call and an empty result', async () => {
  assert.deepEqual(await engine.submitToOsv([]), []);
});

test('submitToOsv: HTTP 403 rejects with VulnLookupError (was: logged, 0 findings, ALLOW)', async () => {
  osvMode = '403';
  await assert.rejects(() => engine.submitToOsv(PURLS), (err) => {
    assert.ok(err instanceof engine.VulnLookupError);
    assert.equal(err.source, 'osv');
    assert.match(err.message, /incomplete/);
    return true;
  });
});

test('submitToOsv: HTTP 200 with a malformed body rejects', async () => {
  osvMode = 'malformed';
  await assert.rejects(() => engine.submitToOsv(PURLS), engine.VulnLookupError);
});

test('submitToOsv: fewer results than packages rejects (positional mapping would be wrong)', async () => {
  osvMode = 'short';
  await assert.rejects(() => engine.submitToOsv(PURLS), engine.VulnLookupError);
});

test('getVulnById: healthy advisory is returned', async () => {
  vulnMode = 'ok';
  const v = await engine.getVulnById({
    vulnerability_id: ADVISORY.id, purl: PURLS[0], dependency: 'lodash', affected_version: '4.17.20',
  });
  assert.equal(v.id, ADVISORY.id);
});

test('getVulnById: failed fetch rejects with VulnLookupError (was: null, finding silently dropped)', async () => {
  vulnMode = '404';
  await assert.rejects(
    () => engine.getVulnById({ vulnerability_id: ADVISORY.id, purl: PURLS[0], dependency: 'lodash', affected_version: '4.17.20' }),
    (err) => err instanceof engine.VulnLookupError && err.source === 'osv-vuln',
  );
});

test('submitToNvd: HTTP 403 rejects with VulnLookupError (was: skipped)', async () => {
  nvdMode = '403';
  await assert.rejects(() => engine.submitToNvd([CPE_ITEM]), (err) => {
    assert.ok(err instanceof engine.VulnLookupError);
    assert.equal(err.source, 'nvd');
    return true;
  });
});

test('submitToNvd: connection failure rejects with VulnLookupError (was: skipped)', async () => {
  nvdMode = 'reset';
  await assert.rejects(() => engine.submitToNvd([CPE_ITEM]), engine.VulnLookupError);
});

test('submitToNvd: 404 for an unknown CPE is a complete "nothing known" answer, not a failure', async () => {
  nvdMode = '404';
  assert.deepEqual(await engine.submitToNvd([CPE_ITEM]), []);
});

test('submitToNvd: healthy empty answer returns no vulnerabilities', async () => {
  nvdMode = 'ok-empty';
  assert.deepEqual(await engine.submitToNvd([CPE_ITEM]), []);
});
