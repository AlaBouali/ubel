// The EASM private/self-IP safety guard must be answered locally.
//
// It used to call https://api.ipify.org on every scan (and once per scanned IP
// in ubel-easm) to learn this machine's public IP - leaking the scanner's address
// to a third party, contradicting the "no other outbound calls" docs, and
// silently disabling the guard whenever that request failed.
//
// Run: node --test tests/easm-self-ip.test.js

import { test } from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import http from 'node:http';
import https from 'node:https';
import { IpInfo, DomainScanner } from '../easm/fingerprint/src/index.js';

function withInterfaces(map, fn) {
  const real = os.networkInterfaces;
  os.networkInterfaces = () => map;
  return Promise.resolve().then(fn).finally(() => { os.networkInterfaces = real; });
}

test('IpInfo no longer exposes the third-party public-IP lookup', () => {
  assert.equal(typeof IpInfo.myIp, 'undefined');
});

test('isLocalAddress: matches addresses bound to a local interface, nothing else', async () => {
  await withInterfaces({ eth0: [{ address: '198.51.100.9', family: 'IPv4' }] }, () => {
    assert.equal(IpInfo.isLocalAddress('198.51.100.9'), true);
    assert.equal(IpInfo.isLocalAddress('198.51.100.10'), false);
    assert.equal(IpInfo.isLocalAddress(null), false);
    assert.equal(IpInfo.isLocalAddress(undefined), false);
  });
});

test('DomainScanner.scan refuses a locally-bound address without making any HTTP request', async () => {
  const calls = [];
  const realH = http.request, realS = https.request;
  http.request  = (...a) => { calls.push(['http',  String(a[0]?.href || a[0]?.hostname || a[0])]); throw new Error('network call attempted'); };
  https.request = (...a) => { calls.push(['https', String(a[0]?.href || a[0]?.hostname || a[0])]); throw new Error('network call attempted'); };
  try {
    await withInterfaces({ eth0: [{ address: '198.51.100.9', family: 'IPv4' }] }, async () => {
      // An IP literal "resolves" to itself, so no DNS traffic is needed either.
      const out = await DomainScanner.scan('198.51.100.9');
      assert.deepEqual(out, []);
    });
  } finally {
    http.request = realH; https.request = realS;
  }
  assert.deepEqual(calls, [], `unexpected outbound requests: ${JSON.stringify(calls)}`);
});
