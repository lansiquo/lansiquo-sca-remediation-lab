// WARNING: INTENTIONALLY VULNERABLE DEMO CODE (SCA Remediation Lab).
// Its dependencies are pinned to known-vulnerable versions on purpose.
// Local use only. Never deploy this app or expose it to a network.
'use strict';
// Ordinary functional tests. These pass on BOTH the vulnerable and fixed versions,
// which is the point: compatibility tests alone don't catch the vulnerability.
const test = require('node:test');
const assert = require('node:assert');
const { parseOptions, clientSupported, planExport } = require('../src/export-job');

test('parses format and positional files', () => {
  const o = parseOptions(['--format', 'json', 'a.log', 'b.log']);
  assert.strictEqual(o.format, 'json');
  assert.deepStrictEqual(o.files, ['a.log', 'b.log']);
});

test('defaults format to csv', () => {
  assert.strictEqual(parseOptions([]).format, 'csv');
});

test('parses boolean flags', () => {
  assert.strictEqual(parseOptions(['--zip']).zip, true);
});

test('accepts supported client versions', () => {
  assert.ok(clientSupported('3.1.0'));
  assert.ok(!clientSupported('4.0.0'));
  assert.ok(!clientSupported('not-a-version'));
});

test('plans an export with a notification', () => {
  const plan = planExport(['--client', '2.5.0', 'x.log']);
  assert.strictEqual(plan.notification.data.text, 'export planned: 1 file(s)');
});
