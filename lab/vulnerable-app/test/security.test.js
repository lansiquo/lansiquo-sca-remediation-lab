// WARNING: INTENTIONALLY VULNERABLE DEMO CODE (SCA Remediation Lab).
// Its dependencies are pinned to known-vulnerable versions on purpose.
// Local use only. Never deploy this app or expose it to a network.
'use strict';
// Security invariant for GHSA-xvch-5gv4-984h (minimist prototype pollution).
// Fails on minimist 1.2.5, passes once minimist is upgraded.
const test = require('node:test');
const assert = require('node:assert');
const { parseOptions } = require('../src/export-job');

test('parsing untrusted options must not modify Function.prototype', () => {
  try {
    parseOptions(['--_.constructor.constructor.prototype.labMarker', 'polluted']);
    assert.strictEqual((function () {}).labMarker, undefined, 'Function.prototype was polluted');
  } finally {
    delete Function.prototype.labMarker;
  }
});
