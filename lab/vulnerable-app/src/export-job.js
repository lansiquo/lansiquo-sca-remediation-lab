// WARNING: INTENTIONALLY VULNERABLE DEMO CODE (SCA Remediation Lab).
// Its dependencies are pinned to known-vulnerable versions on purpose.
// Local use only. Never deploy this app or expose it to a network.
'use strict';

// Evidence-export job. Option tokens come from a less-trusted submitter.
const parseArgs = require('minimist');
const semver = require('semver');
const { buildNotification } = require('./notify');

const SUPPORTED_CLIENTS = '>=2.0.0 <4.0.0';

function parseOptions(tokens) {
  const opts = parseArgs(tokens, { string: ['format', 'client'], default: { format: 'csv' } });
  return { format: opts.format, client: opts.client || '2.0.0', zip: Boolean(opts.zip), files: opts._ };
}

function clientSupported(version) {
  return semver.valid(version) !== null && semver.satisfies(version, SUPPORTED_CLIENTS);
}

function planExport(tokens) {
  const opts = parseOptions(tokens);
  if (!clientSupported(opts.client)) throw new Error('unsupported client ' + opts.client);
  return { ...opts, notification: buildNotification('export planned: ' + opts.files.length + ' file(s)') };
}

module.exports = { parseOptions, clientSupported, planExport };
