// WARNING: INTENTIONALLY VULNERABLE DEMO CODE (SCA Remediation Lab).
// Its dependencies are pinned to known-vulnerable versions on purpose.
// Local use only. Never deploy this app or expose it to a network.
'use strict';

// Builds (but never sends) a webhook notification. Tests make no network calls.
const axios = require('axios');

const client = axios.create({ baseURL: 'https://hooks.example.invalid', timeout: 5000 });

function buildNotification(text) {
  return { method: 'post', url: '/export-events', baseURL: client.defaults.baseURL, data: { text } };
}

module.exports = { buildNotification };
