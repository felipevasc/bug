#!/usr/bin/env node
'use strict';

// Target parsing/normalization wrapper used across runner/scope/skills.
//
// Contract:
// - parseTarget(input) => { input, kind: 'domain'|'url', host, url? }
// - host is canonicalized (lowercase, trailing dot stripped)
// - if kind=url, url is normalized (scheme/host/port/path/query preserved; fragments dropped)

const { normalizeHost, normalizeTarget } = require('./target');

function parseTarget(input, opts = {}) {
  const info = normalizeTarget(input, opts);
  const host = normalizeHost(info.host || '');
  const out = {
    input: String(input || ''),
    kind: info.kind === 'url' ? 'url' : 'domain',
    host
  };
  if (info.kind === 'url' && info.url) out.url = info.url;
  return out;
}

module.exports = {
  parseTarget,
  normalizeHost,
  normalizeTarget
};

