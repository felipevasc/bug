#!/usr/bin/env node
'use strict';

// Target parsing/normalization wrapper used across runner/scope/skills.
//
// Contract:
// - parseTarget(input) => canonical target object with stable fields and a folder-safe key
// - host is canonicalized (lowercase, trailing dot stripped)
// - if kind=url, url is normalized (scheme/host/port/path/query preserved; fragments dropped)

const crypto = require('crypto');
const { URL } = require('url');
const { normalizeHost, normalizeTarget } = require('./target');

function urlPath(urlStr) {
  try {
    const u = new URL(urlStr);
    return u.pathname || '/';
  } catch (_e) {
    return '/';
  }
}

function fsSafeKeyPart(raw) {
  // Windows-safe and portable: keep only a-z0-9._- and collapse others to "_".
  return String(raw || '')
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_+/, '')
    .replace(/_+$/, '');
}

function canonicalTargetKey(t) {
  const kind = t && t.kind === 'url' ? 'url' : 'domain';
  const host = normalizeHost(t && t.host ? t.host : '');
  if (!host) return '';
  const hostKey = fsSafeKeyPart(host) || host;
  if (kind === 'domain') return `domain--${hostKey}`;

  const url = String((t && t.url) || '');
  if (!url) return `url--${hostKey}`;

  // Fixed-length, filesystem-safe and stable across runs/OSes.
  const h = crypto.createHash('sha1').update(url).digest('hex');
  return `url--${hostKey}--${h}`;
}

function parseTarget(input, opts = {}) {
  const info = normalizeTarget(input, opts);
  const host = normalizeHost(info.host || '');
  const kind = info.kind === 'url' ? 'url' : 'domain';
  const out = {
    input: String(input || ''),
    kind,
    host
  };

  if (kind === 'url' && info.url) {
    out.url = info.url;
    if (info.scheme) out.scheme = info.scheme;
    if (info.origin) out.origin = info.origin;
    if (typeof info.port !== 'undefined') out.port = info.port;
    out.path = urlPath(info.url);
  }

  // Runner-friendly display value.
  out.normalizedTarget = kind === 'url' ? (out.url || '') : host;
  out.key = canonicalTargetKey(out);
  return out;
}

function compareTargets(a, b) {
  const ha = normalizeHost(a && a.host ? a.host : '');
  const hb = normalizeHost(b && b.host ? b.host : '');
  if (ha < hb) return -1;
  if (ha > hb) return 1;

  const ra = a && a.kind === 'url' ? 1 : 0;
  const rb = b && b.kind === 'url' ? 1 : 0;
  if (ra !== rb) return ra - rb;

  const na = String((a && a.normalizedTarget) || '');
  const nb = String((b && b.normalizedTarget) || '');
  if (na < nb) return -1;
  if (na > nb) return 1;

  const ka = String((a && a.key) || '');
  const kb = String((b && b.key) || '');
  if (ka < kb) return -1;
  if (ka > kb) return 1;
  return 0;
}

function parseTargetsText(text) {
  const out = [];
  String(text || '').split(/\r?\n/).forEach((raw) => {
    const s = String(raw || '').trim();
    if (!s) return;
    if (s.startsWith('#')) return;
    out.push(s);
  });
  return out;
}

function canonicalizeTargets(rawTargets, opts = {}) {
  const out = [];
  const seen = new Set();
  (rawTargets || []).forEach((raw) => {
    const t = parseTarget(raw, opts);
    if (!t.host) return;
    const key = t.key || canonicalTargetKey(t);
    if (!key) return;
    if (seen.has(key)) return;
    seen.add(key);
    out.push(t);
  });
  out.sort(compareTargets);
  return out;
}

module.exports = {
  parseTarget,
  canonicalTargetKey,
  compareTargets,
  parseTargetsText,
  canonicalizeTargets,
  normalizeHost,
  normalizeTarget
};
