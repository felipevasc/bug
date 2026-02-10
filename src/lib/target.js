#!/usr/bin/env node
'use strict';

const { URL } = require('url');

function normalizeHost(raw) {
  return String(raw || '').trim().toLowerCase().replace(/\.$/, '');
}

function hasScheme(raw) {
  return /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(raw);
}

function isIpv4Cidr(raw) {
  return /^\d+\.\d+\.\d+\.\d+\/\d{1,2}$/.test(raw);
}

function looksLikeUrl(raw) {
  if (!raw) return false;
  if (hasScheme(raw)) return true;
  if (isIpv4Cidr(raw)) return false;
  if (/[/?#]/.test(raw)) return true;
  if (/^[^/]+:\d{1,5}$/.test(raw)) return true;
  return false;
}

function normalizeDomain(raw) {
  const host = normalizeHost(raw);
  return {
    raw: String(raw || ''),
    kind: 'domain',
    host,
    normalizedTarget: host
  };
}

function normalizeUrl(raw, opts = {}) {
  const rawStr = String(raw || '');
  const trimmed = rawStr.trim();
  const defaultScheme = opts.defaultScheme || 'https';
  const input = hasScheme(trimmed) ? trimmed : `${defaultScheme}://${trimmed}`;

  let parsed = null;
  try {
    parsed = new URL(input);
  } catch (_e) {
    return normalizeDomain(rawStr);
  }

  const scheme = String(parsed.protocol || '').replace(/:$/, '').toLowerCase();
  const host = normalizeHost(parsed.hostname || '');
  if (!host) return normalizeDomain(rawStr);

  const portRaw = parsed.port || '';
  let port = portRaw ? Number(portRaw) : null;
  let keepPort = portRaw;
  if ((scheme === 'http' && portRaw === '80') || (scheme === 'https' && portRaw === '443')) {
    keepPort = '';
    port = null;
  }

  let pathname = parsed.pathname || '/';
  if (!pathname.startsWith('/')) pathname = `/${pathname}`;
  const search = parsed.search || '';

  const origin = `${scheme}://${host}${keepPort ? `:${keepPort}` : ''}`;
  // Preserve path/query (but drop fragments) so URL targets remain web-first and unambiguous.
  const url = `${origin}${pathname}${search}`;

  const out = {
    raw: rawStr,
    kind: 'url',
    host,
    scheme,
    url,
    origin,
    normalizedTarget: url
  };
  if (keepPort) out.port = port;
  return out;
}

function normalizeTarget(raw, opts = {}) {
  const rawStr = String(raw || '');
  const trimmed = rawStr.trim();
  if (!trimmed) return normalizeDomain(rawStr);
  if (looksLikeUrl(trimmed)) return normalizeUrl(trimmed, opts);
  return normalizeDomain(trimmed);
}

module.exports = {
  normalizeHost,
  normalizeDomain,
  normalizeUrl,
  normalizeTarget
};
