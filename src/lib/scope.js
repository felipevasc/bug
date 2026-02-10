#!/usr/bin/env node
'use strict';

const fs = require('fs');
const net = require('net');
const { URL } = require('url');
const { normalizeTarget, normalizeHost } = require('./target');

function normalizeLine(s) {
  return String(s || '').trim();
}

function isCidrEntry(s) {
  return /^\d+\.\d+\.\d+\.\d+\/\d{1,2}$/.test(String(s || '').trim());
}

function normalizeScopeEntry(raw) {
  const line = normalizeLine(raw);
  if (!line) return null;

  if (isIp(line) || isCidrEntry(line)) return line;

  if (line.startsWith('*.')) {
    const root = normalizeHost(line.slice(2));
    return root ? `*.${root}` : null;
  }

  const info = normalizeTarget(line);
  if (info.kind === 'url') return info.normalizedTarget;
  return normalizeHost(info.host || line);
}

function isIp(s) {
  return net.isIP(s) !== 0;
}

function ipToInt(ip) {
  const parts = ip.split('.').map((x) => parseInt(x, 10));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return null;
  // >>> 0 keeps uint32
  return (((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3]) >>> 0;
}

function cidrToRange(cidr) {
  const [ip, prefixStr] = cidr.split('/');
  const prefix = parseInt(prefixStr, 10);
  if (!isIp(ip) || net.isIP(ip) !== 4 || Number.isNaN(prefix) || prefix < 0 || prefix > 32) return null;
  const base = ipToInt(ip);
  if (base === null) return null;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const start = (base & mask) >>> 0;
  const end = (start | (~mask >>> 0)) >>> 0;
  return { start, end };
}

function pathFromUrl(urlStr) {
  try {
    const u = new URL(urlStr);
    return u.pathname || '/';
  } catch (_e) {
    return '/';
  }
}

function normalizePathPrefix(p) {
  if (!p || p === '/') return '/';
  let out = String(p);
  if (!out.startsWith('/')) out = `/${out}`;
  if (out.length > 1 && out.endsWith('/')) out = out.slice(0, -1);
  return out;
}

function pathMatchesPrefix(targetPath, entryPath) {
  const prefix = normalizePathPrefix(entryPath);
  if (prefix === '/') return true;
  const targetNorm = normalizePathPrefix(targetPath);
  if (targetNorm === prefix) return true;
  return targetNorm.startsWith(prefix) && targetNorm[prefix.length] === '/';
}

function hostnameInScope(host, entry) {
  const h = normalizeHost(host);
  const e = normalizeHost(entry);
  if (!h || !e) return false;
  if (e.startsWith('*.')) {
    const root = e.slice(2);
    return h === root || h.endsWith(`.${root}`);
  }
  // "example.com" should allow subdomains too, per repo requirements.
  return h === e || h.endsWith(`.${e}`);
}

function loadScopeFile(scopeFile) {
  if (!scopeFile) return { ok: true, entries: [] };
  const txt = fs.readFileSync(scopeFile, 'utf8');
  const entries = [];
  txt.split('\n').forEach((raw) => {
    const trimmed = normalizeLine(raw);
    if (!trimmed || trimmed.startsWith('#')) return;
    const line = normalizeScopeEntry(trimmed);
    if (!line || line.startsWith('#')) return;
    entries.push(line);
  });
  return { ok: true, entries };
}

function targetInScope(target, entries) {
  if (!entries || entries.length === 0) return true;
  const t = String(target || '').trim();
  if (!t) return false;

  if (isIp(t)) {
    const ipInt = ipToInt(t);
    if (ipInt === null) return false;
    for (const e of entries) {
      if (isIp(e) && e === t) return true;
      if (isCidrEntry(e)) {
        const r = cidrToRange(e);
        if (r && ipInt >= r.start && ipInt <= r.end) return true;
      }
    }
    return false;
  }

  // Hostname/domain
  const tInfo = normalizeTarget(t);
  const tHost = normalizeHost(tInfo.host || t);
  const tPath = tInfo.kind === 'url' ? pathFromUrl(tInfo.url) : '';
  for (const e of entries) {
    if (!e) continue;
    const entry = String(e).trim();
    if (!entry) continue;
    if (isIp(entry) || isCidrEntry(entry)) continue;

    let entryHost = '';
    let entryPath = '';
    if (entry.startsWith('*.')) {
      entryHost = `*.${normalizeHost(entry.slice(2))}`;
    } else {
      const eInfo = normalizeTarget(entry);
      entryHost = eInfo.kind === 'url' ? eInfo.host : normalizeHost(eInfo.host || entry);
      if (eInfo.kind === 'url') entryPath = pathFromUrl(eInfo.url);
    }

    if (!entryHost) continue;
    if (!hostnameInScope(tHost, entryHost)) continue;
    if (entryPath && entryPath !== '/') {
      if (!tInfo || tInfo.kind !== 'url') continue;
      if (!pathMatchesPrefix(tPath, entryPath)) continue;
    }
    return true;
  }
  return false;
}

module.exports = { loadScopeFile, targetInScope };
