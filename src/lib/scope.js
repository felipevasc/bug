#!/usr/bin/env node
'use strict';

const fs = require('fs');
const net = require('net');

function normalizeLine(s) {
  return String(s || '').trim();
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
  if (!isIp(ip) || Number.isNaN(prefix) || prefix < 0 || prefix > 32) return null;
  const base = ipToInt(ip);
  if (base === null) return null;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const start = (base & mask) >>> 0;
  const end = (start | (~mask >>> 0)) >>> 0;
  return { start, end };
}

function hostnameInScope(host, entry) {
  const h = String(host || '').toLowerCase().replace(/\.$/, '');
  const e = String(entry || '').toLowerCase().replace(/\.$/, '');
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
    const line = normalizeLine(raw);
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
      if (e.includes('/')) {
        const r = cidrToRange(e);
        if (r && ipInt >= r.start && ipInt <= r.end) return true;
      }
    }
    return false;
  }

  // Hostname/domain
  for (const e of entries) {
    // ignore pure IP/CIDR lines for hostname checks
    if (isIp(e) || e.includes('/')) continue;
    if (hostnameInScope(t, e)) return true;
  }
  return false;
}

module.exports = { loadScopeFile, targetInScope };

