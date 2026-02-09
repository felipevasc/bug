'use strict';

const http = require('http');
const https = require('https');
const dns = require('dns');

const DEFAULT_TIMEOUT_MS = 8000;
const AUTH_CACHE_TTL_MS = 5 * 60 * 1000;

function nowIso() {
  return new Date().toISOString();
}

function buildPayload(record) {
  const ts = record.ts || record.timestamp || nowIso();
  return {
    ...record,
    ts,
    timestamp: record.timestamp || ts
  };
}

function isIpv4(value) {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(value || '');
}

function allowDummyIp() {
  return process.env.FARADAY_ALLOW_DUMMY_IP === '1' || process.env.FARADAY_ALLOW_DUMMY_IP === 'true';
}

function baseUrlFromEnv() {
  const raw = process.env.FARADAY_URL;
  if (!raw) return null;

  const trimmed = raw.endsWith('/') ? raw.slice(0, -1) : raw;
  try {
    // Validate URL early to avoid surprising exceptions later.
    // eslint-disable-next-line no-new
    new URL(trimmed);
    return trimmed;
  } catch (_err) {
    return null;
  }
}

function workspaceName(record) {
  return (record && record.workspace) || process.env.FARADAY_WORKSPACE || null;
}

function debugEnabled() {
  return process.env.FARADAY_DEBUG === '1' || process.env.FARADAY_DEBUG === 'true';
}

function logDebug(message) {
  if (!debugEnabled()) return;
  process.stderr.write(`[faraday] ${message}\n`);
}

function joinUrl(base, path) {
  if (!base) return null;
  if (!path) return base;
  if (path.startsWith('/')) return `${base}${path}`;
  return `${base}/${path}`;
}

function request(method, url, headers, body, timeoutMs = DEFAULT_TIMEOUT_MS) {
  return new Promise((resolve) => {
    try {
      const target = new URL(url);
      const client = target.protocol === 'https:' ? https : http;

      const payload = body === undefined || body === null ? null : JSON.stringify(body);
      const req = client.request(
        {
          method,
          hostname: target.hostname,
          port: target.port || (target.protocol === 'https:' ? 443 : 80),
          path: `${target.pathname}${target.search}`,
          headers: {
            ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}),
            ...headers
          },
          timeout: timeoutMs
        },
        (res) => {
          let text = '';
          res.setEncoding('utf8');
          res.on('data', (chunk) => { text += chunk; });
          res.on('end', () => {
            let json = null;
            try {
              json = text ? JSON.parse(text) : null;
            } catch (_err) {
              json = null;
            }

            resolve({
              ok: res.statusCode >= 200 && res.statusCode < 300,
              status: res.statusCode,
              headers: res.headers,
              text,
              json
            });
          });
        }
      );

      req.on('error', (err) => {
        logDebug(`request error: ${err && err.message ? err.message : 'unknown'}`);
        resolve({ ok: false, status: 0, error: 'request_failed', headers: {}, text: '', json: null });
      });

      req.on('timeout', () => {
        req.destroy();
        resolve({ ok: false, status: 0, error: 'timeout', headers: {}, text: '', json: null });
      });

      if (payload) req.write(payload);
      req.end();
    } catch (_err) {
      resolve({ ok: false, status: 0, error: 'invalid_url', headers: {}, text: '', json: null });
    }
  });
}

async function requestWithFallback(method, urlA, urlB, headers, body) {
  const resA = await request(method, urlA, headers, body);
  if (resA.status !== 404) return resA;
  if (!urlB) return resA;
  return request(method, urlB, headers, body);
}

let cachedAuth = null;
let cachedAuthAt = 0;

async function tokenAuth(baseUrl) {
  const user = process.env.FARADAY_USER;
  const pass = process.env.FARADAY_PASS;
  if (!user || !pass) return null;

  // NOTE: Token endpoints are highly version-dependent and some "authentication_token"
  // values returned by Faraday are NOT JWTs; using them as Authorization can crash the API.
  // Prefer cookie-based auth for broad compatibility.
  return null;
}

async function cookieAuth(baseUrl) {
  const user = process.env.FARADAY_USER;
  const pass = process.env.FARADAY_PASS;
  if (!user || !pass) return null;

  const urlA = joinUrl(baseUrl, '/_api/login');
  const urlB = joinUrl(baseUrl, '/_api/login/');
  // Faraday's login handler may assume a User-Agent is present; ensure one to avoid 500s.
  const res = await requestWithFallback(
    'POST',
    urlA,
    urlB,
    { 'User-Agent': 'bugbounty-automation-hub/0.1' },
    { email: user, password: pass }
  );
  if (!res.ok) return null;

  const cookies = res.headers['set-cookie'];
  if (!cookies || cookies.length === 0) return null;

  // Keep using cookies: some Faraday versions expose an "authentication_token" in JSON that is not a JWT
  // and will cause 500s if used as Authorization Token on v3 endpoints.
  return { Cookie: cookies.map((c) => c.split(';')[0]).join('; ') };
}

async function authHeaders(baseUrl) {
  const token = process.env.FARADAY_TOKEN;
  if (token && token.trim()) {
    return { Authorization: `Token ${token.trim()}` };
  }

  if (cachedAuth && Date.now() - cachedAuthAt < AUTH_CACHE_TTL_MS) {
    return cachedAuth;
  }

  const tokenHeaders = await tokenAuth(baseUrl);
  if (tokenHeaders) {
    cachedAuth = tokenHeaders;
    cachedAuthAt = Date.now();
    return tokenHeaders;
  }

  const cookieHeaders = await cookieAuth(baseUrl);
  if (cookieHeaders) {
    cachedAuth = cookieHeaders;
    cachedAuthAt = Date.now();
    return cookieHeaders;
  }

  return {};
}

async function listHosts(baseUrl, ws, headers) {
  const urlA = joinUrl(baseUrl, `/_api/v3/ws/${encodeURIComponent(ws)}/hosts/`);
  const urlB = joinUrl(baseUrl, `/_api/v3/ws/${encodeURIComponent(ws)}/hosts`);
  const res = await requestWithFallback('GET', urlA, urlB, headers, null);
  if (!res.ok) return res;
  return { ...res, data: res.json };
}

async function createWorkspace(baseUrl, ws, headers, opts = {}) {
  const urlA = joinUrl(baseUrl, '/_api/v3/ws');
  const urlB = joinUrl(baseUrl, '/_api/v3/ws/');
  const payload = { name: ws, description: opts.description || '' };
  return requestWithFallback('POST', urlA, urlB, headers, payload);
}

function findHostIdInList(hosts, target) {
  if (!Array.isArray(hosts)) return null;
  for (const h of hosts) {
    const id = h && (h.id || h._id || h.obj_id);
    const ip = h && h.ip;
    const hostnames = h && h.hostnames;

    if (id && ip === target) return id;
    if (id && Array.isArray(hostnames) && hostnames.includes(target)) return id;
  }
  return null;
}

async function upsertHost(baseUrl, ws, headers, record) {
  const target = (record && record.target) || '';
  const data = (record && record.data) || {};

  let hostnames = Array.isArray(data.hostnames) ? [...data.hostnames] : [];

  // Treat non-IP targets as hostnames.
  if (target && !isIpv4(target) && !hostnames.includes(target)) hostnames.unshift(target);

  let ip = data.ip || (isIpv4(target) ? target : null);

  // Optional DNS resolution for hostname targets.
  const resolveHostnames = process.env.FARADAY_RESOLVE_HOSTNAMES === '1' || process.env.FARADAY_RESOLVE_HOSTNAMES === 'true';
  if (!ip && resolveHostnames && target) {
    try {
      const res = await dns.promises.lookup(target, { family: 4 });
      if (res && res.address) ip = res.address;
    } catch (_err) {
      // ignore resolution failures
    }
  }

  // If we still don't have an IP, keep Faraday happy and store the hostname.
  if (!ip) {
    if (!allowDummyIp()) {
      return { ok: false, status: 0, error: 'missing_ip', text: 'missing ip for hostname target (set FARADAY_RESOLVE_HOSTNAMES=true or FARADAY_ALLOW_DUMMY_IP=true)' };
    }
    ip = '0.0.0.0';
  }

  const payload = {
    ip,
    hostnames,
    mac: data.mac || '00:00:00:00:00:00',
    description: data.description || '',
    default_gateway: data.default_gateway || 'None',
    os: data.os || '',
    owned: Boolean(data.owned),
    owner: data.owner || ''
  };

  // Faraday accepts POST on the non-trailing-slash endpoint.
  const urlA = joinUrl(baseUrl, `/_api/v3/ws/${encodeURIComponent(ws)}/hosts`);
  const urlB = joinUrl(baseUrl, `/_api/v3/ws/${encodeURIComponent(ws)}/hosts/`);
  const res = await requestWithFallback('POST', urlA, urlB, headers, payload);

  if (res.ok) {
    const id = res.json && (res.json.id || res.json._id || res.json.obj_id);
    return { ...res, id, data: res.json };
  }

  // Best-effort idempotency: if it already exists, fetch and find its id.
  if (res.status === 409) {
    const list = await listHosts(baseUrl, ws, headers);
    const id = list && list.data ? findHostIdInList(list.data, target) : null;
    return { ...res, id, data: res.json };
  }

  return { ...res, data: res.json };
}

async function createVuln(baseUrl, ws, headers, record, parentId) {
  const data = (record && record.data) || {};
  const owner = process.env.FARADAY_USER || '';
  const timestamp = Date.now() / 1000;

  const name = data.name || data.category || 'Finding';
  const severity = data.severity || 'unclassified';
  const desc = data.desc || data.description || data.notes || data.summary || 'Generated from skill output';

  const payload = {
    metadata: {
      update_time: timestamp,
      update_user: '',
      update_action: 0,
      creator: 'API',
      create_time: timestamp,
      update_controller_action: 'API',
      owner
    },
    obj_id: '',
    owner,
    parent: parentId,
    parent_type: 'Host',
    type: 'Vulnerability',
    ws,
    confirmed: true,
    data: data.data || {},
    desc,
    easeofresolution: data.easeofresolution || null,
    impact: data.impact || {
      accountability: false,
      availability: false,
      confidentiality: false,
      integrity: false
    },
    name,
    owned: Boolean(data.owned),
    policyviolations: data.policyviolations || [],
    refs: data.refs || [],
    resolution: data.resolution || '',
    severity,
    issuetracker: data.issuetracker || '',
    status: data.status || 'opened',
    _attachments: {},
    description: data.description || desc,
    protocol: data.protocol || '',
    version: data.version || ''
  };

  const urlA = joinUrl(baseUrl, `/_api/v3/ws/${encodeURIComponent(ws)}/vulns/`);
  const urlB = joinUrl(baseUrl, `/_api/v3/ws/${encodeURIComponent(ws)}/vulns`);
  const res = await requestWithFallback('POST', urlA, urlB, headers, payload);
  return { ...res, data: res.json };
}

async function ingestRecord(record) {
  const baseUrl = baseUrlFromEnv();
  if (!baseUrl) return { skipped: true, reason: 'FARADAY_URL not set/invalid' };

  const ws = workspaceName(record);
  if (!ws) return { skipped: true, reason: 'FARADAY_WORKSPACE not set' };

  const headers = await authHeaders(baseUrl);
  if (!headers || Object.keys(headers).length === 0) {
    return { skipped: true, reason: 'no_auth' };
  }

  const type = record && record.type;
  if (type !== 'asset' && type !== 'finding' && type !== 'note') {
    return { skipped: true, reason: 'unsupported_type' };
  }

  if (!record || !record.target) {
    return { skipped: true, reason: 'missing_target' };
  }

  // Avoid polluting Faraday with a shared dummy IP host for hostname-only records.
  const resolveHostnames = process.env.FARADAY_RESOLVE_HOSTNAMES === '1' || process.env.FARADAY_RESOLVE_HOSTNAMES === 'true';
  if (!allowDummyIp()) {
    const data = (record && record.data) || {};
    const target = String(record.target || '');
    const hasIp = Boolean(data.ip) || isIpv4(target);
    if (!hasIp && !resolveHostnames) {
      return { skipped: true, reason: 'no_ip_for_hostname (set FARADAY_RESOLVE_HOSTNAMES=true or FARADAY_ALLOW_DUMMY_IP=true)' };
    }
  }

  const hostRes = await upsertHost(baseUrl, ws, headers, record);
  if (!hostRes.ok || !hostRes.id) {
    return { ok: false, stage: 'host', status: hostRes.status, error: hostRes.error || 'host_failed', response: hostRes.text };
  }

  if (type === 'asset') {
    return { ok: true, stage: 'host', host_id: hostRes.id };
  }

  if (type === 'note') {
    const importNotes = process.env.FARADAY_IMPORT_NOTES === '1' || process.env.FARADAY_IMPORT_NOTES === 'true';
    if (!importNotes) return { skipped: true, reason: 'notes_disabled' };

    const noteRecord = buildPayload({
      ...record,
      type: 'finding',
      data: {
        category: 'note',
        severity: 'info',
        ...((record && record.data) || {})
      }
    });

    const vulnRes = await createVuln(baseUrl, ws, headers, noteRecord, hostRes.id);
    return vulnRes.ok ? { ok: true, stage: 'vuln', vuln: vulnRes.data } : { ok: false, stage: 'vuln', status: vulnRes.status, error: vulnRes.error || 'vuln_failed', response: vulnRes.text };
  }

  const vulnRes = await createVuln(baseUrl, ws, headers, record, hostRes.id);
  return vulnRes.ok ? { ok: true, stage: 'vuln', vuln: vulnRes.data } : { ok: false, stage: 'vuln', status: vulnRes.status, error: vulnRes.error || 'vuln_failed', response: vulnRes.text };
}

module.exports = {
  buildPayload,
  ingestRecord,
  request,
  listHosts,
  createWorkspace,
  baseUrlFromEnv,
  authHeaders
};
