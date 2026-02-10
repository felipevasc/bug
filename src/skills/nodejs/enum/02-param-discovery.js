#!/usr/bin/env node
'use strict';

/**
 * @skill: nodejs/enum/param-discovery
 * @inputs: target[, out-dir, max-urls, max-fetch, rate, timeout, run-ts]
 * @outputs: asset|note
 * @tools: fetch
 */

const fs = require('fs');
const path = require('path');
const { URL } = require('node:url');
const { parseCommonArgs, emitJsonl, ensureDir, writeEvidence } = require('../../../lib/skill-utils');

const STAGE = 'enum';
const SOURCE = 'src/skills/nodejs/enum/02-param-discovery.js';

const DEFAULT_MAX_URLS = 4000;       // read from urls_internal
const DEFAULT_MAX_FETCH = 120;       // fetch top pages to extract forms
const DEFAULT_RATE = 5;             // req/s
const DEFAULT_TIMEOUT = 15;         // seconds

const STATIC_EXTENSIONS = new Set(['.js', '.css', '.png', '.jpg', '.jpeg', '.svg', '.woff', '.woff2', '.ttf', '.otf', '.ico', '.map', '.gif', '.bmp', '.webp', '.pdf', '.zip', '.gz', '.tar', '.7z', '.mp4', '.mp3']);

function safeParseJsonl(filePath) {
  if (!fs.existsSync(filePath)) return [];
  const out = [];
  const lines = fs.readFileSync(filePath, 'utf8').split(/\r?\n/);
  for (const line of lines) {
    const t = line.trim();
    if (!t) continue;
    try { out.push(JSON.parse(t)); } catch { /* ignore */ }
  }
  return out;
}

function safeHostSegment(v) {
  return String(v || '').replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 80);
}

function snip(text, n = 800) {
  return String(text || '').slice(0, n);
}

function parseAttributes(attrText) {
  const attrs = {};
  const re = /([a-zA-Z0-9_:\-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g;
  let m;
  while ((m = re.exec(attrText))) {
    const key = (m[1] || '').toLowerCase();
    const val = m[2] || m[3] || m[4] || '';
    if (!key) continue;
    attrs[key] = val;
  }
  return attrs;
}

function parseFormInputs(formHtml) {
  const inputs = [];
  const add = (name, type, value) => {
    if (!name) return;
    inputs.push({ name, type: type || 'text', value: value || '' });
  };

  const inputRe = /<input\b([^>]*)\/?\s*>/gi;
  let m;
  while ((m = inputRe.exec(formHtml))) {
    const attrs = parseAttributes(m[1] || '');
    const name = attrs.name;
    const type = (attrs.type || 'text').toLowerCase();
    if (!name) continue;
    if (['submit', 'button', 'reset', 'image'].includes(type)) continue;
    add(name, type, attrs.value || '');
  }

  const textareaRe = /<textarea\b([^>]*)>([\s\S]*?)<\/textarea>/gi;
  while ((m = textareaRe.exec(formHtml))) {
    const attrs = parseAttributes(m[1] || '');
    const name = attrs.name;
    if (!name) continue;
    add(name, 'textarea', (m[2] || '').trim());
  }

  const selectRe = /<select\b([^>]*)>([\s\S]*?)<\/select>/gi;
  while ((m = selectRe.exec(formHtml))) {
    const attrs = parseAttributes(m[1] || '');
    const name = attrs.name;
    if (!name) continue;
    // pick first option
    const optRe = /<option\b([^>]*)>([\s\S]*?)<\/option>/gi;
    let opt;
    let pick = '';
    while ((opt = optRe.exec(m[2] || ''))) {
      const optAttrs = parseAttributes(opt[1] || '');
      pick = (optAttrs.value || opt[2] || '').trim();
      break;
    }
    add(name, 'select', pick);
  }

  return inputs;
}

function parseFormsFromHtml(html, baseUrl) {
  const forms = [];
  const formRe = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let m;
  while ((m = formRe.exec(html))) {
    const attrs = parseAttributes(m[1] || '');
    const method = (attrs.method || 'get').toUpperCase() === 'POST' ? 'POST' : 'GET';
    const actionRaw = attrs.action || '';
    let action = '';
    try { action = new URL(actionRaw || baseUrl, baseUrl).href; } catch { action = ''; }
    if (!/^https?:\/\//i.test(action)) continue;
    const inputs = parseFormInputs(m[2] || '');
    if (!inputs.length) continue;
    forms.push({ action, method, inputs });
  }
  return forms;
}

function isStaticUrl(u) {
  try {
    const p = new URL(u);
    const ext = path.extname(p.pathname || '').toLowerCase();
    return STATIC_EXTENSIONS.has(ext);
  } catch {
    return true;
  }
}

function loadInternalUrlsFromRecords(records) {
  const paths = [];
  for (const rec of records) {
    if (rec && rec.type === 'asset' && rec.tool === 'wget-crawl' && rec.evidence && rec.evidence.length) {
      const found = rec.evidence.find((p) => String(p).endsWith('urls_internal.txt'));
      if (found) paths.push(found);
    }
  }
  const urls = new Set();
  for (const p of paths) {
    const fp = path.isAbsolute(p) ? p : path.resolve(p);
    if (!fs.existsSync(fp)) continue;
    const lines = fs.readFileSync(fp, 'utf8').split(/\r?\n/);
    for (const line of lines) {
      const t = line.trim();
      if (!t) continue;
      try {
        const u = new URL(t);
        if (u.protocol === 'http:' || u.protocol === 'https:') urls.add(u.href);
      } catch {
        // ignore
      }
    }
  }
  return Array.from(urls);
}

async function fetchText(url, timeoutSec) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), Math.max(1, timeoutSec) * 1000);
  const start = Date.now();
  try {
    const res = await fetch(url, {
      method: 'GET',
      headers: { 'User-Agent': 'biascan-param-discovery/1.0', 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' },
      signal: controller.signal
    });
    const body = await res.text();
    return { ok: res.ok, status: res.status, body, duration: Date.now() - start };
  } catch (err) {
    return { ok: false, status: null, body: '', error: err?.message || String(err), duration: Date.now() - start };
  } finally {
    clearTimeout(timer);
  }
}

async function run({ target, emit, outDir, runTs }) {
  if (!target) {
    emitJsonl(emit, { type: 'note', tool: 'param-discovery', stage: STAGE, target: '', severity: 'info', evidence: [], data: { message: 'No target specified.' }, source: SOURCE });
    return;
  }

  const rootOut = outDir || process.env.OUT_DIR || path.resolve('data', 'runs', runTs || 'run');
  const recordsPath = path.join(rootOut, 'records.jsonl');
  const records = safeParseJsonl(recordsPath);

  const maxUrls = Number(process.env.PARAM_DISCOVERY_MAX_URLS || DEFAULT_MAX_URLS);
  const maxFetch = Number(process.env.PARAM_DISCOVERY_MAX_FETCH || DEFAULT_MAX_FETCH);
  const timeout = Number(process.env.PARAM_DISCOVERY_TIMEOUT || DEFAULT_TIMEOUT);
  const rate = Number(process.env.PARAM_DISCOVERY_RATE || DEFAULT_RATE);
  const delayMs = Math.max(0, Math.ceil(1000 / Math.max(1, rate)));

  const urlsAll = loadInternalUrlsFromRecords(records).slice(0, Number.isFinite(maxUrls) ? maxUrls : DEFAULT_MAX_URLS);

  const queryParams = new Map(); // name -> count
  const endpoints = new Map(); // baseUrl -> {count, sample}

  const addParam = (name) => {
    if (!name) return;
    queryParams.set(name, (queryParams.get(name) || 0) + 1);
  };

  for (const u of urlsAll) {
    try {
      const parsed = new URL(u);
      const base = `${parsed.origin}${parsed.pathname}`;
      endpoints.set(base, (endpoints.get(base) || 0) + 1);
      for (const [k] of parsed.searchParams.entries()) addParam(k);
    } catch {
      // ignore
    }
  }

  // pick pages to fetch for forms: prefer those with no static ext and with path depth.
  const candidates = urlsAll
    .filter((u) => !isStaticUrl(u))
    .filter((u) => !u.includes('#'));

  const chosen = [];
  const seenBase = new Set();
  for (const u of candidates) {
    let base;
    try {
      const parsed = new URL(u);
      base = `${parsed.origin}${parsed.pathname}`;
    } catch {
      continue;
    }
    if (seenBase.has(base)) continue;
    seenBase.add(base);
    chosen.push(u);
    if (chosen.length >= maxFetch) break;
  }

  const evidenceDir = path.join(rootOut, 'evidence', 'enum', 'param-discovery', safeHostSegment(target));
  ensureDir(evidenceDir);

  const forms = [];
  let fetched = 0;
  let lastTs = 0;
  const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  const next = async () => {
    if (!delayMs) return;
    const now = Date.now();
    if (lastTs && now < lastTs + delayMs) await wait(lastTs + delayMs - now);
    lastTs = Date.now();
  };

  for (const u of chosen) {
    await next();
    const res = await fetchText(u, timeout);
    fetched += 1;
    if (!res.ok || !res.body) continue;
    const pageForms = parseFormsFromHtml(res.body, u);
    for (const f of pageForms) {
      forms.push(f);
      for (const inp of f.inputs) addParam(inp.name);
      endpoints.set(f.action, (endpoints.get(f.action) || 0) + 1);
    }

    // evidence sample, bounded
    if (pageForms.length) {
      const fp = writeEvidence(evidenceDir, `${Date.now()}-${fetched}.json`, JSON.stringify({ url: u, status: res.status, duration_ms: res.duration, forms: pageForms, sample: snip(res.body, 1200) }, null, 2));
      emitJsonl(emit, { type: 'note', tool: 'param-discovery', stage: STAGE, target, severity: 'info', evidence: [fp], data: { url: u, forms: pageForms.length }, source: SOURCE });
    }
  }

  const topParams = Array.from(queryParams.entries()).sort((a, b) => b[1] - a[1]).slice(0, 200).map(([name, count]) => ({ name, count }));
  const topEndpoints = Array.from(endpoints.entries()).sort((a, b) => b[1] - a[1]).slice(0, 400).map(([url, count]) => ({ url, count }));

  const summaryPath = writeEvidence(evidenceDir, 'summary.json', JSON.stringify({ target, urls_seen: urlsAll.length, pages_fetched: fetched, forms_found: forms.length, topParams: topParams.slice(0, 50), topEndpoints: topEndpoints.slice(0, 50) }, null, 2));

  emitJsonl(emit, {
    type: 'asset',
    tool: 'param-discovery',
    stage: STAGE,
    target,
    severity: 'info',
    evidence: [summaryPath],
    data: {
      urls_seen: urlsAll.length,
      pages_fetched: fetched,
      forms_found: forms.length,
      endpoints: topEndpoints,
      params: topParams,
      forms: forms.slice(0, 200) // bounded
    },
    source: SOURCE
  });
}

module.exports = { run };

if (require.main === module) {
  const args = parseCommonArgs(process.argv.slice(2));
  const target = args.target || args.url || '';
  run({
    target,
    outDir: args.outDir,
    runTs: process.env.RUN_TS || '',
    emit: (rec) => process.stdout.write(`${JSON.stringify(rec)}\n`)
  }).catch((err) => {
    // eslint-disable-next-line no-console
    console.error(err);
    process.exit(1);
  });
}
