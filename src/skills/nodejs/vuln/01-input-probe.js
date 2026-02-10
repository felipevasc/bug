#!/usr/bin/env node
'use strict';

/**
 * @skill: nodejs/vuln/input-probe
 * @inputs: target[, out-dir, rate, timeout, allow-vuln, run-ts]
 * @outputs: finding|note
 * @tools: fetch
 */

const fs = require('fs');
const path = require('path');
const { URL } = require('node:url');
const { parseCommonArgs, emitJsonl, ensureDir, writeEvidence } = require('../../../lib/skill-utils');

const STAGE = 'vuln';
const SOURCE = 'src/skills/nodejs/vuln/01-input-probe.js';
const BENIGN_VALUES = ['alpha', 'beta', 'gamma'];
const DEFAULT_MAX_CANDIDATES = 200;
const DEFAULT_PAYLOADS_PER_PARAM = 30;
const DEFAULT_RATE = 2;
const DEFAULT_TIMEOUT = 15;
const ERROR_REGEX = /(error|exception|stack|fatal|undefined|warning|sqlstate|trace)/i;
const PAYLOAD_CATEGORIES = ['xss', 'sqli', 'ssrf', 'cmdi', 'traversal'];

function allowVulnEnabled() {
  const fromEnv = String(process.env.ALLOW_VULN || '').trim() === '1';
  const fromCli = process.argv.includes('--allow-vuln');
  return fromEnv || fromCli;
}

function safeParseJsonl(filePath) {
  if (!fs.existsSync(filePath)) return [];
  const lines = fs.readFileSync(filePath, 'utf8').split('\n');
  const out = [];
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      out.push(JSON.parse(trimmed));
    } catch (_err) {
      // ignore
    }
  }
  return out;
}

function gatherUrlsFromRecords(records) {
  const urls = new Set();
  for (const rec of records) {
    if (!rec || !rec.data) continue;
    const pushUrl = (value) => {
      if (!value) return;
      try {
        const parsed = new URL(String(value).trim());
        if (parsed.protocol && parsed.hostname) urls.add(parsed.href);
      } catch (_err) {
        // skip relative values
      }
    };

    if (Array.isArray(rec.data.urls)) {
      rec.data.urls.forEach(pushUrl);
    }
    if (rec.data.url) {
      pushUrl(rec.data.url);
    }
    if (rec.data.effective_url) {
      pushUrl(rec.data.effective_url);
    }
  }
  return urls;
}

function gatherInternalUrls(rootOut) {
  const urls = new Set();
  const crawlDir = path.join(rootOut, 'evidence', 'enum', 'crawl');
  if (!fs.existsSync(crawlDir)) return urls;
  for (const entry of fs.readdirSync(crawlDir)) {
    const entryPath = path.join(crawlDir, entry);
    const stat = fs.statSync(entryPath);
    if (!stat.isDirectory()) continue;
    const filePath = path.join(entryPath, 'urls_internal.txt');
    if (!fs.existsSync(filePath)) continue;
    const content = fs.readFileSync(filePath, 'utf8');
    content.split(/\r?\n/).forEach((line) => {
      const trimmed = line.trim();
      if (trimmed) {
        try {
          const parsed = new URL(trimmed);
          urls.add(parsed.href);
        } catch (_err) {
          // skip
        }
      }
    });
  }
  return urls;
}

function parseAttributes(attrText) {
  const attrs = {};
  const re = /([a-zA-Z0-9_:\-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/gi;
  let match;
  while ((match = re.exec(attrText))) {
    const key = match[1].toLowerCase();
    const value = match[2] || match[3] || match[4] || '';
    attrs[key] = value;
  }
  return attrs;
}

function parseFormInputs(formHtml) {
  const inputs = {};
  const addInput = (name, value) => {
    if (!name) return;
    if (inputs[name]) return;
    inputs[name] = value;
  };

  const inputRe = /<input\b([^>]*)\/?\s*>/gi;
  let match;
  while ((match = inputRe.exec(formHtml))) {
    const attrs = parseAttributes(match[1]);
    const name = attrs.name;
    if (!name) continue;
    const type = (attrs.type || 'text').toLowerCase();
    if (['submit', 'button', 'reset', 'image'].includes(type)) continue;
    addInput(name, attrs.value || '1');
  }

  const textareaRe = /<textarea\b([^>]*)>([\s\S]*?)<\/textarea>/gi;
  while ((match = textareaRe.exec(formHtml))) {
    const attrs = parseAttributes(match[1]);
    const name = attrs.name;
    if (!name) continue;
    addInput(name, match[2].trim() || attrs.value || '1');
  }

  const selectRe = /<select\b([^>]*)>([\s\S]*?)<\/select>/gi;
  while ((match = selectRe.exec(formHtml))) {
    const attrs = parseAttributes(match[1]);
    const name = attrs.name;
    if (!name) continue;
    const optionRe = /<option\b([^>]*)>([\s\S]*?)<\/option>/gi;
    let defaultValue = null;
    let optionMatch;
    while ((optionMatch = optionRe.exec(match[2]))) {
      const optionAttrs = parseAttributes(optionMatch[1]);
      const textValue = (optionAttrs.value || optionMatch[2] || '').trim();
      const isSelected = /\bselected\b/i.test(optionMatch[1]);
      if (isSelected) {
        defaultValue = textValue || defaultValue;
        break;
      }
      if (defaultValue === null) {
        defaultValue = textValue;
      }
    }
    addInput(name, defaultValue || '1');
  }

  return inputs;
}

function parseFormsFromPage(html, baseUrl) {
  const forms = [];
  const formRe = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let match;
  while ((match = formRe.exec(html))) {
    const attrs = parseAttributes(match[1] || '');
    const method = (attrs.method || 'get').toUpperCase();
    const actionValue = attrs.action || '';
    let resolvedAction = '';
    try {
      resolvedAction = new URL(actionValue || baseUrl, baseUrl).href;
    } catch (_err) {
      resolvedAction = '';
    }
    if (!resolvedAction.startsWith('http://') && !resolvedAction.startsWith('https://')) {
      continue;
    }
    const inputs = parseFormInputs(match[2] || '');
    if (!Object.keys(inputs).length) continue;
    forms.push({
      action: resolvedAction,
      method,
      inputs
    });
  }
  return forms;
}

function gatherForms(rootOut, target, crawlBase) {
  const forms = [];
  const crawlDir = path.join(rootOut, 'evidence', 'enum', 'crawl');
  const fallbackBase = crawlBase || `https://${target}/`;
  if (!fs.existsSync(crawlDir)) return forms;
  for (const entry of fs.readdirSync(crawlDir)) {
    const entryPath = path.join(crawlDir, entry);
    const stat = fs.statSync(entryPath);
    if (!stat.isDirectory()) continue;
    const pagePath = path.join(entryPath, 'page.html');
    if (!fs.existsSync(pagePath)) continue;
    const html = fs.readFileSync(pagePath, 'utf8');
    const baseUrl = entry && entry.includes('.') ? `https://${entry}/` : fallbackBase;
    forms.push(...parseFormsFromPage(html, baseUrl));
  }
  return forms;
}

function buildCandidates(urls, forms, maxCandidates) {
  const seen = new Map();

  const addCandidate = (candidate) => {
    const key = `${candidate.method}|${candidate.baseUrl}|${candidate.param}`;
    if (!candidate.param || !candidate.baseUrl) return;
    if (seen.has(key)) return;
    seen.set(key, candidate);
  };

  for (const rawUrl of urls) {
    let parsed;
    try {
      parsed = new URL(rawUrl);
    } catch (_err) {
      continue;
    }
    const baseUrl = `${parsed.origin}${parsed.pathname}`;
    const params = Array.from(parsed.searchParams.entries());
    if (!params.length) continue;
    for (const [name, value] of params) {
      const baseParams = {};
      parsed.searchParams.forEach((v, k) => {
        if (k === name) return;
        baseParams[k] = v;
      });
      addCandidate({
        method: 'GET',
        baseUrl,
        param: name,
        baseParams,
        originalUrl: rawUrl,
        source: 'query'
      });
    }
  }

  for (const form of forms) {
    const method = form.method === 'POST' ? 'POST' : 'GET';
    const baseUrl = form.action;
    const fields = Object.entries(form.inputs);
    for (const [name, value] of fields) {
      const baseParams = {};
      for (const [k, v] of fields) {
        if (k === name) continue;
        baseParams[k] = v;
      }
      addCandidate({
        method,
        baseUrl,
        param: name,
        baseParams,
        source: 'form'
      });
    }
  }

  const ordered = Array.from(seen.values()).sort((a, b) => {
    if (a.baseUrl !== b.baseUrl) return a.baseUrl.localeCompare(b.baseUrl);
    return a.param.localeCompare(b.param);
  });

  if (maxCandidates && ordered.length > maxCandidates) {
    return ordered.slice(0, maxCandidates);
  }
  return ordered;
}

function loadPayloads() {
  const payloadRoot = path.resolve(__dirname, '../../../..', 'wordlists', 'payloads');
  const entries = [];
  for (const category of PAYLOAD_CATEGORIES) {
    const filePath = path.join(payloadRoot, `${category}.txt`);
    if (!fs.existsSync(filePath)) continue;
    const lines = fs.readFileSync(filePath, 'utf8').split(/\r?\n/);
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      entries.push({ category, payload: trimmed });
    }
  }
  return entries;
}

function analyzeBaseline(baselines) {
  const statuses = baselines
    .map((item) => Number(item.status))
    .filter((n) => Number.isFinite(n));
  const lengths = baselines
    .map((item) => Number(item.length))
    .filter((n) => Number.isFinite(n));
  const durations = baselines
    .map((item) => Number(item.duration))
    .filter((n) => Number.isFinite(n));

  const statusMode = (() => {
    if (!statuses.length) return null;
    const freq = new Map();
    let best = statuses[0];
    for (const value of statuses) {
      freq.set(value, (freq.get(value) || 0) + 1);
      if ((freq.get(value) || 0) > (freq.get(best) || 0)) {
        best = value;
      }
    }
    return best;
  })();

  const avgLen = lengths.length ? lengths.reduce((a, b) => a + b, 0) / lengths.length : null;
  const avgDuration = durations.length ? durations.reduce((a, b) => a + b, 0) / durations.length : null;

  return { statusMode, avgLen, avgDuration };
}

function detectAnomalies(result, baselineStats) {
  const reasons = new Set();
  if (result.error) {
    reasons.add('error');
    if (ERROR_REGEX.test(result.error)) reasons.add('error-regex');
  } else {
    if (baselineStats.statusMode !== null && result.status !== baselineStats.statusMode) {
      reasons.add('status-change');
    }
    if (baselineStats.avgLen !== null && Math.abs(result.length - baselineStats.avgLen) / Math.max(baselineStats.avgLen, 1) > 0.3) {
      reasons.add('length-change');
    }
    if (baselineStats.avgDuration !== null && result.duration > (baselineStats.avgDuration || 0) * 2 + 200) {
      reasons.add('time-spike');
    }
    if (ERROR_REGEX.test(result.bodySnippet || '')) {
      reasons.add('error-regex');
    }
  }
  return Array.from(reasons);
}

function buildRequest(candidate, value) {
  const method = candidate.method || 'GET';
  if (method === 'GET') {
    const url = new URL(candidate.baseUrl);
    Object.entries(candidate.baseParams || {}).forEach(([k, v]) => {
      url.searchParams.set(k, String(v));
    });
    url.searchParams.set(candidate.param, value);
    return { url: url.href, options: { method: 'GET', headers: { 'User-Agent': 'biascan-input-probe/1.0' } }, payload: '' };
  }

  const url = candidate.baseUrl;
  const params = new URLSearchParams();
  Object.entries(candidate.baseParams || {}).forEach(([k, v]) => {
    params.set(k, String(v));
  });
  params.set(candidate.param, value);
  return {
    url,
    options: {
      method: 'POST',
      headers: {
        'User-Agent': 'biascan-input-probe/1.0',
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: params.toString()
    },
    payload: params.toString()
  };
}

function snip(value) {
  return value ? String(value).slice(0, 512) : '';
}

function safeFileSegment(value) {
  return String(value || '').replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 64);
}

async function sendRequest(timeoutSec, candidate, probeValue) {
  const { url, options } = buildRequest(candidate, probeValue);
  const controller = new AbortController();
  const timer = timeoutSec > 0 ? setTimeout(() => controller.abort(), timeoutSec * 1000) : null;
  const start = Date.now();
  let response;
  let bodyText = '';
  let error = null;
  try {
    response = await fetch(url, { ...options, signal: controller.signal });
    bodyText = await response.text();
  } catch (err) {
    error = err && err.message ? err.message : String(err);
  } finally {
    if (timer) clearTimeout(timer);
  }
  const duration = Date.now() - start;
  const status = response ? response.status : null;
  const length = bodyText ? Buffer.byteLength(bodyText, 'utf8') : 0;
  return {
    status,
    length,
    duration,
    error,
    bodySnippet: snip(bodyText),
    body: bodyText,
    url,
    options
  };
}

async function run({ target, emit, outDir, rate, timeout, runTs }) {
  if (!target) {
    emitJsonl(emit, {
      type: 'note',
      tool: 'input-probe',
      stage: STAGE,
      target: '',
      severity: 'info',
      evidence: [],
      data: { message: 'No target specified; input probing skipped.' },
      source: SOURCE
    });
    return;
  }

  if (!allowVulnEnabled()) {
    emitJsonl(emit, {
      type: 'note',
      tool: 'input-probe',
      stage: STAGE,
      target,
      severity: 'info',
      evidence: [],
      data: { skipped: true, reason: 'allow-vuln flag not set' },
      source: SOURCE
    });
    return;
  }

  const rootOut = outDir || process.env.OUT_DIR || path.resolve('data', 'runs', runTs || 'run');
  const recordsPath = path.join(rootOut, 'records.jsonl');
  const records = safeParseJsonl(recordsPath);
  if (!records.length) {
    emitJsonl(emit, {
      type: 'note',
      tool: 'input-probe',
      stage: STAGE,
      target,
      severity: 'info',
      evidence: [],
      data: { reason: 'No records available for input discovery' },
      source: SOURCE
    });
    return;
  }

  const parsedMaxCandidates = Number(process.env.INPUT_PROBE_MAX_CANDIDATES || DEFAULT_MAX_CANDIDATES);
  const maxCandidates = Number.isFinite(parsedMaxCandidates) && parsedMaxCandidates > 0
    ? parsedMaxCandidates
    : DEFAULT_MAX_CANDIDATES;
  const parsedPayloadsPerParam = Number(process.env.PAYLOADS_PER_PARAM || DEFAULT_PAYLOADS_PER_PARAM);
  const payloadsPerParam = Number.isFinite(parsedPayloadsPerParam) && parsedPayloadsPerParam > 0
    ? parsedPayloadsPerParam
    : DEFAULT_PAYLOADS_PER_PARAM;
  const configuredRate = Number(rate || process.env.RATE || DEFAULT_RATE);
  const rateDelayMs = Math.max(0, Math.ceil(1000 / Math.max(configuredRate, 1)));
  const configuredTimeout = Number(timeout || process.env.TIMEOUT || DEFAULT_TIMEOUT);

  const urls = gatherUrlsFromRecords(records);
  gatherInternalUrls(rootOut).forEach((url) => urls.add(url));
  const crawlBase = records.find((rec) => rec.tool === 'wget-crawl' && rec.data && rec.data.base_url);
  const crawlBaseUrl = crawlBase && crawlBase.data ? crawlBase.data.base_url : null;
  const forms = gatherForms(rootOut, target, crawlBaseUrl);
  const candidates = buildCandidates(urls, forms, maxCandidates);

  if (!candidates.length) {
    emitJsonl(emit, {
      type: 'note',
      tool: 'input-probe',
      stage: STAGE,
      target,
      severity: 'info',
      evidence: [],
      data: { message: 'No parameter candidates were discovered.' },
      source: SOURCE
    });
    return;
  }

  const payloadRegistry = loadPayloads();
  if (!payloadRegistry.length) {
    emitJsonl(emit, {
      type: 'note',
      tool: 'input-probe',
      stage: STAGE,
      target,
      severity: 'info',
      evidence: [],
      data: { message: 'No payloads available to probe parameters.' },
      source: SOURCE
    });
    return;
  }

  const evidenceDir = path.join(rootOut, 'evidence', 'vuln', 'input-probe', target.replace(/[^a-zA-Z0-9._-]/g, '_'));
  ensureDir(evidenceDir);

  let anomalyCount = 0;
  let lastRequestTs = 0;

  const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const nextRequestReady = async () => {
    if (!rateDelayMs) return;
    const now = Date.now();
    if (lastRequestTs && now < lastRequestTs + rateDelayMs) {
      await wait(lastRequestTs + rateDelayMs - now);
    }
    lastRequestTs = Date.now();
  };

  const perParamLimit = Math.max(1, payloadsPerParam);
  for (const candidate of candidates) {
    const baselineResults = [];
    for (const benign of BENIGN_VALUES) {
      await nextRequestReady();
      const result = await sendRequest(configuredTimeout, candidate, benign);
      baselineResults.push(result);
    }
    const baselineStats = analyzeBaseline(baselineResults);
    if (!baselineStats.statusMode && baselineStats.avgLen === null) {
      continue;
    }

    const limitedPayloads = payloadRegistry.slice(0, perParamLimit);
    for (const entry of limitedPayloads) {
      await nextRequestReady();
      const probeResult = await sendRequest(configuredTimeout, candidate, entry.payload);
      const anomalies = detectAnomalies(probeResult, baselineStats);
      if (!anomalies.length) continue;
      anomalyCount += 1;
      const snippetName = `${Date.now()}-${anomalyCount}-${safeFileSegment(candidate.param)}-${safeFileSegment(entry.category)}.json`;
      const snippetPath = writeEvidence(evidenceDir, snippetName, JSON.stringify({
        target,
        candidate,
        payload: entry.payload,
        category: entry.category,
        anomaly: anomalies,
        response: {
          status: probeResult.status,
          length: probeResult.length,
          duration: probeResult.duration,
          error: probeResult.error,
          snippet: probeResult.bodySnippet
        },
        timestamp: new Date().toISOString()
      }, null, 2));

      emitJsonl(emit, {
        type: 'finding',
        tool: 'input-probe',
        stage: STAGE,
        target,
        severity: 'low',
        evidence: [snippetPath],
        data: {
          url: candidate.baseUrl,
          method: candidate.method,
          param: candidate.param,
          payload: entry.payload,
          category: entry.category,
          anomalies,
          baseline: {
            status: baselineStats.statusMode,
            avg_length: baselineStats.avgLen,
            avg_duration: baselineStats.avgDuration
          },
          probe_type: candidate.source
        },
        source: SOURCE
      });
    }
  }

  emitJsonl(emit, {
    type: 'note',
    tool: 'input-probe',
    stage: STAGE,
    target,
    severity: 'info',
    evidence: [],
    data: {
      candidates: candidates.length,
      payloads_per_param: payloadRegistry.length ? Math.min(payloadRegistry.length, perParamLimit) : 0,
      anomalies: anomalyCount
    },
    source: SOURCE
  });
}

module.exports = { run };

if (require.main === module) {
  const args = parseCommonArgs(process.argv.slice(2));
  const target = args.target || args.url || '';
  if (!target) {
    // eslint-disable-next-line no-console
    console.error('Usage: 01-input-probe.js --target <host> --allow-vuln [--out-dir dir] [--rate n] [--timeout s]');
    process.exit(1);
  }
  run({
    target,
    outDir: args.outDir,
    rate: args.rate,
    timeout: args.timeout,
    runTs: process.env.RUN_TS || '' ,
    emit: (rec) => process.stdout.write(`${JSON.stringify(rec)}\n`)
  }).catch((err) => {
    // eslint-disable-next-line no-console
    console.error(err);
    process.exit(1);
  });
}
