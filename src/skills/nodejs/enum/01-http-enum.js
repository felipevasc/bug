#!/usr/bin/env node
'use strict';

/**
 * @skill: nodejs/enum/http-enum
 * @inputs: target[, out-dir, scope-file, rate, timeout]
 * @outputs: asset|finding|note
 * @tools: httpx, whatweb, sslscan, nikto, curl
 */

const fs = require('fs');
const path = require('path');
const { loadScopeFile, targetInScope } = require('../../../lib/scope');
const { parseCommonArgs, emitJsonl, which, runCmdCapture, writeEvidence, ensureDir } = require('../../../lib/skill-utils');

const STAGE = 'enum';
const SOURCE = 'src/skills/nodejs/enum/01-http-enum.js';

function safeOutDir(outDir, runTs) {
  const root = outDir || process.env.OUT_DIR || path.resolve('data', 'runs', runTs || 'run');
  const dir = path.join(root, 'evidence', 'enum', 'http');
  ensureDir(dir);
  return dir;
}

function parseHttpxJsonLines(txt) {
  const urls = [];
  txt.split('\n').forEach((l) => {
    const line = l.trim();
    if (!line) return;
    try {
      const obj = JSON.parse(line);
      if (obj && obj.url) urls.push(obj.url);
      else if (obj && obj.input && typeof obj.input === 'string') urls.push(obj.input);
    } catch (_e) {
      // -silent output is plain URL
      urls.push(line);
    }
  });
  return Array.from(new Set(urls));
}

async function run({ target, emit, outDir, scopeFile, rate, timeout, runTs }) {
  const scope = loadScopeFile(scopeFile);
  if (!targetInScope(target, scope.entries)) {
    emitJsonl(emit, {
      type: 'note',
      tool: 'scope',
      stage: STAGE,
      target,
      severity: 'info',
      evidence: [`out_of_scope: ${target}`],
      data: { reason: 'target not in scope (blocked)' },
      source: SOURCE
    });
    return;
  }

  const evDir = safeOutDir(outDir, runTs);
  const maxSecs = Number(timeout || 20);
  const urls = [];
  const evidence = [];

  if (which('httpx')) {
    const rateArg = rate ? `-rl ${Number(rate)}` : '';
    const cmd = `printf '%s\\n' ${JSON.stringify(target)} | timeout ${maxSecs}s httpx -silent -json ${rateArg} 2>/dev/null || true`;
    const res = await runCmdCapture('bash', ['-lc', cmd]);
    const p = writeEvidence(evDir, `${target}.httpx.jsonl`, res.stdout || '');
    evidence.push(p);
    parseHttpxJsonLines(res.stdout || '').forEach((u) => urls.push(u));
  } else {
    // fallback: try https and http with curl
    emitJsonl(emit, {
      type: 'note',
      tool: 'httpx',
      stage: STAGE,
      target,
      severity: 'info',
      evidence: [],
      data: { skipped: true, reason: 'tool not found; using curl fallback' },
      source: SOURCE
    });
    urls.push(`https://${target}/`, `http://${target}/`);
  }

  const uniqueUrls = Array.from(new Set(urls));
  if (uniqueUrls.length === 0) {
    emitJsonl(emit, {
      type: 'note',
      tool: 'http-enum',
      stage: STAGE,
      target,
      severity: 'info',
      evidence,
      data: { message: 'no http endpoints detected' },
      source: SOURCE
    });
    return;
  }

  emitJsonl(emit, {
    type: 'asset',
    tool: 'httpx',
    stage: STAGE,
    target,
    severity: 'info',
    evidence,
    data: { urls: uniqueUrls },
    source: SOURCE
  });

  for (const url of uniqueUrls.slice(0, 20)) {
    // eslint-disable-next-line no-await-in-loop
    if (which('whatweb')) {
      const res = await runCmdCapture('bash', ['-lc', `timeout ${maxSecs}s whatweb --no-errors -a 1 ${JSON.stringify(url)} 2>/dev/null || true`]);
      const p = writeEvidence(evDir, `${target}.${Buffer.from(url).toString('base64url')}.whatweb.txt`, res.stdout || '');
      emitJsonl(emit, {
        type: 'finding',
        tool: 'whatweb',
        stage: STAGE,
        target,
        severity: 'info',
        evidence: [p],
        data: { url, fingerprint: (res.stdout || '').trim().slice(0, 500) },
        source: SOURCE
      });
    }
  }

  // Light TLS check (only if https is present)
  const httpsUrl = uniqueUrls.find((u) => u.startsWith('https://'));
  if (httpsUrl && which('sslscan')) {
    const host = httpsUrl.replace(/^https:\/\//, '').split('/')[0];
    const res = await runCmdCapture('bash', ['-lc', `timeout ${Math.max(maxSecs, 30)}s sslscan --no-colour ${JSON.stringify(host)} 2>/dev/null || true`]);
    const p = writeEvidence(evDir, `${target}.sslscan.txt`, res.stdout || '');
    const weak = /SSLv2|SSLv3|TLSv1\.0|TLSv1\.1/i.test(res.stdout || '');
    emitJsonl(emit, {
      type: 'finding',
      tool: 'sslscan',
      stage: STAGE,
      target,
      severity: weak ? 'med' : 'info',
      evidence: [p],
      data: { host, weak_protocols: weak },
      source: SOURCE
    });
  }
}

function defaultEmit(record) {
  if (!record.ts) record.ts = new Date().toISOString();
  if (!record.timestamp) record.timestamp = record.ts;
  process.stdout.write(`${JSON.stringify(record)}\n`);
}

module.exports = { run };

if (require.main === module) {
  // CLI
  (async () => {
    const args = parseCommonArgs(process.argv.slice(2));
    if (!args.target) {
      process.stderr.write('Usage: --target <host> [--out-dir dir] [--scope-file file] [--rate n] [--timeout sec]\n');
      process.exit(1);
    }
    await run({
      target: args.target,
      emit: defaultEmit,
      outDir: args.outDir,
      scopeFile: args.scopeFile,
      rate: args.rate,
      timeout: args.timeout,
      runTs: process.env.RUN_TS || ''
    });
  })().catch((e) => {
    process.stderr.write(`${e && e.stack ? e.stack : String(e)}\n`);
    process.exit(1);
  });
}
