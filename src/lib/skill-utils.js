#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const { normalizeRecord } = require('./schema');

function nowIso() {
  return new Date().toISOString();
}

function ensureDir(p) {
  fs.mkdirSync(p, { recursive: true });
}

function which(bin) {
  try {
    const { status } = require('child_process').spawnSync('bash', ['-lc', `command -v ${bin} >/dev/null 2>&1`], { stdio: 'ignore' });
    return status === 0;
  } catch (_e) {
    return false;
  }
}

function parseCommonArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const k = argv[i];
    const v = argv[i + 1];
    if (k === '--target' && v) { args.target = v; i += 1; continue; }
    if (k === '--url' && v) { args.url = v; i += 1; continue; }
    if (k === '--out-dir' && v) { args.outDir = v; i += 1; continue; }
    if (k === '--scope-file' && v) { args.scopeFile = v; i += 1; continue; }
    if (k === '--rate' && v) { args.rate = v; i += 1; continue; }
    if (k === '--timeout' && v) { args.timeout = v; i += 1; continue; }
    if (k === '--allow-exploit') { args.allowExploit = true; continue; }
  }
  return args;
}

function emitJsonl(emit, record) {
  const normalized = normalizeRecord(record, {
    ts: record && (record.ts || record.timestamp) ? (record.ts || record.timestamp) : nowIso(),
    source: record && record.source ? record.source : 'src/lib/skill-utils.js'
  });
  emit(normalized);
}

function runCmdCapture(cmd, argv, opts = {}) {
  return new Promise((resolve) => {
    const child = spawn(cmd, argv, { stdio: ['ignore', 'pipe', 'pipe'], env: opts.env || process.env });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; if (opts.streamStderr) process.stderr.write(d); });
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

function writeEvidence(outDir, relName, content) {
  ensureDir(outDir);
  const p = path.join(outDir, relName);
  ensureDir(path.dirname(p));
  fs.writeFileSync(p, content);
  return p;
}

module.exports = {
  nowIso,
  ensureDir,
  which,
  parseCommonArgs,
  emitJsonl,
  runCmdCapture,
  writeEvidence
};
