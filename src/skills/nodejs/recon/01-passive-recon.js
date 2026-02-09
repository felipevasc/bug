#!/usr/bin/env node
'use strict';

/**
 * @skill: nodejs/recon/passive-recon
 * @inputs: target[, out-dir, scope-file, rate, timeout]
 * @outputs: asset|note
 * @tools: whois, theHarvester
 */

const path = require('path');
const { loadScopeFile, targetInScope } = require('../../../lib/scope');
const { parseCommonArgs, emitJsonl, which, runCmdCapture, writeEvidence, ensureDir } = require('../../../lib/skill-utils');

const STAGE = 'recon';
const SOURCE = 'src/skills/nodejs/recon/01-passive-recon.js';

function safeOutDir(outDir, runTs) {
  const root = outDir || process.env.OUT_DIR || path.resolve('data', 'runs', runTs || 'run');
  const dir = path.join(root, 'evidence', 'recon', 'passive');
  ensureDir(dir);
  return dir;
}

async function run({ target, emit, outDir, scopeFile, timeout, runTs }) {
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
  const evidence = [];

  if (which('whois')) {
    const res = await runCmdCapture('bash', ['-lc', `timeout ${maxSecs}s whois ${JSON.stringify(target)}`], { streamStderr: true });
    const p = writeEvidence(evDir, `${target}.whois.txt`, res.stdout || res.stderr || '');
    evidence.push(p);
  } else {
    emitJsonl(emit, {
      type: 'note',
      tool: 'whois',
      stage: STAGE,
      target,
      severity: 'info',
      evidence: [],
      data: { skipped: true, reason: 'tool not found' },
      source: SOURCE
    });
  }

  if (which('theHarvester')) {
    // theHarvester output is noisy; keep it in evidence and emit a note.
    const outJson = path.join(evDir, `${target}.theharvester.json`);
    const cmd = [
      'bash',
      ['-lc', `timeout ${maxSecs}s theHarvester -d ${JSON.stringify(target)} -b all -f ${JSON.stringify(outJson)} >/dev/null 2>&1 || true`]
    ];
    // eslint-disable-next-line no-unused-vars
    const [_c, argv] = cmd;
    await runCmdCapture(_c, argv, { streamStderr: false });
    if (require('fs').existsSync(outJson)) evidence.push(outJson);
  } else {
    emitJsonl(emit, {
      type: 'note',
      tool: 'theHarvester',
      stage: STAGE,
      target,
      severity: 'info',
      evidence: [],
      data: { skipped: true, reason: 'tool not found' },
      source: SOURCE
    });
  }

  emitJsonl(emit, {
    type: 'asset',
    tool: 'passive-recon',
    stage: STAGE,
    target,
    severity: 'info',
    evidence,
    data: { whois: evidence.some((p) => p.endsWith('.whois.txt')), theHarvester: evidence.some((p) => p.endsWith('.theharvester.json')) },
    source: SOURCE
  });
}

function defaultEmit(record) {
  if (!record.ts) record.ts = new Date().toISOString();
  if (!record.timestamp) record.timestamp = record.ts;
  process.stdout.write(`${JSON.stringify(record)}\n`);
}

async function handleTargets(targets) {
  for (const t of targets.filter(Boolean)) {
    // eslint-disable-next-line no-await-in-loop
    await run({ target: t, emit: defaultEmit });
  }
}

function readStdin() {
  return new Promise((resolve) => {
    if (process.stdin.isTTY) return resolve('');
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => { data += chunk; });
    process.stdin.on('end', () => resolve(data));
  });
}

async function main() {
  const args = parseCommonArgs(process.argv.slice(2));
  const stdin = await readStdin();
  const targets = [];

  if (args.target) targets.push(args.target);
  if (stdin.trim()) {
    stdin.trim().split('\n').forEach((line) => {
      try {
        const obj = JSON.parse(line);
        if (obj.target) targets.push(obj.target);
      } catch (_err) { /* ignore */ }
    });
  }

  if (targets.length === 0) {
    process.stderr.write('Usage: --target <host> [--out-dir dir] [--scope-file file] [--timeout sec]\n');
    process.exit(1);
  }

  for (const t of targets.filter(Boolean)) {
    // eslint-disable-next-line no-await-in-loop
    await run({
      target: t,
      emit: defaultEmit,
      outDir: args.outDir,
      scopeFile: args.scopeFile,
      timeout: args.timeout,
      runTs: process.env.RUN_TS || ''
    });
  }
}

module.exports = { run };

if (require.main === module) {
  void main();
}
