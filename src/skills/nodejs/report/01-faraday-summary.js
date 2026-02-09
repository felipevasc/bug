#!/usr/bin/env node
'use strict';

/**
 * @skill: nodejs/report/markdown-report
 * @inputs: target[, out-dir, scope-file]
 * @outputs: note
 * @tools: local-files
 */

const fs = require('fs');
const path = require('path');
const { parseCommonArgs, emitJsonl, ensureDir } = require('../../../lib/skill-utils');

const STAGE = 'report';
const SOURCE = 'src/skills/nodejs/report/01-faraday-summary.js';

function readJsonl(p) {
  if (!fs.existsSync(p)) return [];
  const out = [];
  const txt = fs.readFileSync(p, 'utf8');
  txt.split('\n').forEach((l) => {
    const line = l.trim();
    if (!line) return;
    try { out.push(JSON.parse(line)); } catch (_e) { /* ignore */ }
  });
  return out;
}

function mdEscape(s) {
  return String(s || '').replace(/\|/g, '\\|').replace(/\n/g, ' ');
}

function countBy(arr, keyFn) {
  const m = new Map();
  for (const x of arr) {
    const k = keyFn(x);
    m.set(k, (m.get(k) || 0) + 1);
  }
  return m;
}

function severityRank(s) {
  const m = { crit: 5, high: 4, med: 3, low: 2, info: 1 };
  return m[String(s || '').toLowerCase()] || 0;
}

async function run({ target, emit, outDir, runTs }) {
  const rootOut = outDir || process.env.OUT_DIR || path.resolve('data', 'runs', runTs || 'run');
  const recordsPath = path.join(rootOut, 'records.jsonl');
  const records = readJsonl(recordsPath);

  const reportTs = process.env.RUN_TS || runTs || 'run';
  const reportDir = path.resolve('data', 'reports', reportTs);
  ensureDir(reportDir);
  const reportPath = path.join(reportDir, 'report.md');

  const findings = records.filter((r) => r && r.type === 'finding');
  const assets = records.filter((r) => r && r.type === 'asset');
  const notes = records.filter((r) => r && r.type === 'note');

  findings.sort((a, b) => severityRank(b.severity) - severityRank(a.severity));

  const sevCounts = countBy(findings, (r) => r.severity || 'info');
  const lines = [];
  lines.push(`# Report: ${mdEscape(target)}`);
  lines.push('');
  lines.push(`- Run: \`${mdEscape(reportTs)}\``);
  lines.push(`- Target: \`${mdEscape(target)}\``);
  lines.push(`- Records: ${records.length} (assets=${assets.length}, findings=${findings.length}, notes=${notes.length})`);
  lines.push('');
  lines.push('## Summary');
  lines.push('');
  lines.push('| Severity | Count |');
  lines.push('|---|---:|');
  ['crit', 'high', 'med', 'low', 'info'].forEach((s) => lines.push(`| ${s} | ${sevCounts.get(s) || 0} |`));
  lines.push('');
  lines.push('## Findings');
  lines.push('');
  lines.push('| Severity | Tool | Stage | Target | Evidence |');
  lines.push('|---|---|---|---|---|');
  for (const f of findings) {
    const ev = Array.isArray(f.evidence) ? f.evidence : [];
    const evStr = ev.slice(0, 5).map((p) => `\`${mdEscape(p)}\``).join('<br>');
    lines.push(`| ${mdEscape(f.severity)} | ${mdEscape(f.tool)} | ${mdEscape(f.stage)} | \`${mdEscape(f.target)}\` | ${evStr} |`);
  }
  lines.push('');
  lines.push('## Assets');
  lines.push('');
  lines.push('| Tool | Stage | Target | Evidence |');
  lines.push('|---|---|---|---|');
  for (const a of assets.slice(0, 200)) {
    const ev = Array.isArray(a.evidence) ? a.evidence : [];
    const evStr = ev.slice(0, 3).map((p) => `\`${mdEscape(p)}\``).join('<br>');
    lines.push(`| ${mdEscape(a.tool)} | ${mdEscape(a.stage)} | \`${mdEscape(a.target)}\` | ${evStr} |`);
  }
  lines.push('');
  lines.push('## Notes');
  lines.push('');
  for (const n of notes.slice(0, 100)) {
    lines.push(`- [${mdEscape(n.tool)}] ${mdEscape(n.data && (n.data.message || n.data.reason || n.data.summary) ? (n.data.message || n.data.reason || n.data.summary) : '')}`);
  }
  lines.push('');
  lines.push('## Evidence');
  lines.push('');
  lines.push(`- Records JSONL: \`${mdEscape(recordsPath)}\``);
  lines.push(`- Evidence root: \`${mdEscape(path.join(rootOut, 'evidence'))}\``);
  lines.push('');

  fs.writeFileSync(reportPath, `${lines.join('\n')}\n`);

  emitJsonl(emit, {
    type: 'note',
    tool: 'markdown-report',
    stage: STAGE,
    target,
    severity: 'info',
    evidence: [reportPath, recordsPath],
    data: { report: reportPath, records: recordsPath },
    source: SOURCE
  });
}

function defaultEmit(record) {
  if (!record.ts) record.ts = new Date().toISOString();
  if (!record.timestamp) record.timestamp = record.ts;
  process.stdout.write(`${JSON.stringify(record)}\n`);
}

module.exports = { run };

if (require.main === module) {
  (async () => {
    const args = parseCommonArgs(process.argv.slice(2));
    if (!args.target) {
      process.stderr.write('Usage: --target <host> [--out-dir dir]\n');
      process.exit(1);
    }
    await run({
      target: args.target,
      emit: defaultEmit,
      outDir: args.outDir,
      runTs: process.env.RUN_TS || ''
    });
  })().catch((e) => {
    process.stderr.write(`${e && e.stack ? e.stack : String(e)}\n`);
    process.exit(1);
  });
}
