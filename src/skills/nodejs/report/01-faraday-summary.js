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
  lines.push('| Severity | Tool | Stage | Target | What | Evidence |');
  lines.push('|---|---|---|---|---|---|');
  for (const f of findings) {
    const ev = Array.isArray(f.evidence) ? f.evidence : [];
    const evStr = ev.slice(0, 5).map((p) => `\`${mdEscape(p)}\``).join('<br>');
    const what = mdEscape(f.data ? JSON.stringify(f.data).slice(0, 180) : '');
    lines.push(`| ${mdEscape(f.severity)} | ${mdEscape(f.tool)} | ${mdEscape(f.stage)} | \`${mdEscape(f.target)}\` | ${what} | ${evStr} |`);
  }
  lines.push('');

  // Extract useful summary even when tooling is missing and there are no "findings".
  const dnsNotes = records.filter((r) => r && r.tool === 'dns-recon');
  const dnsAssets = records.filter((r) => r && r.tool === 'dns' && r.type === 'asset');
  const curlFindings = records.filter((r) => r && r.tool === 'curl' && r.type === 'finding');
  const portNotes = records.filter((r) => r && r.tool === 'port-scan');

  // Counts
  const toolCounts = countBy(records, (r) => `${r.stage || 'na'}:${r.tool || 'na'}`);
  const stageCounts = countBy(records, (r) => r.stage || 'na');

  lines.push('## Counts');
  lines.push('');
  lines.push('- By stage:');
  Array.from(stageCounts.entries()).sort((a, b) => String(a[0]).localeCompare(String(b[0]))).forEach(([k, v]) => {
    lines.push(`  - ${mdEscape(k)}: ${v}`);
  });
  lines.push('');
  lines.push('- By tool (stage:tool):');
  Array.from(toolCounts.entries()).sort((a, b) => String(a[0]).localeCompare(String(b[0]))).slice(0, 80).forEach(([k, v]) => {
    lines.push(`  - ${mdEscape(k)}: ${v}`);
  });
  lines.push('');

  lines.push('## Useful extracted summary');
  lines.push('');

  const subdomainAssets = records.filter((r) => r && r.type === 'asset' && r.tool === 'subdomains');
  const subdomainList = [];
  subdomainAssets.forEach((a) => {
    const hs = a.data && Array.isArray(a.data.hostnames) ? a.data.hostnames : [];
    hs.forEach((h) => subdomainList.push(h));
  });
  const uniqSubs = Array.from(new Set(subdomainList));
  if (uniqSubs.length) {
    lines.push(`- Subdomains discovered: ${uniqSubs.length} (see evidence in recon/subdomains)`);
  }

  if (dnsNotes.length || dnsAssets.length) {
    const aRecs = [];
    dnsNotes.forEach((n) => {
      const arr = n.data && Array.isArray(n.data.a_records) ? n.data.a_records : [];
      arr.forEach((ip) => aRecs.push(ip));
    });
    dnsAssets.forEach((a) => { if (a && a.target) aRecs.push(a.target); });
    const uniq = Array.from(new Set(aRecs)).slice(0, 50);
    lines.push(`- DNS A records (${uniq.length}): ${uniq.map((x) => `\`${mdEscape(x)}\``).join(' ') || '(none)'}`);
  }

  if (curlFindings.length) {
    lines.push('- HTTP checks (curl -I):');
    curlFindings.slice(0, 12).forEach((f) => {
      const u = f.data && (f.data.effective_url || f.data.url) ? (f.data.effective_url || f.data.url) : '';
      const sc = f.data && (f.data.status_code !== undefined) ? String(f.data.status_code) : '';
      const red = f.data && (f.data.redirects !== undefined) ? String(f.data.redirects) : '';
      lines.push(`  - ${mdEscape(u)} → status ${mdEscape(sc)} redirects ${mdEscape(red)}`);
    });
  }

  const secHdrFindings = records.filter((r) => r && r.type === 'finding' && r.tool === 'security-headers');
  if (secHdrFindings.length) {
    lines.push(`- Missing security headers findings: ${secHdrFindings.length}`);
    const top = secHdrFindings.slice(0, 12);
    top.forEach((f) => lines.push(`  - ${mdEscape((f.data && f.data.url) || '')}: missing ${mdEscape((f.data && f.data.missing) || '')}`));
  }

  const ffufFindings = records.filter((r) => r && r.type === 'finding' && r.tool === 'ffuf');
  if (ffufFindings.length) {
    lines.push(`- Dir enum (ffuf) interesting paths: ${ffufFindings.length}`);
  }

  const nucleiFindings = records.filter((r) => r && r.type === 'finding' && r.tool === 'nuclei');
  if (nucleiFindings.length) {
    lines.push(`- Nuclei findings: ${nucleiFindings.length}`);
  }

  if (portNotes.length) {
    const n = portNotes[0];
    const ev = Array.isArray(n.evidence) ? n.evidence : [];
    const nmapTxt = ev.find((p) => String(p).endsWith('.nmap.txt'));
    if (nmapTxt) lines.push(`- Nmap output: \`${mdEscape(nmapTxt)}\``);
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
