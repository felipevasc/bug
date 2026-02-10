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

  let findings = records.filter((r) => r && r.type === 'finding');
  const assets = records.filter((r) => r && r.type === 'asset');
  const notes = records.filter((r) => r && r.type === 'note');

  // De-duplicate findings to avoid repeated noisy entries.
  const seen = new Set();
  findings = findings.filter((f) => {
    const key = [f.tool || '', f.stage || '', f.target || '', JSON.stringify(f.data || {})].join('|');
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  findings.sort((a, b) => severityRank(b.severity) - severityRank(a.severity));

  const sevCounts = countBy(findings, (r) => r.severity || 'info');

  const lines = [];
  lines.push(`# Report: ${mdEscape(target)}`);
  lines.push('');
  lines.push(`- Run: \`${mdEscape(reportTs)}\``);
  lines.push(`- Target: \`${mdEscape(target)}\``);
  lines.push(`- Records: ${records.length} (assets=${assets.length}, findings=${findings.length}, notes=${notes.length})`);
  lines.push('');

  // --- Executive summary ---
  const critN = sevCounts.get('crit') || 0;
  const highN = sevCounts.get('high') || 0;
  const medN = sevCounts.get('med') || 0;
  const lowN = sevCounts.get('low') || 0;

  lines.push('## Executive summary');
  lines.push('');
  if ((critN + highN + medN) === 0) {
    lines.push('- No confirmed **high/critical** vulnerabilities were identified by this automated run.');
  } else {
    lines.push(`- Action required: **${critN} critical**, **${highN} high**, **${medN} medium** potential vulnerabilities identified.`);
  }
  if (lowN > 0) {
    lines.push(`- **${lowN} low** severity issues were identified (mostly hardening/misconfig hygiene).`);
  }
  lines.push('- This report is based on automated recon/enum checks; exploitation is **not performed** unless explicitly allowed.');
  lines.push('');

  // --- Summary table ---
  lines.push('## Summary');
  lines.push('');
  lines.push('| Severity | Count |');
  lines.push('|---|---:|');
  ['crit', 'high', 'med', 'low', 'info'].forEach((s) => lines.push(`| ${s} | ${sevCounts.get(s) || 0} |`));
  lines.push('');

  // --- What was tested / limitations ---
  lines.push('## Scope & methodology');
  lines.push('');
  lines.push('- Inputs: URLs discovered via `httpx` + `curl` and related pipeline artifacts.');
  lines.push('- Rate limiting: `--rate` propagated to tools when supported.');
  lines.push('- Nuclei: runs templates by **tags** or a project allowlist (if configured), with separate *run budget* vs *per-request timeout*.' );
  lines.push('- Limitations: missing tools are skipped; timeouts may cause partial coverage.');
  lines.push('');

  // --- Classification (more intuitive) ---
  const isHardening = (f) => f.tool === 'security-headers';
  const isInformational = (f) => ['curl', 'whatweb', 'port-scan'].includes(String(f.tool || ''));
  const isDiscovery = (f) => f.tool === 'ffuf';
  const isPotentialVuln = (f) => !isHardening(f) && !isInformational(f) && !isDiscovery(f);

  const potVuln = findings.filter(isPotentialVuln);
  const hardening = findings.filter(isHardening);
  const discovery = findings.filter(isDiscovery);
  const info = findings.filter((f) => !isPotentialVuln(f) && !isHardening(f) && !isDiscovery(f));

  lines.push('## Key items (triage)');
  lines.push('');
  if (potVuln.length === 0) {
    lines.push('- Potential vulnerabilities: **none identified** by automated checks in this run.');
  } else {
    lines.push(`- Potential vulnerabilities: **${potVuln.length}** item(s).`);
  }
  lines.push(`- Hardening recommendations: **${hardening.length}** item(s).`);
  lines.push(`- Discovery / interesting paths: **${discovery.length}** item(s).`);
  lines.push('');

  // --- Hardening details (group missing headers per URL) ---
  const secHdrFindings = findings.filter((r) => r && r.type === 'finding' && r.tool === 'security-headers');
  const byUrl = new Map();
  for (const f of secHdrFindings) {
    const url = (f.data && f.data.url) ? String(f.data.url) : '';
    const miss = (f.data && f.data.missing) ? String(f.data.missing) : '';
    if (!url || !miss) continue;
    if (!byUrl.has(url)) byUrl.set(url, new Set());
    byUrl.get(url).add(miss);
  }

  lines.push('## Hardening recommendations');
  lines.push('');
  if (byUrl.size === 0) {
    lines.push('_None._');
  } else {
    lines.push('### Missing HTTP security headers');
    lines.push('');
    for (const [url, set] of Array.from(byUrl.entries()).sort((a, b) => String(a[0]).localeCompare(String(b[0])))) {
      const missing = Array.from(set.values()).sort();
      lines.push(`- ${mdEscape(url)}: missing **${missing.map((x) => mdEscape(x)).join(', ')}**`);
    }
  }
  lines.push('');

  // --- Discovery ---
  lines.push('## Discovery / enumeration');
  lines.push('');
  const ffufFindings = findings.filter((r) => r && r.type === 'finding' && r.tool === 'ffuf');
  if (ffufFindings.length === 0) {
    lines.push('_None._');
  } else {
    // Only include a small, readable list.
    ffufFindings.slice(0, 20).forEach((f) => {
      const url = (f.data && f.data.url) ? String(f.data.url) : (f.target || '');
      const status = (f.data && f.data.status !== undefined) ? String(f.data.status) : '';
      lines.push(`- ffuf interesting path: ${mdEscape(url)}${status ? ` (status ${mdEscape(status)})` : ''}`);
    });
    if (ffufFindings.length > 20) lines.push(`- _(and ${ffufFindings.length - 20} more; see records.jsonl for details)_`);
  }
  lines.push('');

  // --- Potential vulnerabilities (if any) ---
  lines.push('## Potential vulnerabilities');
  lines.push('');
  if (potVuln.length === 0) {
    lines.push('_None identified by automated templates in this run._');
  } else {
    potVuln.forEach((f) => {
      const ev = Array.isArray(f.evidence) ? f.evidence : [];
      lines.push(`- **${mdEscape(f.severity)}** ${mdEscape(f.tool)} @ \`${mdEscape(f.target)}\`: ${mdEscape(f.data ? JSON.stringify(f.data) : '')}`);
      if (ev.length) lines.push(`  - Evidence: ${ev.slice(0, 5).map((p) => `\`${mdEscape(p)}\``).join(', ')}`);
    });
  }
  lines.push('');

  // Keep the raw-ish table, but move it later and keep it compact.
  lines.push('## Appendix: full findings (compact)');
  lines.push('');
  lines.push('| Severity | Tool | Stage | Target | What |');
  lines.push('|---|---|---|---|---|');
  for (const f of findings) {
    const what = mdEscape(f.data ? JSON.stringify(f.data).slice(0, 160) : '');
    lines.push(`| ${mdEscape(f.severity)} | ${mdEscape(f.tool)} | ${mdEscape(f.stage)} | \`${mdEscape(f.target)}\` | ${what} |`);
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
