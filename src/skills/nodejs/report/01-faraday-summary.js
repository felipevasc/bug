#!/usr/bin/env node
'use strict';

/**
 * @skill: nodejs/report/markdown-report
 * @inputs: target[, out-dir, scope-file]
 * @outputs: note
 * @tools: local-files
 *
 * Goal: produce a professional, reader-friendly report (not a log dump).
 * - Avoid leaking internal file paths in the body.
 * - Group by meaning (potential vulns vs hardening vs attack surface).
 * - Keep raw details minimal; prefer concise summaries.
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
  return String(s || '')
    .replace(/\|/g, '\\|')
    .replace(/\r/g, ' ')
    .replace(/\n/g, ' ');
}

function uniq(arr) {
  return Array.from(new Set((arr || []).filter(Boolean)));
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
  const m = { crit: 5, high: 4, med: 3, medium: 3, low: 2, info: 1, informational: 1 };
  return m[String(s || '').toLowerCase()] || 0;
}

function toSev(s) {
  const v = String(s || '').toLowerCase();
  if (v === 'critical') return 'crit';
  if (v === 'high') return 'high';
  if (v === 'medium') return 'med';
  if (v === 'low') return 'low';
  if (v === 'info' || v === 'informational') return 'info';
  if (['crit', 'high', 'med', 'low', 'info'].includes(v)) return v;
  return 'info';
}

function getUrlFromFinding(f) {
  if (!f || !f.data) return '';
  return String(f.data.url || f.data.effective_url || '');
}

function parseHost(u) {
  try {
    // eslint-disable-next-line no-new
    const x = new URL(u);
    return String(x.hostname || '').toLowerCase();
  } catch (_e) {
    return '';
  }
}

function isProbablyNoiseFfufUrl(u) {
  const s = String(u || '');
  if (!s) return true;
  // We saw ffuf results like "https://ufu.br/# admin" due to wordlist/comment artifacts.
  if (s.includes('/# ')) return true;
  if (s.includes('Curated paths/filenames')) return true;
  if (s.includes('One token per line')) return true;
  if (s.includes('Example:')) return true;
  return false;
}

function capList(arr, n) {
  const a = (arr || []).slice(0, n);
  return { list: a, more: (arr || []).length - a.length };
}

async function run({ target, emit, outDir, runTs }) {
  const rootOut = outDir || process.env.OUT_DIR || path.resolve('data', 'runs', runTs || 'run');
  const recordsPath = path.join(rootOut, 'records.jsonl');
  const records = readJsonl(recordsPath);

  const reportTs = process.env.REPORT_TS || process.env.RUN_TS || runTs || 'run';
  const reportDir = path.resolve('data', 'reports', reportTs);
  ensureDir(reportDir);
  const reportPath = path.join(reportDir, 'report.md');

  // Classify records
  let findings = records.filter((r) => r && r.type === 'finding');
  const assets = records.filter((r) => r && r.type === 'asset');
  const notes = records.filter((r) => r && r.type === 'note');

  // De-duplicate findings (many tools repeat identical checks for http/https redirects)
  const seen = new Set();
  findings = findings.filter((f) => {
    const key = [f.tool || '', f.stage || '', f.target || '', JSON.stringify(f.data || {})].join('|');
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  findings.forEach((f) => { f.severity = toSev(f.severity); });
  findings.sort((a, b) => severityRank(b.severity) - severityRank(a.severity));

  const sevCounts = countBy(findings, (r) => r.severity || 'info');

  // Extract attack surface snapshot
  const subdomainAssets = assets.filter((r) => r && r.tool === 'subdomains' && r.data && Array.isArray(r.data.hostnames));
  const hostnames = uniq(subdomainAssets.flatMap((a) => (a.data && a.data.hostnames) ? a.data.hostnames : []));

  const dnsAssets = assets.filter((r) => r && r.tool === 'dns' && r.data && Array.isArray(r.data.all_a));
  const ips = uniq(dnsAssets.flatMap((a) => (a.data && a.data.all_a) ? a.data.all_a : []));

  const openPorts = {};
  findings
    .filter((f) => f.tool === 'port-scan' && f.data && Array.isArray(f.data.open_ports))
    .forEach((f) => { openPorts[f.target] = f.data.open_ports; });

  // Tech fingerprint (whatweb)
  const whatweb = findings.filter((f) => f.tool === 'whatweb' && f.data && f.data.fingerprint);
  const drupal = [];
  const servers = [];
  whatweb.forEach((f) => {
    const fp = String(f.data.fingerprint || '');
    const m = fp.match(/Drupal\s+([0-9]+(?:\.[0-9]+)*)/i);
    if (m && m[1]) drupal.push(m[1]);
    const m2 = fp.match(/Apache\/([0-9]+(?:\.[0-9]+){1,3})/i);
    if (m2 && m2[1]) servers.push(`Apache/${m2[1]}`);
  });

  // Hardening issues
  const hdrFindings = findings.filter((f) => f.tool === 'security-headers' && f.data && f.data.url && f.data.missing);
  const hdrByHost = new Map();
  hdrFindings.forEach((f) => {
    const url = String(f.data.url || '');
    const host = parseHost(url) || String(f.target || '');
    const missing = String(f.data.missing || '');
    if (!host || !missing) return;
    if (!hdrByHost.has(host)) hdrByHost.set(host, new Set());
    hdrByHost.get(host).add(missing);
  });

  const tlsWeak = findings.filter((f) => f.tool === 'sslscan' && f.data && f.data.weak_protocols);

  // Potential vulnerabilities: for now, treat nuclei results and other non-hardening signals as "potential".
  const potentialVuln = findings.filter((f) => {
    if (f.tool === 'nuclei') return true;
    // keep room for future tools
    return false;
  });

  // Discovery: ffuf
  const ffuf = findings
    .filter((f) => f.tool === 'ffuf' && f.data && (f.data.url || f.target))
    .map((f) => ({
      url: String(f.data.url || f.target || ''),
      status: f.data && f.data.status !== undefined ? String(f.data.status) : '',
      len: f.data && f.data.length !== undefined ? String(f.data.length) : ''
    }))
    .filter((x) => x.url && !isProbablyNoiseFfufUrl(x.url));

  // Notes: timeouts / missing tools
  const timeouts = notes.filter((n) => n.tool === 'runner-timeout');
  const skippedTools = notes
    .filter((n) => n && n.data && (n.data.skipped === true || /tool not found/i.test(String((n.data && (n.data.message || n.data.reason)) || ''))))
    .slice(0, 30);

  // --- Build markdown ---
  const lines = [];
  lines.push(`# Security Scan Report — ${mdEscape(target)}`);
  lines.push('');
  lines.push(`**Run ID:** \`${mdEscape(reportTs)}\``);
  lines.push('');

  // Executive summary (keep it short and decision-oriented)
  const critN = sevCounts.get('crit') || 0;
  const highN = sevCounts.get('high') || 0;
  const medN = sevCounts.get('med') || 0;
  const lowN = sevCounts.get('low') || 0;

  lines.push('## Executive summary');
  lines.push('');
  if (critN + highN + medN === 0) {
    lines.push('- No **high/critical** vulnerabilities were identified by the automated checks in this run.');
  } else {
    lines.push(`- **Action required:** ${critN} critical, ${highN} high, ${medN} medium item(s) detected.`);
  }
  if (lowN > 0) lines.push(`- ${lowN} low-severity items were identified (mostly hardening / configuration hygiene).`);
  lines.push('- This report focuses on **actionable security insights** (not raw tool logs).');
  lines.push('');

  lines.push('## Findings summary');
  lines.push('');
  lines.push('| Severity | Count |');
  lines.push('|---|---:|');
  ['crit', 'high', 'med', 'low', 'info'].forEach((s) => lines.push(`| ${s} | ${sevCounts.get(s) || 0} |`));
  lines.push('');

  lines.push('## Attack surface snapshot');
  lines.push('');
  if (hostnames.length) {
    const capped = capList(hostnames, 25);
    lines.push(`- Subdomains discovered from site links: **${hostnames.length}**`);
    lines.push(`  - Examples: ${capped.list.map((h) => `\`${mdEscape(h)}\``).join(', ')}${capped.more > 0 ? ` _(plus ${capped.more} more)_` : ''}`);
  } else {
    lines.push('- Subdomains: _(none discovered by link-crawl in this run)_');
  }
  if (ips.length) lines.push(`- IPs observed: ${ips.map((ip) => `\`${mdEscape(ip)}\``).join(', ')}`);
  if (Object.keys(openPorts).length) {
    const top = Object.entries(openPorts).slice(0, 12);
    lines.push('- Open ports (top):');
    top.forEach(([h, ps]) => lines.push(`  - \`${mdEscape(h)}\`: ${Array.isArray(ps) ? ps.join(', ') : mdEscape(String(ps))}`));
  }
  if (drupal.length) lines.push(`- Detected CMS: Drupal ${uniq(drupal).map((v) => `\`${mdEscape(v)}\``).join(', ')}`);
  if (servers.length) lines.push(`- Web server fingerprints observed: ${uniq(servers).slice(0, 6).map((v) => `\`${mdEscape(v)}\``).join(', ')}`);
  lines.push('');

  lines.push('## Potential vulnerabilities');
  lines.push('');
  if (potentialVuln.length === 0) {
    lines.push('_No potential vulnerabilities were flagged by templates/tools in this run._');
  } else {
    const capped = capList(potentialVuln, 20);
    capped.list.forEach((f) => {
      const u = getUrlFromFinding(f);
      lines.push(`- **${mdEscape(f.severity)}** ${mdEscape(f.tool)} — ${u ? mdEscape(u) : `target ${mdEscape(f.target)}`}`);
    });
    if (capped.more > 0) lines.push(`- _(plus ${capped.more} more)_`);
  }
  lines.push('');

  lines.push('## Hardening / configuration issues');
  lines.push('');

  if (hdrByHost.size === 0 && tlsWeak.length === 0) {
    lines.push('_No hardening items captured by the current checks._');
  } else {
    if (hdrByHost.size) {
      lines.push('### Missing HTTP security headers');
      lines.push('');
      Array.from(hdrByHost.entries())
        .sort((a, b) => String(a[0]).localeCompare(String(b[0])))
        .forEach(([host, set]) => {
          const missing = Array.from(set.values()).sort();
          lines.push(`- \`${mdEscape(host)}\`: ${missing.map((x) => `**${mdEscape(x)}**`).join(', ')}`);
        });
      lines.push('');
    }

    if (tlsWeak.length) {
      lines.push('### TLS / SSL observations');
      lines.push('');
      const hosts = uniq(tlsWeak.map((f) => f.target)).slice(0, 50);
      lines.push(`- Weak/legacy TLS protocol support observed on: ${hosts.map((h) => `\`${mdEscape(h)}\``).join(', ')}`);
      lines.push('');
    }
  }

  lines.push('## Discovery highlights');
  lines.push('');
  if (ffuf.length === 0) {
    lines.push('_No high-signal endpoints were extracted from directory enumeration in this run._');
  } else {
    const capped = capList(ffuf, 20);
    capped.list.forEach((x) => {
      lines.push(`- ${mdEscape(x.url)}${x.status ? ` (status ${mdEscape(x.status)})` : ''}`);
    });
    if (capped.more > 0) lines.push(`- _(plus ${capped.more} more)_`);
  }
  lines.push('');

  lines.push('## Notes / limitations');
  lines.push('');
  if (timeouts.length) lines.push(`- Timeouts occurred: **${timeouts.length}**`);
  if (skippedTools.length) {
    lines.push('- Some optional tools were missing/skipped in this environment; coverage may be partial.');
  }
  lines.push('- Evidence and raw logs are available, but intentionally omitted from the main body to keep the report readable.');
  lines.push('');

  // Minimal appendix for operators (no full paths)
  lines.push('## Appendix (operator details)');
  lines.push('');
  lines.push(`- Records file: \`records.jsonl\` (run folder)`);
  lines.push(`- Evidence folder: \`evidence/\` (run folder)`);
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

module.exports = { run };

if (require.main === module) {
  const args = parseCommonArgs(process.argv.slice(2));
  const target = args.target || '';
  if (!target) {
    // eslint-disable-next-line no-console
    console.error('Usage: 01-faraday-summary.js --target <host> [--out-dir dir]');
    process.exit(1);
  }
  // Emit to stdout (JSONL)
  run({
    target,
    outDir: args.outDir,
    runTs: process.env.RUN_TS || '',
    emit: (rec) => process.stdout.write(`${JSON.stringify(rec)}\n`)
  }).catch((e) => {
    // eslint-disable-next-line no-console
    console.error(e);
    process.exit(1);
  });
}
