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

function describeFinding(f) {
  if (!f || !f.data) return '';
  const keys = ['template', 'title', 'name', 'description', 'detail', 'info', 'match', 'payload'];
  for (const key of keys) {
    const value = f.data[key];
    if (value) return String(value);
  }
  return '';
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

function formatSampleList(arr, limit = 5) {
  const items = uniq(arr).slice(0, limit);
  if (!items.length) return '';
  return items.map((v) => `\`${mdEscape(v)}\``).join(', ');
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

  const missingHeaderCounts = new Map();
  hdrByHost.forEach((set) => {
    Array.from(set.values()).forEach((hdr) => {
      missingHeaderCounts.set(hdr, (missingHeaderCounts.get(hdr) || 0) + 1);
    });
  });

  const sortedMissingHeaders = Array.from(missingHeaderCounts.entries())
    .sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0])));
  const hardeningHosts = hdrByHost.size;

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
  lines.push(`# Security Assessment Report — ${mdEscape(target)}`);
  lines.push('');
  lines.push(`**Run ID:** \`${mdEscape(reportTs)}\``);
  lines.push('');

  const summarySevCounts = countBy(potentialVuln, (r) => toSev(r.severity));
  const totalPotential = potentialVuln.length;
  const severityOrder = ['crit', 'high', 'med', 'low', 'info'];
  const severitySummary = severityOrder
    .map((sev) => {
      const count = summarySevCounts.get(sev) || 0;
      return count ? `${count} ${sev}` : null;
    })
    .filter(Boolean);
  const tlsHostsList = uniq(tlsWeak.map((f) => f.target)).filter(Boolean);
  const attackHosts = hostnames.length;
  const attackIps = ips.length;
  const openPortHostCount = Object.keys(openPorts).length;
  const limitationNotes = [];
  if (timeouts.length) limitationNotes.push(`timeout events (${timeouts.length})`);
  if (skippedTools.length) limitationNotes.push(`${skippedTools.length} optional tools unavailable`);

  lines.push('## Executive summary');
  lines.push('');
  if (totalPotential) {
    lines.push(`- Potential vulnerabilities flagged: ${severitySummary.join(', ')}.`);
  } else {
    lines.push('- Potential vulnerabilities: none flagged by the automated templates enabled in this run.');
  }
  if (hardeningHosts || tlsHostsList.length) {
    const hardeningParts = [];
    if (hardeningHosts) hardeningParts.push(`${hardeningHosts} host(s) missing expected headers`);
    if (tlsHostsList.length) hardeningParts.push(`${tlsHostsList.length} host(s) still allowing legacy TLS`);
    lines.push(`- Hardening opportunities: ${hardeningParts.join('; ')}.`);
  } else {
    lines.push('- Hardening posture: the automated configuration checks did not surface deviations beyond the scoped targets.');
  }
  if (attackHosts || attackIps || openPortHostCount) {
    lines.push(`- Attack surface: enumerated ${attackHosts} subdomain(s) and ${attackIps} IP address(es); ${openPortHostCount} host(s) reported open ports.`);
  } else {
    lines.push('- Attack surface: no additional hosts or ports were discovered beyond the scoped entry points.');
  }
  if (limitationNotes.length) {
    lines.push(`- Limitations: ${limitationNotes.join('; ')}; refer to the run folder for details.`);
  } else {
    lines.push('- Limitations: coverage is limited to the automated skills in this pipeline; follow-up validation is recommended.');
  }
  lines.push('');

  lines.push('## Potential vulnerabilities');
  lines.push('');
  if (!totalPotential) {
    lines.push('_No potential vulnerabilities were captured by the vulnerability templates enabled in this run._');
  } else {
    const sortedPotential = [...potentialVuln].sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
    const sampleVulns = capList(sortedPotential, 12);
    sampleVulns.list.forEach((f) => {
      const url = getUrlFromFinding(f);
      const context = url ? mdEscape(url) : `target ${mdEscape(f.target)}`;
      const detail = describeFinding(f);
      lines.push(`- **${mdEscape(f.severity)}** ${mdEscape(f.tool)} (${context})${detail ? ` — ${mdEscape(detail)}` : ''}`);
    });
    if (sampleVulns.more > 0) {
      lines.push(`- _(plus ${sampleVulns.more} additional items captured in the run)_`);
    }
  }
  lines.push('');

  lines.push('## Hardening & configuration');
  lines.push('');
  if (hdrByHost.size === 0 && tlsHostsList.length === 0) {
    lines.push('_No configuration gaps were identified by the security headers or TLS checks._');
  } else {
    if (sortedMissingHeaders.length) {
      const headerSummary = sortedMissingHeaders.slice(0, 4)
        .map(([hdr, count]) => `${mdEscape(hdr)} (${count} host${count === 1 ? '' : 's'})`)
        .join(', ');
      lines.push(`- Missing HTTP headers observed on ${hardeningHosts} host(s); top offenders: ${headerSummary}.`);
      const headerSamples = formatSampleList(Array.from(hdrByHost.keys()), 6);
      if (headerSamples) {
        lines.push(`  - Sample hosts: ${headerSamples}.`);
      }
    }
    if (tlsHostsList.length) {
      lines.push(`- Legacy TLS protocols detected on ${tlsHostsList.length} host(s); sample: ${formatSampleList(tlsHostsList, 5)}.`);
    }
  }
  lines.push('');

  lines.push('## Attack surface & discovery');
  lines.push('');
  if (hostnames.length) {
    lines.push(`- Discovered ${hostnames.length} subdomain(s); sample: ${formatSampleList(hostnames, 6)}.`);
  } else {
    lines.push('- Subdomain enumeration produced no additional hosts beyond the scoped entry points.');
  }
  if (ips.length) {
    lines.push(`- Resolved ${ips.length} IP address(es).`);
  }
  if (openPortHostCount) {
    const samples = Object.entries(openPorts).slice(0, 6);
    samples.forEach(([host, ports]) => {
      const portList = Array.isArray(ports) ? ports.join(', ') : mdEscape(String(ports));
      lines.push(`- Open ports reported on \`${mdEscape(host)}\`: ${portList}.`);
    });
  }
  if (drupal.length) {
    lines.push(`- CMS fingerprinting noted Drupal ${uniq(drupal).map((v) => `\`${mdEscape(v)}\``).join(', ')}.`);
  }
  if (servers.length) {
    lines.push(`- Web server banners observed: ${uniq(servers).slice(0, 6).map((v) => `\`${mdEscape(v)}\``).join(', ')}.`);
  }
  if (ffuf.length) {
    const discovered = capList(ffuf, 8);
    const entries = discovered.list.map((x) => `${mdEscape(x.url)}${x.status ? ` (status ${mdEscape(x.status)})` : ''}`);
    lines.push(`- Directory enumeration flagged ${ffuf.length} endpoints; sample: ${entries.join('; ')}.`);
    if (discovered.more > 0) {
      lines.push(`- _(plus ${discovered.more} additional endpoints captured)_`);
    }
  } else {
    lines.push('- Directory enumeration did not surface high-signal endpoints in this run.');
  }
  lines.push('');

  lines.push('## Limitations');
  lines.push('');
  if (!limitationNotes.length) {
    lines.push('_All enabled tools completed without timeouts or skips; scope is limited to the configured skills._');
  } else {
    limitationNotes.forEach((note) => {
      lines.push(`- ${note}.`);
    });
  }
  lines.push('- Raw evidence remains in the corresponding run folder; this summary highlights the most actionable signals only.');
  lines.push('');

  lines.push('## Appendix');
  lines.push('');
  lines.push(`- Generated artifacts for run \`${mdEscape(reportTs)}\` (records, evidence, etc.) are available in that run's folder for deeper review.`);
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
