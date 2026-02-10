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

function severityLabel(s) {
  const norm = toSev(s);
  const labels = {
    crit: 'Critical',
    high: 'High',
    med: 'Medium',
    low: 'Low',
    info: 'Informational'
  };
  return labels[norm] || 'Informational';
}

function toPosixPath(p) {
  return String(p || '').replace(/\\/g, '/');
}

function formatHostList(arr, limit = 4) {
  const cleaned = uniq((arr || []).map((v) => String(v || '').trim()).filter(Boolean));
  if (!cleaned.length) return '';
  const quoted = cleaned.map((v) => `\`${mdEscape(v)}\``);
  if (quoted.length <= limit) return quoted.join(', ');
  return `${quoted.slice(0, limit).join(', ')} (+${quoted.length - limit} more)`;
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

function gatherHostsFromFinding(f) {
  const hosts = [];
  if (f && f.target) hosts.push(String(f.target));
  const url = getUrlFromFinding(f);
  if (url) {
    const parsed = parseHost(url);
    if (parsed) hosts.push(parsed);
  }
  return uniq(hosts).filter(Boolean);
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

function getWatchlistKey(entry) {
  if (!entry) return '';
  return `${entry.cveId || ''}|${entry.tech?.vendor || ''}|${entry.tech?.product || ''}|${entry.tech?.version || ''}`;
}

function getWatchlistTimestamp(entry) {
  if (!entry) return '';
  return entry.timestamp || entry.ts || '';
}

function shouldReplaceWatchlistEntry(existing, candidate) {
  if (!existing) return true;
  const existingTs = getWatchlistTimestamp(existing);
  const candidateTs = getWatchlistTimestamp(candidate);
  if (candidateTs && existingTs && candidateTs !== existingTs) {
    return candidateTs > existingTs;
  }
  const existingScore = existing.score !== null && existing.score !== undefined ? existing.score : -1;
  const candidateScore = candidate.score !== null && candidate.score !== undefined ? candidate.score : -1;
  if (candidateScore !== existingScore) return candidateScore > existingScore;
  return true;
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

  const inputProbeFindings = findings.filter((f) => f.tool === 'input-probe');
  const inputProbeCategoryCounts = countBy(inputProbeFindings, (f) => {
    const category = f && f.data && f.data.category ? String(f.data.category) : 'uncategorized';
    return category;
  });
  const inputProbeParamCounts = countBy(inputProbeFindings, (f) => {
    const param = f && f.data && f.data.param ? String(f.data.param) : '';
    const url = f && f.data && f.data.url ? String(f.data.url) : f.target || '';
    if (param && url) return `${param} @ ${url}`;
    if (param) return param;
    return url || 'unknown';
  });
  const topInputProbeParams = Array.from(inputProbeParamCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  // Notes: timeouts / missing tools
  const timeouts = notes.filter((n) => n.tool === 'runner-timeout');
  const skippedTools = notes
    .filter((n) => n && n.data && (n.data.skipped === true || /tool not found/i.test(String((n.data && (n.data.message || n.data.reason)) || ''))))
    .slice(0, 30);

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

  const sortedPotential = [...potentialVuln].sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
  const recommendationEntries = [];
  sortedPotential.slice(0, 6).forEach((f) => {
    const hosts = gatherHostsFromFinding(f);
    if (!hosts.length && target) hosts.push(target);
    const description = describeFinding(f) || f.tool || 'Automated signal';
    const context = getUrlFromFinding(f) || f.target || '';
    const summary = `Validate ${description}${context ? ` (${context})` : ''} and apply the appropriate mitigation.`;
    recommendationEntries.push({
      priority: severityLabel(f.severity),
      summary,
      hosts: formatHostList(hosts, 4)
    });
  });

  if (hdrByHost.size && sortedMissingHeaders.length) {
    const headerList = sortedMissingHeaders.slice(0, 3)
      .map(([hdr, count]) => `${hdr} (${count})`)
      .join(', ');
    recommendationEntries.push({
      priority: 'Medium',
      summary: `Implement missing HTTP security headers (${headerList}) across impacted hosts.`,
      hosts: formatHostList(Array.from(hdrByHost.keys()), 4)
    });
  }
  if (tlsHostsList.length) {
    recommendationEntries.push({
      priority: 'Medium',
      summary: 'Retire legacy TLS protocols and confirm cipher suites align with current best practices.',
      hosts: formatHostList(tlsHostsList, 4)
    });
  }
  if (openPortHostCount) {
    recommendationEntries.push({
      priority: 'Medium',
      summary: 'Review open ports and services for unauthorized exposure before progressing deeper.',
      hosts: formatHostList(Object.keys(openPorts), 4)
    });
  }
  if (!recommendationEntries.length) {
    recommendationEntries.push({
      priority: 'Info',
      summary: 'Maintain continuous coverage with automated and manual reviews to keep pace with evolving risk.',
      hosts: formatHostList([target], 1)
    });
  }

  const runFolderRel = toPosixPath(path.relative(process.cwd(), rootOut));
  const reportRelPath = toPosixPath(path.relative(process.cwd(), reportPath));
  const recordsRelPath = toPosixPath(path.relative(process.cwd(), recordsPath));
  const appendixRunPath = runFolderRel || `data/runs/${reportTs}`;

  const lines = [];
  lines.push(`# Security Assessment Report — ${mdEscape(target)}`);
  lines.push('');
  lines.push(`**Run ID:** \`${mdEscape(reportTs)}\``);
  lines.push('');

  lines.push('## Executive summary');
  lines.push('');
  lines.push('Automated reconnaissance, enumeration, and configuration checks were scoped to the provided target and its resolved assets.');
  lines.push(totalPotential
    ? `Potential vulnerabilities flagged: ${severitySummary.join(', ')}.`
    : 'No potential vulnerabilities were flagged by the templates enabled for this run.');
  lines.push(hardeningHosts || tlsHostsList.length
    ? `Configuration reviews highlighted ${hardeningHosts} host(s) missing HTTP security headers and ${tlsHostsList.length} host(s) still allowing legacy TLS.`
    : 'Configuration posture remains consistent with expectations across the scanned hosts.');
  lines.push(attackHosts || attackIps || openPortHostCount
    ? `Attack surface mapping captured ${attackHosts} subdomain(s), ${attackIps} IP address(es), and ${openPortHostCount} host(s) with recorded open ports.`
    : 'Attack surface enumeration did not expand beyond the scoped entry points in this run.');
  lines.push(limitationNotes.length
    ? `Limitations include ${limitationNotes.join('; ')}; consult the associated run artifacts for full detail.`
    : 'All enabled skills completed without timeouts or skips; coverage remains confined to the configured pipeline.');
  lines.push('');

  lines.push('## Potential vulnerabilities');
  lines.push('');
  if (!totalPotential) {
    lines.push('_No potential vulnerabilities were captured by the enabled templates in this run._');
  } else {
    const sampleVulns = capList(sortedPotential, 10);
    sampleVulns.list.forEach((f) => {
      const url = getUrlFromFinding(f);
      const context = url ? `\`${mdEscape(url)}\`` : (f.target ? `target \`${mdEscape(f.target)}\`` : 'scoped target');
      const detail = describeFinding(f);
      lines.push(`- **${severityLabel(f.severity)}** ${mdEscape(f.tool)} on ${context}${detail ? ` — ${mdEscape(detail)}` : ''}`);
    });
    if (sampleVulns.more > 0) {
      lines.push(`- _(${sampleVulns.more} additional findings captured in the run.)_`);
    }
  }
  lines.push('');

  lines.push('## Recommendations');
  lines.push('');
  recommendationEntries.forEach((rec) => {
    const hostNote = rec.hosts ? ` (Affected hosts: ${rec.hosts})` : '';
    lines.push(`- **${mdEscape(rec.priority)}** ${mdEscape(rec.summary)}${hostNote}`);
  });
  lines.push('');

  lines.push('## Hardening');
  lines.push('');
  if (!hdrByHost.size && !tlsHostsList.length) {
    lines.push('_No configuration gaps were surfaced by the security header or TLS checks._');
  } else {
    if (hdrByHost.size) {
      const headerSummary = sortedMissingHeaders.slice(0, 4)
        .map(([hdr, count]) => `${mdEscape(hdr)} (${count} host${count === 1 ? '' : 's'})`)
        .join(', ');
      lines.push(`- Missing HTTP headers were detected on ${hardeningHosts} host(s); top offenders: ${headerSummary}.`);
      const headerSamples = formatSampleList(Array.from(hdrByHost.keys()), 6);
      if (headerSamples) lines.push(`  - Sample hosts: ${headerSamples}.`);
    }
    if (tlsHostsList.length) {
      lines.push(`- Legacy TLS protocols remain enabled on ${tlsHostsList.length} host(s); sample: ${formatSampleList(tlsHostsList, 5)}.`);
    }
  }
  lines.push('');

  lines.push('## Attack surface');
  lines.push('');
  if (hostnames.length) {
    lines.push(`- Discovered ${hostnames.length} subdomain(s); sample: ${formatSampleList(hostnames, 6)}.`);
  } else {
    lines.push('- Subdomain enumeration did not expand the scoped host list.');
  }
  if (ips.length) {
    lines.push(`- Resolved ${ips.length} IP address(es).`);
  }
  if (openPortHostCount) {
    const portSamples = Object.entries(openPorts).slice(0, 5);
    portSamples.forEach(([host, ports]) => {
      const portSnapshot = Array.isArray(ports) ? ports.join(', ') : String(ports);
      lines.push(`- Open ports noted on \`${mdEscape(host)}\`: ${mdEscape(portSnapshot)}.`);
    });
  }
  if (drupal.length) {
    lines.push(`- CMS fingerprinting captured Drupal versions: ${uniq(drupal).map((v) => `\`${mdEscape(v)}\``).join(', ')}.`);
  }
  if (servers.length) {
    lines.push(`- Web server banners observed: ${uniq(servers).slice(0, 6).map((v) => `\`${mdEscape(v)}\``).join(', ')}.`);
  }
  if (ffuf.length) {
    const discovered = capList(ffuf, 6);
    const entries = discovered.list.map((x) => `${mdEscape(x.url)}${x.status ? ` (status ${mdEscape(x.status)})` : ''}`);
    lines.push(`- Directory enumeration flagged ${ffuf.length} endpoints; sample: ${entries.join('; ')}.`);
    if (discovered.more > 0) {
      lines.push(`- _(${discovered.more} additional endpoints captured.)_`);
    }
  } else {
    lines.push('- Directory enumeration did not surface high-signal endpoints in this run.');
  }
  lines.push('');

  const watchlistNotes = notes.filter((n) => n.tool === 'cve-enrich' && n.data && Array.isArray(n.data.watchlist));
  const watchlistMap = new Map();
  watchlistNotes.forEach((note) => {
    (note.data.watchlist || []).forEach((entry) => {
      if (!entry || !entry.cveId) return;
      const key = getWatchlistKey(entry);
      const existing = watchlistMap.get(key);
      if (!existing || shouldReplaceWatchlistEntry(existing, entry)) {
        watchlistMap.set(key, entry);
      }
    });
  });
  const watchlistList = Array.from(watchlistMap.values());
  const severityPriority = { high: 0, med: 1, low: 2, info: 3, unknown: 4 };
  const sortedWatchlist = [...watchlistList].sort((a, b) => {
    const aSeverity = severityPriority[String(a.severityBand || 'unknown').toLowerCase()] ?? severityPriority.unknown;
    const bSeverity = severityPriority[String(b.severityBand || 'unknown').toLowerCase()] ?? severityPriority.unknown;
    if (aSeverity !== bSeverity) return aSeverity - bSeverity;
    const aScore = a.score !== null && a.score !== undefined ? a.score : -1;
    const bScore = b.score !== null && b.score !== undefined ? b.score : -1;
    if (aScore !== bScore) return bScore - aScore;
    return (a.cveId || '').localeCompare(b.cveId || '');
  });
  const watchlistTop = sortedWatchlist.slice(0, 8);
  const severityCounts = countBy(watchlistList, (entry) => String(entry.severityBand || 'unknown').toLowerCase());
  const exploitSignalCount = watchlistList.filter((entry) => entry.exploitSignal).length;

  lines.push('## Technology risk watchlist (CVE enrichment)');
  lines.push('');
  if (!watchlistList.length) {
    lines.push('_No CVE enrichment watchlist entries were emitted for this run._');
  } else {
    const severityOrder = ['crit', 'high', 'med', 'low', 'info', 'unknown'];
    const severitySummary = severityOrder
      .map((label) => `${severityCounts.get(label) || 0} ${label}`)
      .join(' · ');
    lines.push(`- Severity breakdown: ${mdEscape(severitySummary)}.`);
    lines.push(`- Exploit signal: ${mdEscape(String(exploitSignalCount))} of ${mdEscape(String(watchlistList.length))} entries reference public exploit sources.`);
    lines.push('');
    lines.push('Top CVEs:');
    watchlistTop.forEach((entry, idx) => {
      const techParts = [];
      if (entry.tech) {
        if (entry.tech.vendor) techParts.push(entry.tech.vendor);
        if (entry.tech.product) techParts.push(entry.tech.product);
        if (entry.tech.version) techParts.push(entry.tech.version);
      }
      const techLabel = techParts.length ? techParts.join(' ') : 'Technology';
      const scoreText = entry.score !== null && entry.score !== undefined ? Number(entry.score).toFixed(1) : 'unknown';
      const impactLabel = entry.impact || 'Other';
      const applicabilityLabel = entry.applicability || 'unknown';
      const summaryText = entry.shortSummary ? mdEscape(entry.shortSummary) : 'Summary unavailable.';
      const referenceLinks = (entry.references || []).slice(0, 3)
        .map((ref) => {
          const value = String(ref || '').trim();
          return value ? `[${mdEscape(value)}](${value})` : '';
        })
        .filter(Boolean);
      const refsText = referenceLinks.length ? ` References: ${referenceLinks.join(', ')}` : '';
      const techNote = techLabel ? ` (Technology: ${mdEscape(techLabel)})` : '';
      lines.push(`${idx + 1}. **${mdEscape(entry.cveId)}** (CVSS ${mdEscape(scoreText)}, Impact ${mdEscape(impactLabel)}, Applicability ${mdEscape(applicabilityLabel)}) — ${summaryText}${techNote}.${refsText}`);
    });
  }
  lines.push('');

  lines.push('## Input probe anomalies');
  lines.push('');
  if (!inputProbeFindings.length) {
    lines.push('_Input probing did not detect anomalies during this run or the stage was disabled._');
  } else {
    const categorySummary = Array.from(inputProbeCategoryCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .map(([cat, count]) => `${count} ${mdEscape(cat)}`)
      .join(', ');
    lines.push(`- Input probe flagged ${inputProbeFindings.length} anomaly${inputProbeFindings.length === 1 ? '' : 'ies'}; counts by category: ${categorySummary}.`);
    if (topInputProbeParams.length) {
      const paramsList = topInputProbeParams
        .map(([param, count]) => `\`${mdEscape(param)}\` (${count})`)
        .join(', ');
      lines.push(`- Top affected parameters: ${paramsList}.`);
    }
  }
  lines.push('');

  lines.push('## Limitations');
  lines.push('');
  if (!limitationNotes.length) {
    lines.push('_All enabled tools finished without interruption; scope remains tied to the configured pipeline skills._');
  } else {
    limitationNotes.forEach((note) => {
      lines.push(`- ${note}.`);
    });
  }
  lines.push('- Records and evidence persist in the associated run artifacts for further review.');
  lines.push('');

  lines.push('## Appendix');
  lines.push('');
  lines.push(`- Run artifacts are maintained under \`${mdEscape(appendixRunPath)}\`; the generated report (markdown, HTML, PDF) lives under \`${mdEscape(reportRelPath)}\` and records under \`${mdEscape(recordsRelPath)}\`.`);
  lines.push('');

  fs.writeFileSync(reportPath, `${lines.join('\n')}\n`);

  emitJsonl(emit, {
    type: 'note',
    tool: 'markdown-report',
    stage: STAGE,
    target,
    severity: 'info',
    evidence: [reportPath, recordsPath],
    data: { report: reportRelPath, records: recordsRelPath, run: appendixRunPath },
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
