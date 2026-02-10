#!/usr/bin/env node
'use strict';

/**
 * @skill: nodejs/report/pdf-report
 * @inputs: target[, out-dir]
 * @outputs: note
 * @tools: chromium or wkhtmltopdf (optional)
 */

const fs = require('fs');
const path = require('path');
const { parseCommonArgs, emitJsonl, ensureDir, which, runCmdCapture } = require('../../../lib/skill-utils');

const STAGE = 'report';
const SOURCE = 'src/skills/nodejs/report/02-pdf-report.js';

function escapeHtml(s) {
  return String(s || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

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

function sevRank(s) {
  const m = { crit: 5, critical: 5, high: 4, med: 3, medium: 3, low: 2, info: 1 };
  return m[String(s || '').toLowerCase()] || 0;
}

function badge(sev) {
  const s = String(sev || 'info').toLowerCase();
  return `<span class="badge badge-${s}">${escapeHtml(s)}</span>`;
}

function table(headers, rows, opts = {}) {
  const th = headers.map((h) => `<th>${escapeHtml(h)}</th>`).join('');
  const body = rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join('')}</tr>`).join('');
  const classAttr = opts.tableClass ? ` class="${opts.tableClass}"` : '';
  const tableHtml = `<table${classAttr}><thead><tr>${th}</tr></thead><tbody>${body}</tbody></table>`;
  return opts.noWrapper ? tableHtml : `<div class="table-wrapper">${tableHtml}</div>`;
}

function uniq(arr) {
  return Array.from(new Set((arr || []).filter((v) => v)));
}

function capList(arr, n) {
  const list = (arr || []).slice(0, n);
  return { list, more: (arr || []).length - list.length };
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

function severityLabel(s) {
  const labelMap = {
    crit: 'Critical',
    high: 'High',
    med: 'Medium',
    low: 'Low',
    info: 'Informational'
  };
  return labelMap[toSev(s)] || 'Informational';
}

function cvssSeverity(score) {
  if (score === null || score === undefined) return 'info';
  if (score >= 7) return 'high';
  if (score >= 4) return 'med';
  if (score > 0) return 'low';
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

function gatherHostsFromFinding(f) {
  const hosts = [];
  if (f && f.target) hosts.push(String(f.target));
  const url = getUrlFromFinding(f);
  if (url) {
    const parsed = parseHost(url);
    if (parsed) hosts.push(parsed);
  }
  return uniq(hosts);
}

function formatHostList(arr, limit = 4) {
  const cleaned = uniq((arr || []).map((v) => String(v || '').trim()).filter(Boolean));
  if (!cleaned.length) return '';
  const quoted = cleaned.map((v) => `<code>${escapeHtml(v)}</code>`);
  if (quoted.length <= limit) return quoted.join(', ');
  return `${quoted.slice(0, limit).join(', ')} (+${quoted.length - limit} more)`;
}

function formatSampleList(arr, limit = 5) {
  const cleaned = uniq((arr || []).filter(Boolean));
  if (!cleaned.length) return '';
  const entries = cleaned.slice(0, limit).map((v) => `<code>${escapeHtml(v)}</code>`);
  if (cleaned.length <= limit) return entries.join(', ');
  return `${entries.join(', ')} (+${cleaned.length - limit} more)`;
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

function countBy(arr, keyFn) {
  const map = new Map();
  (arr || []).forEach((item) => {
    const key = keyFn(item);
    map.set(key, (map.get(key) || 0) + 1);
  });
  return map;
}

function toPosixPath(p) {
  return String(p || '').replace(/\\/g, '/');
}

function isProbablyNoiseFfufUrl(u) {
  const s = String(u || '');
  if (!s) return true;
  if (s.includes('/# ')) return true;
  if (s.includes('Curated paths/filenames')) return true;
  if (s.includes('One token per line')) return true;
  if (s.includes('Example:')) return true;
  return false;
}

function buildPrettyBody({ target, runTs, rootOut, records, mdPath }) {
  const assets = records.filter((r) => r && r.type === 'asset');
  const findings = records.filter((r) => r && r.type === 'finding');
  const notes = records.filter((r) => r && r.type === 'note');

  const counts = {
    assets: assets.length,
    findings: findings.length,
    notes: notes.length,
    total: records.length
  };

  const subdomainAssets = assets.filter((r) => r.tool === 'subdomains' && r.data && Array.isArray(r.data.hostnames));
  const hostnames = uniq(subdomainAssets.flatMap((a) => (a.data && a.data.hostnames) ? a.data.hostnames : [])).sort();

  const dnsAssets = assets.filter((r) => r.tool === 'dns' && r.data && Array.isArray(r.data.all_a));
  const ips = uniq(dnsAssets.flatMap((a) => (a.data && a.data.all_a) ? a.data.all_a : []));

  const openPorts = {};
  findings
    .filter((f) => f.tool === 'port-scan' && f.data && Array.isArray(f.data.open_ports))
    .forEach((f) => { openPorts[f.target] = f.data.open_ports; });

  const potentialVuln = findings.filter((f) => f.tool === 'nuclei');
  const totalPotential = potentialVuln.length;
  const summarySevCounts = countBy(potentialVuln, (r) => toSev(r.severity));
  const severityOrder = ['crit', 'high', 'med', 'low', 'info'];
  const severitySummary = severityOrder
    .map((sev) => {
      const count = summarySevCounts.get(sev) || 0;
      return count ? `${count} ${sev}` : null;
    })
    .filter(Boolean);
  const sortedPotential = [...potentialVuln].sort((a, b) => sevRank(b.severity) - sevRank(a.severity));

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
  const tlsHostsList = uniq(tlsWeak.map((f) => f.target)).filter(Boolean);

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

  const ffuf = findings
    .filter((f) => f.tool === 'ffuf' && f.data && (f.data.url || f.target))
    .map((f) => ({
      url: String(f.data.url || f.target || ''),
      status: f.data && f.data.status !== undefined ? String(f.data.status) : '',
      len: f.data && f.data.length !== undefined ? String(f.data.length) : ''
    }))
    .filter((x) => x.url && !(/#/).test(x.url) && !isProbablyNoiseFfufUrl(x.url));

  const limTimeouts = notes.filter((n) => n.tool === 'runner-timeout');
  const skippedTools = notes
    .filter((n) => n && n.data && (n.data.skipped === true || /tool not found/i.test(String((n.data && (n.data.message || n.data.reason)) || ''))))
    .slice(0, 30);
  const limitationNotes = [];
  if (limTimeouts.length) limitationNotes.push(`timeout events (${limTimeouts.length})`);
  if (skippedTools.length) limitationNotes.push(`${skippedTools.length} optional tools unavailable`);

  let openPortHostCount = Object.keys(openPorts).length;
  if (openPortHostCount < 0) openPortHostCount = 0;

  const recommendationEntries = [];
  sortedPotential.slice(0, 5).forEach((f) => {
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
      priority: 'Informational',
      summary: 'Maintain continuous coverage with automated and manual reviews to keep pace with evolving risk.',
      hosts: formatHostList([target], 1)
    });
  }

  const runFolderRel = toPosixPath(path.relative(process.cwd(), rootOut));
  const appendixRunPath = runFolderRel || `data/runs/${runTs}`;
  const reportFolderRel = `data/reports/${runTs}`;

  const summaryCards = `
  <div class="summary-grid">
    <div class="summary-card highlight">
      <div class="label">Target</div>
      <div class="value">${escapeHtml(target)}</div>
      <div class="sm">Run ${escapeHtml(runTs)}</div>
    </div>
    <div class="summary-card">
      <div class="label">Records</div>
      <div class="value">${counts.total}</div>
      <div class="sm">assets ${counts.assets} · findings ${counts.findings} · notes ${counts.notes}</div>
    </div>
    <div class="summary-card">
      <div class="label">Potential vulnerabilities</div>
      <div class="value">${totalPotential}</div>
      <div class="sm">${severitySummary.length ? escapeHtml(severitySummary.join(' · ')) : 'none flagged'}</div>
    </div>
    <div class="summary-card">
      <div class="label">Subdomains</div>
      <div class="value">${hostnames.length}</div>
      <div class="sm">discovered via recon</div>
    </div>
    <div class="summary-card">
      <div class="label">Missing security headers</div>
      <div class="value">${hardeningHosts}</div>
      <div class="sm">unique hosts</div>
    </div>
    <div class="summary-card">
      <div class="label">Legacy TLS signals</div>
      <div class="value">${tlsHostsList.length}</div>
      <div class="sm">sampled endpoints</div>
    </div>
  </div>`;

  const execPoints = [];
  execPoints.push(totalPotential
    ? `Potential vulnerabilities flagged: ${severitySummary.join(', ')}.`
    : 'No potential vulnerabilities were flagged by the enabled templates.');
  execPoints.push(hardeningHosts || tlsHostsList.length
    ? `Configuration reviews highlighted ${hardeningHosts} host(s) missing HTTP security headers and ${tlsHostsList.length} host(s) still allowing legacy TLS.`
    : 'Configuration posture remains consistent across the scanned hosts.');
  execPoints.push(hostnames.length || ips.length || openPortHostCount
    ? `Attack surface mapping captured ${hostnames.length} subdomain(s), ${ips.length} IP address(es), and ${openPortHostCount} host(s) with recorded open ports.`
    : 'Attack surface enumeration did not expand the scoped hosts.');
  execPoints.push(limitationNotes.length
    ? `Limitations include ${limitationNotes.join('; ')}.`
    : 'All enabled skills completed within their configured timeouts and scopes.');

  const execSummary = execPoints.map((item) => `<p>${escapeHtml(item)}</p>`).join('');

  const samplePotential = capList(sortedPotential, 15);
  const potentialRows = samplePotential.list.map((f) => {
    const targetCell = getUrlFromFinding(f) || f.target || 'scoped target';
    const detail = describeFinding(f) || (f.data ? (f.data['template-id'] || f.data.name || JSON.stringify(f.data).slice(0, 120)) : '');
    return [
      badge(f.severity),
      `<code>${escapeHtml(f.tool)}</code>`,
      `<code>${escapeHtml(targetCell)}</code>`,
      escapeHtml(detail)
    ];
  });
  const potentialTable = potentialRows.length
    ? `${table(['Severity', 'Tool', 'Target', 'Details'], potentialRows, { tableClass: 'data-table' })}${samplePotential.more > 0 ? `<p class="muted table-note">${samplePotential.more} additional findings captured in the run.</p>` : ''}`
    : '<div class="callout ok"><b>No potential vulnerabilities were flagged</b> by the enabled templates in this run.</div>';

  const recommendationHtml = recommendationEntries.map((rec) => `
    <div class="recommendation-item">
      <div class="rec-priority">${escapeHtml(rec.priority)}</div>
      <div class="rec-summary">${escapeHtml(rec.summary)}</div>
      ${rec.hosts ? `<div class="rec-hosts">Affected hosts: ${rec.hosts}</div>` : ''}
    </div>`).join('');

  const headerList = sortedMissingHeaders.slice(0, 4)
    .map(([hdr, count]) => `<li>${escapeHtml(hdr)} — ${count} host(s)</li>`).join('');
  const missingHeaderSamples = formatSampleList(Array.from(hdrByHost.keys()), 5);
  const headerCard = hdrByHost.size
    ? `<ul class="bullet-list">${headerList}</ul>${missingHeaderSamples ? `<div class="muted small">Sample hosts: ${missingHeaderSamples}</div>` : ''}`
    : '<div class="callout ok">No missing security headers were detected.</div>';
  const tlsCard = tlsHostsList.length
    ? `<div class="callout warn"><b>Legacy TLS detected</b> on ${formatHostList(tlsHostsList, 5)}.</div>`
    : '<div class="callout ok">TLS configuration is free of legacy protocols.</div>';

  const attackEntries = [];
  if (hostnames.length) attackEntries.push(`Discovered ${hostnames.length} subdomain(s); sample: ${formatSampleList(hostnames, 6)}.`);
  else attackEntries.push('Subdomain enumeration did not expand the scoped host list.');
  if (ips.length) attackEntries.push(`Resolved ${ips.length} IP address(es).`);
  if (openPortHostCount) {
    const portSamples = Object.entries(openPorts).slice(0, 4).map(([host, ports]) => {
      const summary = Array.isArray(ports) ? ports.join(', ') : String(ports);
      return `Open ports noted on <code>${escapeHtml(host)}</code>: ${escapeHtml(summary)}.`;
    }).join('<br>');
    attackEntries.push(portSamples);
  }
  if (drupal.length) {
    attackEntries.push(`CMS fingerprinting captured Drupal versions: ${uniq(drupal).map((v) => `<code>${escapeHtml(v)}</code>`).join(', ')}.`);
  }
  if (servers.length) {
    attackEntries.push(`Web server banners observed: ${uniq(servers).slice(0, 6).map((v) => `<code>${escapeHtml(v)}</code>`).join(', ')}.`);
  }
  if (ffuf.length) {
    const discovered = capList(ffuf, 5);
    const entries = discovered.list.map((x) => `${escapeHtml(x.url)}${x.status ? ` (status ${escapeHtml(x.status)})` : ''}`);
    attackEntries.push(`Directory enumeration flagged ${ffuf.length} endpoints; sample: ${entries.join('; ')}.${discovered.more > 0 ? ` +${discovered.more} more` : ''}`);
  }

  const cveNotes = notes
    .filter((n) => n && n.tool === 'cve-enrich' && n.data && Array.isArray(n.data.watchlist));
  const watchlistContext = cveNotes.find((n) => n && n.data && n.data.context)?.data?.context
    || 'CVE enrichment is a technology risk watchlist; treat the findings as candidates for manual verification.';
  const watchlistMap = new Map();
  cveNotes.forEach((note) => {
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
  const watchlistDisplay = watchlistList.slice(0, 5);
  const watchlistMore = Math.max(0, watchlistList.length - watchlistDisplay.length);
  const watchlistCards = watchlistDisplay.map((entry) => {
    const techParts = [];
    if (entry.tech) {
      if (entry.tech.vendor) techParts.push(entry.tech.vendor);
      if (entry.tech.product) techParts.push(entry.tech.product);
      if (entry.tech.version) techParts.push(entry.tech.version);
    }
    const techLabel = techParts.length ? techParts.join(' ') : 'Technology';
    const scoreBadgeText = entry.score !== null && entry.score !== undefined ? `CVSS ${Number(entry.score).toFixed(1)}` : 'Score unknown';
    const impactLabel = entry.impact || 'Other';
    const severityTag = entry.severityBand || 'info';
    const applicabilityText = entry.applicability || 'unknown';
    const summaryText = entry.shortSummary || 'Summary unavailable.';
    const generalRefs = [];
    const seenGeneral = new Set();
    const exploitRefs = [];
    const seenExploit = new Set();
    (entry.exploitReferences || []).forEach((ref) => {
      if (exploitRefs.length >= 2) return;
      const value = String(ref || '').trim();
      if (!value || seenExploit.has(value)) return;
      seenExploit.add(value);
      exploitRefs.push(value);
    });
    (entry.references || []).forEach((ref) => {
      if (generalRefs.length >= 3) return;
      const value = String(ref || '').trim();
      if (!value || seenGeneral.has(value) || seenExploit.has(value)) return;
      seenGeneral.add(value);
      generalRefs.push(value);
    });
    const generalRefLinks = generalRefs
      .map((ref) => {
        const value = String(ref || '').trim();
        return value ? `<a href="${escapeHtml(value)}">${escapeHtml(value)}</a>` : '';
      })
      .filter(Boolean)
      .join(', ');
    const exploitRefLinks = exploitRefs
      .map((ref) => {
        const value = String(ref || '').trim();
        return value ? `<a href="${escapeHtml(value)}">${escapeHtml(value)}</a>` : '';
      })
      .filter(Boolean)
      .join(', ');
    const generalRefsLine = generalRefLinks ? `<div class="watchlist-references">References: ${generalRefLinks}</div>` : '';
    const exploitLine = exploitRefLinks ? `<div class="watchlist-exploit">Exploit references: ${exploitRefLinks}</div>` : '';
    const impactedLine = entry.affected ? `<span>Impacted: ${escapeHtml(entry.affected)}</span>` : '';
    const fixLine = entry.fixedVersionOrMitigation ? `<span>Fix: ${escapeHtml(entry.fixedVersionOrMitigation)}</span>` : '';
    const sourceLine = entry.sources && entry.sources.length
      ? `<div class="watchlist-sources">Sources: ${entry.sources.map((src) => `<code>${escapeHtml(src)}</code>`).join(', ')}</div>`
      : '';
    return `<div class="watchlist-card">
      <div class="watchlist-card-header">
        <div class="watchlist-card-title"><strong>${escapeHtml(techLabel)}</strong></div>
        <div class="watchlist-card-meta">
          ${badge(severityTag)}
          <strong>${escapeHtml(entry.cveId)}</strong>
          <span class="watchlist-score-badge">${escapeHtml(scoreBadgeText)}</span>
          <span class="watchlist-impact-badge">${escapeHtml(impactLabel)}</span>
        </div>
      </div>
      <div class="watchlist-applicability">Applicability: ${escapeHtml(applicabilityText)}</div>
      <p class="watchlist-summary">${escapeHtml(summaryText)}</p>
      <div class="watchlist-impacted">
        ${impactedLine}
        ${fixLine}
      </div>
      ${generalRefsLine}
      ${exploitLine}
      ${sourceLine}
    </div>`;
  }).join('');
  const watchlistSection = watchlistDisplay.length
    ? `<div class="watchlist-grid">${watchlistCards}${watchlistMore > 0 ? `<p class="muted small">+${watchlistMore} additional watchlist entries captured in the run.</p>` : ''}</div>`
    : '<div class="callout ok"><b>No CVE enrichment candidates</b> were surfaced by the watchlist.</div>';

  const limitationList = limitationNotes.length
    ? limitationNotes
    : ['All enabled tools completed without interruption; scope is limited to the configured skills.'];

  return `
  <div class="report-shell">
    <header class="report-header">
      <div>
        <div class="report-title">Security Assessment Report</div>
        <div class="report-subtitle">Automated, non-intrusive checks (no exploitation). Generated for triage & hardening.</div>
      </div>
      <div class="report-meta">
        <div><span>Target</span><strong>${escapeHtml(target)}</strong></div>
        <div><span>Run ID</span><strong>${escapeHtml(runTs)}</strong></div>
      </div>
    </header>

    ${summaryCards}

    <section class="section">
      <h2>Executive summary</h2>
      <div class="section-body">
        <p>Automated reconnaissance, enumeration, and configuration checks were scoped to the provided target and its resolved assets.</p>
        <div class="summary-list">
          ${execSummary}
        </div>
      </div>
    </section>

    <section class="section">
      <h2>Potential vulnerabilities</h2>
      <p class="muted">This section highlights templates such as Nuclei that surfaced higher-risk findings; refer to the run artifacts for the evidence.</p>
      ${potentialTable}
    </section>

    <section class="section">
      <h2>Recommendations</h2>
      <div class="recommendations-list">
        ${recommendationHtml}
      </div>
    </section>

    <section class="section">
      <h2>Hardening</h2>
      <div class="hardening-grid">
        <div class="hardening-card">
          <div class="card-title">Security headers</div>
          ${headerCard}
        </div>
        <div class="hardening-card">
          <div class="card-title">TLS / SSL</div>
          ${tlsCard}
        </div>
      </div>
    </section>

    <section class="section">
      <h2>Attack surface</h2>
      <div class="section-body">
        <ul class="bullet-list">
          ${attackEntries.map((line) => `<li>${line}</li>`).join('')}
        </ul>
      </div>
    </section>

    <section class="section">
      <h2>Technology risk watchlist</h2>
      <p class="muted">${escapeHtml(watchlistContext)}${watchlistList.length ? ` Top ${Math.min(5, watchlistList.length)} entries shown below.` : ''}</p>
      ${watchlistSection}
    </section>

    <section class="section">
      <h2>Limitations</h2>
      <div class="callout note">
        <ul class="bullet-list">
          ${limitationList.map((note) => `<li>${escapeHtml(note)}</li>`).join('')}
        </ul>
      </div>
    </section>

    <section class="section appendix">
      <h2>Appendix</h2>
      <p>Run artifacts reside under <code>${escapeHtml(appendixRunPath)}</code>; the generated report suite is available in <code>${escapeHtml(reportFolderRel)}</code>.</p>
    </section>
  </div>`;
}

function htmlTemplate({ title, bodyHtml }) {
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>${escapeHtml(title)}</title>
  <style>
    @page { size: A4; margin: 18mm 16mm; }
    :root { color: #0f172a; background: #eef2ff; }
    body {
      margin: 0;
      background: #f1f5f9;
      font-family: 'Inter', 'Segoe UI', system-ui, sans-serif;
    }
    .report-shell {
      max-width: 960px;
      margin: 0 auto;
      padding: 32px;
      background: #ffffff;
      border-radius: 24px;
      box-shadow: 0 15px 40px rgba(15, 23, 42, 0.15);
      color: #0f172a;
    }
    .report-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-end;
      gap: 12px;
      border-bottom: 1px solid #e2e8f0;
      padding-bottom: 12px;
    }
    .report-title {
      font-size: 28px;
      font-weight: 700;
      letter-spacing: -0.04em;
      margin: 0;
    }
    .report-subtitle {
      margin-top: 6px;
      font-size: 12px;
      color: #475569;
    }
    .report-meta {
      font-size: 11px;
      color: #475569;
      text-align: right;
    }
    .report-meta span {
      display: block;
      font-size: 9px;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: #94a3b8;
    }
    .report-meta strong {
      display: block;
      font-size: 13px;
      margin-top: 4px;
    }
    .summary-grid {
      margin-top: 20px;
      display: grid;
      gap: 12px;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    }
    .summary-card {
      border: 1px solid #e2e8f0;
      border-radius: 16px;
      padding: 14px;
      background: #fff;
      box-shadow: 0 10px 24px rgba(15, 23, 42, 0.06);
    }
    .summary-card.highlight {
      background: linear-gradient(120deg, #0ea5e9, #6366f1);
      color: #ffffff;
      box-shadow: 0 14px 30px rgba(15, 23, 42, 0.12);
    }
    .summary-card .label {
      font-size: 10px;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: inherit;
    }
    .summary-card .value {
      font-size: 26px;
      font-weight: 700;
      margin-top: 4px;
      color: inherit;
    }
    .summary-card .sm {
      margin-top: 6px;
      font-size: 11px;
      color: inherit;
    }
    .section {
      margin-top: 32px;
    }
    .section h2 {
      font-size: 18px;
      margin-bottom: 8px;
      border-bottom: 1px solid #e2e8f0;
      padding-bottom: 6px;
    }
    .section-body {
      font-size: 14px;
      color: #0f172a;
      line-height: 1.6;
    }
    .summary-list p {
      margin: 6px 0;
    }
    .table-wrapper {
      margin-top: 12px;
      border-radius: 16px;
      border: 1px solid #e2e8f0;
      overflow: hidden;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }
    th, td {
      padding: 10px 12px;
    }
    th {
      background: #f8fafc;
      color: #475569;
      font-weight: 600;
      text-align: left;
      letter-spacing: 0.02em;
      border-bottom: 1px solid #e2e8f0;
    }
    td {
      border-bottom: 1px solid #f1f5f9;
    }
    tr:last-child td {
      border-bottom: 0;
    }
    .data-table td {
      font-size: 13px;
    }
    .muted {
      color: #475569;
      font-size: 12px;
    }
    .table-note {
      margin-top: 6px;
      font-size: 11px;
      color: #64748b;
    }
    .callout {
      border-radius: 16px;
      padding: 14px;
      font-size: 12.5px;
      line-height: 1.5;
      margin: 14px 0;
    }
    .callout.note {
      background: #eef2ff;
      border-left: 4px solid #2563eb;
    }
    .callout.ok {
      background: #ecfdf5;
      border-left: 4px solid #15803d;
    }
    .callout.warn {
      background: #fff7ed;
      border-left: 4px solid #b45309;
    }
    .recommendations-list {
      margin-top: 12px;
      display: grid;
      gap: 12px;
    }
    .recommendation-item {
      border: 1px solid #e2e8f0;
      border-radius: 14px;
      padding: 14px;
      background: #f8fafc;
    }
    .rec-priority {
      font-size: 10px;
      letter-spacing: 0.2em;
      text-transform: uppercase;
      color: #0f172a;
    }
    .rec-summary {
      margin-top: 6px;
      font-size: 14px;
      line-height: 1.5;
      color: #111827;
    }
    .rec-hosts {
      margin-top: 6px;
      font-size: 12px;
      color: #475569;
    }
    .watchlist-grid {
      margin-top: 12px;
      display: grid;
      gap: 16px;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    }
    .watchlist-card {
      border: 1px solid #e2e8f0;
      border-radius: 16px;
      padding: 16px;
      background: #fff;
    }
    .watchlist-card-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 12px;
      margin-bottom: 6px;
    }
    .watchlist-card-meta {
      display: flex;
      align-items: center;
      gap: 6px;
      flex-wrap: wrap;
      font-size: 12px;
      color: #0f172a;
    }
    .watchlist-score-badge,
    .watchlist-impact-badge {
      padding: 3px 10px;
      border-radius: 999px;
      font-size: 11px;
      background: #e0e7ff;
      color: #1d4ed8;
      border: 1px solid #c7d2fe;
    }
    .watchlist-impact-badge {
      background: #fef3c7;
      color: #92400e;
      border-color: #fde68a;
    }
    .watchlist-tech {
      margin-bottom: 8px;
      font-size: 14px;
      color: #0f172a;
    }
    .watchlist-applicability {
      font-size: 12px;
      color: #475569;
      margin-bottom: 12px;
    }
    .watchlist-summary {
      margin: 0;
      font-size: 13px;
      line-height: 1.4;
      color: #0f172a;
      margin-bottom: 12px;
    }
    .watchlist-impacted {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      font-size: 12px;
      color: #475569;
      margin-bottom: 8px;
    }
    .watchlist-impacted span {
      padding: 4px 8px;
      border-radius: 10px;
      border: 1px solid #e2e8f0;
      background: #f8fafc;
    }
    .watchlist-references,
    .watchlist-exploit {
      font-size: 12px;
      color: #1d4ed8;
      margin-bottom: 6px;
    }
    .watchlist-references a,
    .watchlist-exploit a {
      color: inherit;
      text-decoration: underline;
    }
    .watchlist-cve {
      margin-bottom: 12px;
      padding-bottom: 10px;
      border-bottom: 1px dashed #e2e8f0;
      font-size: 13px;
      color: #0f172a;
    }
    .watchlist-cve:last-child {
      border-bottom: 0;
      margin-bottom: 0;
      padding-bottom: 0;
    }
    .watchlist-cve p {
      margin: 4px 0;
    }
    .watchlist-sources {
      font-size: 12px;
      color: #475569;
      margin-top: 8px;
    }
    .hardening-grid {
      margin-top: 12px;
      display: grid;
      gap: 18px;
      grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    }
    .hardening-card {
      border: 1px solid #e2e8f0;
      border-radius: 16px;
      padding: 16px;
      background: #fff;
    }
    .card-title {
      font-size: 10px;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: #94a3b8;
      margin-bottom: 8px;
    }
    .bullet-list {
      padding-left: 20px;
      margin: 0;
      list-style-type: disc;
      color: #0f172a;
    }
    .bullet-list li + li {
      margin-top: 6px;
    }
    .appendix p {
      font-size: 12px;
      color: #475569;
      margin: 0;
    }
    code {
      font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
      background: #f1f5f9;
      padding: 2px 6px;
      border-radius: 6px;
      font-size: 11px;
    }
  </style>
</head>
<body>
  ${bodyHtml}
</body>
</html>`;
}

async function run({ target, emit, outDir, runTs }) {
  const rootOut = outDir || process.env.OUT_DIR || path.resolve('data', 'runs', runTs || 'run');
  const reportTs = process.env.RUN_TS || runTs || 'run';
  const reportDir = path.resolve('data', 'reports', reportTs);
  ensureDir(reportDir);

  const mdPath = path.join(reportDir, 'report.md');
  if (!fs.existsSync(mdPath)) {
    emitJsonl(emit, {
      type: 'note', tool: 'pdf-report', stage: STAGE, target,
      severity: 'info', evidence: [],
      data: { skipped: true, reason: 'report.md not found', expected: mdPath },
      source: SOURCE
    });
    return;
  }

  const recordsPath = path.join(rootOut, 'records.jsonl');
  const records = readJsonl(recordsPath);

  const body = buildPrettyBody({ target, runTs: reportTs, rootOut, records, mdPath });
  const html = htmlTemplate({ title: `Report: ${target}`, bodyHtml: body });

  const htmlPath = path.join(reportDir, 'report.html');
  fs.writeFileSync(htmlPath, html);

  const evidence = [htmlPath, mdPath, recordsPath];

  const pdfPath = path.join(reportDir, 'report.pdf');

  // Preferred: chromium headless print-to-pdf.
  if (which('chromium') || which('chromium-browser')) {
    const bin = which('chromium') ? 'chromium' : 'chromium-browser';
    const fileUrl = `file://${htmlPath}`;
    await runCmdCapture('bash', ['-lc', `${bin} --headless --disable-gpu --no-sandbox --enable-local-file-access --print-to-pdf=${JSON.stringify(pdfPath)} ${JSON.stringify(fileUrl)} >/dev/null 2>&1 || true`]);
    if (fs.existsSync(pdfPath) && fs.statSync(pdfPath).size > 0) {
      evidence.unshift(pdfPath);
      emitJsonl(emit, {
        type: 'note', tool: 'pdf-report', stage: STAGE, target,
        severity: 'info', evidence,
        data: { pdf: pdfPath, html: htmlPath, md: mdPath, rootOut },
        source: SOURCE
      });
      return;
    }
  }

  // Fallback: wkhtmltopdf.
  if (which('wkhtmltopdf')) {
    await runCmdCapture('bash', ['-lc', `wkhtmltopdf --enable-local-file-access ${JSON.stringify(htmlPath)} ${JSON.stringify(pdfPath)} >/dev/null 2>&1 || true`]);
    if (fs.existsSync(pdfPath) && fs.statSync(pdfPath).size > 0) {
      evidence.unshift(pdfPath);
      emitJsonl(emit, {
        type: 'note', tool: 'pdf-report', stage: STAGE, target,
        severity: 'info', evidence,
        data: { pdf: pdfPath, html: htmlPath, md: mdPath, rootOut },
        source: SOURCE
      });
      return;
    }
  }

  emitJsonl(emit, {
    type: 'note', tool: 'pdf-report', stage: STAGE, target,
    severity: 'info', evidence,
    data: { skipped: true, reason: 'no pdf backend available (chromium/wkhtmltopdf missing or failed)', html: htmlPath },
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
