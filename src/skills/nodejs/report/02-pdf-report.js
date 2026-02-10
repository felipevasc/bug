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

function table(headers, rows) {
  const th = headers.map((h) => `<th>${escapeHtml(h)}</th>`).join('');
  const body = rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join('')}</tr>`).join('');
  return `<table><thead><tr>${th}</tr></thead><tbody>${body}</tbody></table>`;
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
  const subdomains = Array.from(new Set(subdomainAssets.flatMap((a) => a.data.hostnames))).sort();

  const secHdr = findings.filter((r) => r.tool === 'security-headers');
  const sslWeak = findings.filter((r) => r.tool === 'sslscan' && r.data && r.data.weak_protocols === true);

  const byMissing = new Map();
  for (const f of secHdr) {
    const k = (f.data && f.data.missing) ? String(f.data.missing) : 'unknown';
    byMissing.set(k, (byMissing.get(k) || 0) + 1);
  }

  const topFindings = [...findings]
    .sort((a, b) => sevRank(b.severity) - sevRank(a.severity))
    .slice(0, 40)
    .map((f) => {
      const what = f.tool === 'security-headers'
        ? `missing ${escapeHtml(f.data && f.data.missing)}`
        : escapeHtml(f.data ? JSON.stringify(f.data).slice(0, 120) : '');
      const ev = Array.isArray(f.evidence) && f.evidence.length ? escapeHtml(String(f.evidence[0])) : '';
      return [badge(f.severity), `<code>${escapeHtml(f.tool)}</code>`, `<code>${escapeHtml(f.target)}</code>`, what, `<span class="muted">${ev}</span>`];
    });

  const secHdrRows = Array.from(byMissing.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 12)
    .map(([k, v]) => [`<code>${escapeHtml(k)}</code>`, `<b>${v}</b>`]);

  const summaryCards = `
  <div class="grid">
    <div class="card"><div class="k">Target</div><div class="v">${escapeHtml(target)}</div></div>
    <div class="card"><div class="k">Run</div><div class="v"><code>${escapeHtml(runTs)}</code></div></div>
    <div class="card"><div class="k">Records</div><div class="v">${counts.total}</div><div class="s">assets ${counts.assets} · findings ${counts.findings} · notes ${counts.notes}</div></div>
    <div class="card"><div class="k">Subdomains</div><div class="v">${subdomains.length}</div><div class="s">discovered in recon</div></div>
    <div class="card"><div class="k">Missing sec headers</div><div class="v">${secHdr.length}</div><div class="s">HSTS/CSP/etc</div></div>
    <div class="card"><div class="k">Weak TLS flags</div><div class="v">${sslWeak.length}</div><div class="s">sslscan heuristic</div></div>
  </div>`;

  const subdomainSample = subdomains.slice(0, 20).map((s) => `<code>${escapeHtml(s)}</code>`).join(' ');

  return `
  <div class="header">
    <div>
      <div class="title">Security Assessment Report</div>
      <div class="subtitle">Automated, non-intrusive checks (no exploitation). Generated for triage & hardening.</div>
    </div>
    <div class="meta">
      <div><b>Target:</b> <code>${escapeHtml(target)}</code></div>
      <div><b>Run:</b> <code>${escapeHtml(runTs)}</code></div>
    </div>
  </div>

  ${summaryCards}

  <h2>Executive summary</h2>
  <p>
    The scan prioritized <b>attack surface mapping</b> and <b>safe configuration checks</b>. Items below are grouped to help you quickly decide
    what to fix (hardening) and what to validate deeper (potential vulnerabilities).
  </p>

  <h2>Potential vulnerabilities (if any)</h2>
  <p class="muted">This section is populated by vulnerability templates/tools (e.g., Nuclei). Hardening signals (headers/TLS) are shown below.</p>
  ${findings.filter((f) => f.tool === 'nuclei').length
    ? table(['sev', 'tool', 'target', 'what'], [...findings]
        .filter((f) => f.tool === 'nuclei')
        .sort((a,b) => sevRank(b.severity) - sevRank(a.severity))
        .slice(0, 25)
        .map((f) => [badge(f.severity), `<code>${escapeHtml(f.tool)}</code>`, `<code>${escapeHtml(f.target)}</code>`, escapeHtml(f.data ? (f.data['template-id'] || f.data.name || JSON.stringify(f.data).slice(0, 140)) : '')]))
    : '<div class="callout ok"><b>No potential vulnerabilities were flagged</b> by enabled vulnerability templates in this run.</div>'}

  <h2>Hardening opportunities</h2>
  <div class="two">
    <div class="card">
      <div class="k">Missing HTTP security headers (most frequent)</div>
      ${secHdrRows.length ? table(['header', 'count'], secHdrRows) : '<p class="muted">No missing-header signals captured.</p>'}
      <div class="small muted">Tip: prioritize HSTS + CSP across public-facing hosts.</div>
    </div>
    <div class="card">
      <div class="k">TLS / SSL</div>
      ${sslWeak.length
        ? `<div class="callout warn"><b>Legacy/weak TLS</b> was observed on <b>${sslWeak.length}</b> checks (sampled endpoints).</div>`
        : '<div class="callout ok"><b>No weak-TLS signals</b> were reported by sslscan in this run.</div>'}
      <ul>
        <li>Confirm supported protocols/ciphers and disable legacy versions where possible.</li>
      </ul>
    </div>
  </div>

  <h2>Attack surface snapshot</h2>
  <div class="card">
    <div class="k">Subdomains discovered from site links</div>
    <div class="s">Total: <b>${subdomains.length}</b> · sample:</div>
    <div class="chips">${subdomainSample || '<span class="muted">(none)</span>'}</div>
  </div>

  <h2>Prioritized findings (compact)</h2>
  <p class="muted">A compact view of top signals across tools. Detailed evidence remains in the run folder artifacts.</p>
  ${table(['sev', 'tool', 'target', 'what'], topFindings.map((r) => r.slice(0, 4)))}

  <h2>Limitations</h2>
  <div class="card">
    <ul>
      <li>Automated scan only; manual validation is recommended before any conclusions.</li>
      <li>Some tools may be missing/timeout in the environment; coverage may be partial.</li>
      <li>Artifacts available in the run folder: <code>report.md</code>, <code>records.jsonl</code>, and <code>evidence/</code>.</li>
    </ul>
  </div>
  `;
}

function htmlTemplate({ title, bodyHtml }) {
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>${escapeHtml(title)}</title>
  <style>
    @page { size: A4; margin: 16mm 14mm; }
    body { font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Arial, sans-serif; color: #0f172a; }

    .header { display:flex; justify-content:space-between; align-items:flex-end; margin-bottom:14px; }
    .title { font-size: 20px; font-weight: 750; letter-spacing: -0.02em; }
    .subtitle { font-size: 11px; color: #475569; margin-top: 2px; }
    .meta { font-size: 10px; color: #64748b; text-align:right; max-width: 320px; }

    h2 { font-size: 13px; margin: 16px 0 8px; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; }
    p, li { font-size: 10.5px; line-height: 1.4; margin: 0 0 6px; }

    code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 10px; background: #f1f5f9; padding: 1px 4px; border-radius: 4px; }
    pre { background: #0b1020; color: #e6edf3; padding: 10px; border-radius: 10px; overflow-wrap: anywhere; white-space: pre-wrap; }
    pre code { background: transparent; color: inherit; padding: 0; }

    .grid { display:grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin: 10px 0 16px; }
    .two { display:grid; grid-template-columns: 1.1fr 0.9fr; gap: 10px; }

    .card { border:1px solid #e2e8f0; border-radius: 12px; padding: 10px; background: #ffffff; }
    .k { font-size: 10px; color:#64748b; text-transform: uppercase; letter-spacing: .06em; }
    .v { font-size: 16px; font-weight: 800; margin-top: 2px; }
    .s { font-size: 10px; color:#475569; margin-top: 2px; }

    table { width:100%; border-collapse: collapse; font-size: 10px; }
    th { text-align:left; color:#64748b; font-weight: 700; border-bottom:1px solid #e2e8f0; padding: 6px 6px; }
    td { border-bottom:1px solid #f1f5f9; padding: 6px 6px; vertical-align: top; }
    tr:last-child td { border-bottom: 0; }

    .muted { color:#64748b; }
    .chips { margin-top: 6px; }
    .chips code { margin-right: 4px; display:inline-block; margin-bottom: 4px; }

    .badge { display:inline-block; padding: 2px 8px; border-radius: 999px; font-size: 10px; font-weight: 700; }
    .badge-info { background:#e0f2fe; color:#075985; }
    .badge-low { background:#ecfccb; color:#365314; }
    .badge-med { background:#ffedd5; color:#9a3412; }
    .badge-high { background:#fee2e2; color:#991b1b; }
    .badge-crit { background:#0f172a; color:#fff; }
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
