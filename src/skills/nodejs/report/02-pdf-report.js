#!/usr/bin/env node
'use strict';

/**
 * @skill: nodejs/report/pdf-report
 * @inputs: target[, out-dir]
 * @outputs: note
 * @tools: wkhtmltopdf (optional)
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

function mdToHtml(md) {
  // Minimal markdown rendering (headings, lists, code fences, tables-as-pre).
  // This avoids adding npm deps; formatting is decent enough for PDF.
  const lines = String(md || '').split('\n');
  const out = [];
  let inCode = false;
  let inList = false;

  const flushList = () => {
    if (inList) {
      out.push('</ul>');
      inList = false;
    }
  };

  for (const raw of lines) {
    const line = raw.replace(/\r$/, '');

    if (line.trim().startsWith('```')) {
      flushList();
      if (!inCode) {
        inCode = true;
        out.push('<pre><code>');
      } else {
        inCode = false;
        out.push('</code></pre>');
      }
      continue;
    }

    if (inCode) {
      out.push(`${escapeHtml(line)}\n`);
      continue;
    }

    const h1 = line.match(/^#\s+(.*)$/);
    const h2 = line.match(/^##\s+(.*)$/);
    const h3 = line.match(/^###\s+(.*)$/);
    if (h1) { flushList(); out.push(`<h1>${escapeHtml(h1[1])}</h1>`); continue; }
    if (h2) { flushList(); out.push(`<h2>${escapeHtml(h2[1])}</h2>`); continue; }
    if (h3) { flushList(); out.push(`<h3>${escapeHtml(h3[1])}</h3>`); continue; }

    const li = line.match(/^[-*]\s+(.*)$/);
    if (li) {
      if (!inList) { out.push('<ul>'); inList = true; }
      out.push(`<li>${escapeHtml(li[1])}</li>`);
      continue;
    }

    if (line.trim().length === 0) {
      flushList();
      out.push('<div class="spacer"></div>');
      continue;
    }

    flushList();
    // Simple inline code: `x`
    const rendered = escapeHtml(line).replace(/`([^`]+)`/g, '<code>$1</code>');
    out.push(`<p>${rendered}</p>`);
  }

  flushList();
  if (inCode) out.push('</code></pre>');
  return out.join('\n');
}

function htmlTemplate({ title, bodyHtml }) {
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>${escapeHtml(title)}</title>
  <style>
    @page { size: A4; margin: 18mm 16mm; }
    body { font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Arial, sans-serif; color: #111; }
    h1 { font-size: 22px; margin: 0 0 10px; }
    h2 { font-size: 16px; margin: 18px 0 8px; border-bottom: 1px solid #eee; padding-bottom: 4px; }
    h3 { font-size: 13px; margin: 14px 0 6px; }
    p, li { font-size: 11px; line-height: 1.35; }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 10px; background: #f6f8fa; padding: 1px 4px; border-radius: 4px; }
    pre { background: #0b1020; color: #e6edf3; padding: 10px; border-radius: 8px; overflow-wrap: anywhere; }
    pre code { background: transparent; color: inherit; padding: 0; }
    ul { margin: 6px 0 6px 18px; }
    .spacer { height: 6px; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 999px; background: #eef2ff; color: #3730a3; font-size: 10px; }
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

  const md = fs.readFileSync(mdPath, 'utf8');
  const body = mdToHtml(md);
  const html = htmlTemplate({ title: `Report: ${target}`, bodyHtml: body });

  const htmlPath = path.join(reportDir, 'report.html');
  fs.writeFileSync(htmlPath, html);

  const evidence = [htmlPath, mdPath];

  if (which('wkhtmltopdf')) {
    const pdfPath = path.join(reportDir, 'report.pdf');
    // wkhtmltopdf wants local file access enabled for file://
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

    emitJsonl(emit, {
      type: 'note', tool: 'pdf-report', stage: STAGE, target,
      severity: 'info', evidence,
      data: { skipped: true, reason: 'wkhtmltopdf failed or produced empty pdf', html: htmlPath },
      source: SOURCE
    });
    return;
  }

  emitJsonl(emit, {
    type: 'note', tool: 'pdf-report', stage: STAGE, target,
    severity: 'info', evidence,
    data: { skipped: true, reason: 'wkhtmltopdf not installed', html: htmlPath },
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
