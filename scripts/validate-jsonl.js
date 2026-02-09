#!/usr/bin/env node
'use strict';

/**
 * Validate JSONL records for required schema keys:
 * type, tool, stage, target, ts, timestamp, severity, evidence
 *
 * Usage:
 *   node scripts/validate-jsonl.js --file data/runs/<ts>/records.jsonl
 *   cat records.jsonl | node scripts/validate-jsonl.js --stdin
 */

const fs = require('fs');

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const k = argv[i];
    const v = argv[i + 1];
    if (k === '--file' && v) { args.file = v; i += 1; continue; }
    if (k === '--stdin') { args.stdin = true; continue; }
    if (k === '--max-errors' && v) { args.maxErrors = Number(v); i += 1; continue; }
  }
  return args;
}

const REQUIRED = ['type', 'tool', 'stage', 'target', 'ts', 'timestamp', 'severity', 'evidence', 'source', 'data'];

function validateObj(obj) {
  if (!obj || typeof obj !== 'object') return 'not_object';
  for (const k of REQUIRED) {
    if (!(k in obj)) return `missing_${k}`;
  }
  if (!Array.isArray(obj.evidence)) return 'evidence_not_array';
  if (typeof obj.source !== 'string' || obj.source.length === 0) return 'source_not_string';
  if (!obj.data || typeof obj.data !== 'object' || Array.isArray(obj.data)) return 'data_not_object';
  return null;
}

async function readAllStdin() {
  return new Promise((resolve) => {
    let s = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (d) => { s += d; });
    process.stdin.on('end', () => resolve(s));
    process.stdin.resume();
  });
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const maxErrors = Number.isFinite(args.maxErrors) && args.maxErrors > 0 ? args.maxErrors : 20;

  let text = '';
  if (args.stdin) {
    text = await readAllStdin();
  } else if (args.file) {
    text = fs.readFileSync(args.file, 'utf8');
  } else {
    process.stderr.write('Usage: validate-jsonl --file <path> | --stdin [--max-errors 20]\n');
    process.exit(2);
  }

  const lines = text.split('\n').filter((l) => l.trim().length > 0);
  let bad = 0;

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    let obj = null;
    try {
      obj = JSON.parse(line);
    } catch (_e) {
      bad += 1;
      process.stderr.write(`[jsonl] line ${i + 1}: invalid_json\n`);
      if (bad >= maxErrors) break;
      continue;
    }

    const err = validateObj(obj);
    if (err) {
      bad += 1;
      process.stderr.write(`[jsonl] line ${i + 1}: ${err}\n`);
      if (bad >= maxErrors) break;
    }
  }

  if (bad > 0) {
    process.stderr.write(`[jsonl] FAIL: ${bad} bad record(s)\n`);
    process.exit(1);
  }
  process.stderr.write(`[jsonl] OK: ${lines.length} record(s)\n`);
}

void main();

