#!/usr/bin/env node
'use strict';

/**
 * Reads JSONL from stdin (or --file) and ingests into Faraday when configured.
 * Always re-emits normalized JSONL to stdout.
 */

const fs = require('fs');
const { loadEnv } = require('../lib/load-env');
const { ingestRecord, buildPayload } = require('../lib/faraday');

loadEnv();

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const key = argv[i];
    const val = argv[i + 1];

    if (key === '--file' && val) {
      args.file = val;
      i += 1;
      continue;
    }

    if (key === '--workspace' && val) {
      args.workspace = val;
      i += 1;
      continue;
    }

    if (key === '--dry-run') {
      args.dryRun = true;
      continue;
    }

    if (key === '--strict') {
      args.strict = true;
      continue;
    }
  }
  return args;
}

function readStdin() {
  return new Promise((resolve) => {
    if (process.stdin.isTTY) return resolve('');
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => { data += chunk; });
    process.stdin.on('end', () => resolve(data));
  });
}

function safeJsonParse(line) {
  try {
    return { ok: true, value: JSON.parse(line) };
  } catch (_err) {
    return { ok: false, value: null };
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  let input = '';
  if (args.file) {
    input = fs.readFileSync(args.file, 'utf8');
  } else {
    input = await readStdin();
  }

  if (!input.trim()) {
    process.stderr.write('Usage: faraday-ingest [--file path.jsonl] [--workspace ws] [--dry-run] [--strict]\n');
    process.stderr.write('Provide JSONL via stdin or --file.\n');
    process.exit(1);
  }

  const lines = input.split('\n').filter((l) => l.trim().length > 0);
  let parseErrors = 0;
  let ingested = 0;

  for (const line of lines) {
    const parsed = safeJsonParse(line);
    if (!parsed.ok) {
      parseErrors += 1;
      process.stderr.write(`[faraday-ingest] invalid jsonl: ${line}\n`);
      if (args.strict) process.exit(2);
      continue;
    }

    const raw = parsed.value || {};
    const record = buildPayload({
      ...raw,
      workspace: raw.workspace || args.workspace,
      source: raw.source || 'stdin'
    });

    process.stdout.write(`${JSON.stringify(record)}\n`);

    if (!args.dryRun) {
      // eslint-disable-next-line no-await-in-loop
      await ingestRecord(record);
      ingested += 1;
    }
  }

  if (parseErrors > 0 && args.strict) process.exit(2);

  if (!args.dryRun) {
    process.stderr.write(`[faraday-ingest] ingested=${ingested} parse_errors=${parseErrors}\n`);
  }
}

main().catch((err) => {
  process.stderr.write(`[faraday-ingest] fatal: ${err && err.message ? err.message : String(err)}\n`);
  process.exit(1);
});
