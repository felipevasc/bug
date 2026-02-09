#!/usr/bin/env node
'use strict';

/**
 * @skill: nodejs/recon/passive-recon
 * @inputs: target, stdin(jsonl)
 * @outputs: asset
 * @tools: whois, dig
 */

function recordForTarget(target) {
  return {
    type: 'asset',
    target,
    data: {
      method: 'passive-recon',
      notes: 'placeholder'
    },
    source: 'src/skills/nodejs/recon/01-passive-recon.js'
  };
}

async function run({ target, emit }) {
  emit(recordForTarget(target));
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const key = argv[i];
    const val = argv[i + 1];
    if (key === '--target' && val) {
      args.target = val;
      i += 1;
    }
  }
  return args;
}

function defaultEmit(record) {
  if (!record.timestamp) record.timestamp = new Date().toISOString();
  process.stdout.write(`${JSON.stringify(record)}\n`);
}

async function handleTargets(targets) {
  for (const t of targets.filter(Boolean)) {
    // eslint-disable-next-line no-await-in-loop
    await run({ target: t, emit: defaultEmit });
  }
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

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const stdin = await readStdin();
  const targets = [];

  if (args.target) targets.push(args.target);

  if (stdin.trim()) {
    stdin.trim().split('\n').forEach((line) => {
      try {
        const obj = JSON.parse(line);
        if (obj.target) targets.push(obj.target);
      } catch (_err) {
        // ignore malformed lines
      }
    });
  }

  if (targets.length === 0) {
    process.stderr.write('Usage: --target <host> or stdin jsonl with target\n');
    process.exit(1);
  }

  await handleTargets(targets);
}

module.exports = { run };

if (require.main === module) {
  void main();
}
