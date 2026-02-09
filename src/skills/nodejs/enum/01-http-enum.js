#!/usr/bin/env node
'use strict';

/**
 * @skill: nodejs/enum/http-enum
 * @inputs: target
 * @outputs: finding
 * @tools: httpx, curl
 */

function recordForTarget(target) {
  return {
    type: 'finding',
    target,
    data: {
      category: 'http-enum',
      endpoints: ['/', '/login'],
      notes: 'placeholder'
    },
    source: 'src/skills/nodejs/enum/01-http-enum.js'
  };
}

async function run({ target, emit }) {
  emit(recordForTarget(target));
}

function getArg(name) {
  const idx = process.argv.indexOf(name);
  return idx > -1 ? process.argv[idx + 1] : null;
}

function defaultEmit(record) {
  if (!record.timestamp) record.timestamp = new Date().toISOString();
  process.stdout.write(`${JSON.stringify(record)}\n`);
}

async function main() {
  const target = getArg('--target');
  if (!target) {
    process.stderr.write('Usage: --target <host>\n');
    process.exit(1);
  }

  await run({ target, emit: defaultEmit });
}

module.exports = { run };

if (require.main === module) {
  void main();
}
