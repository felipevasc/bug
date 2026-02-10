#!/usr/bin/env node
'use strict';

const assert = require('assert');
const { normalizeTarget } = require('../src/lib/target');

const cases = [
  {
    input: 'Example.COM.',
    expected: { kind: 'domain', host: 'example.com', normalizedTarget: 'example.com' }
  },
  {
    input: ' HTTP://Example.com:80/ ',
    expected: { kind: 'url', host: 'example.com', scheme: 'http', url: 'http://example.com', origin: 'http://example.com', port: undefined }
  },
  {
    input: 'https://Example.com:443/#frag',
    expected: { kind: 'url', host: 'example.com', scheme: 'https', url: 'https://example.com', origin: 'https://example.com', port: undefined }
  },
  {
    input: 'example.com/path',
    expected: { kind: 'url', host: 'example.com', scheme: 'https', url: 'https://example.com/path' }
  },
  {
    input: 'example.com/?q=1',
    expected: { kind: 'url', host: 'example.com', scheme: 'https', url: 'https://example.com/?q=1' }
  },
  {
    input: 'example.com:8080',
    expected: { kind: 'url', host: 'example.com', scheme: 'https', url: 'https://example.com:8080', port: 8080 }
  },
  {
    input: 'https://example.com/',
    expected: { kind: 'url', host: 'example.com', scheme: 'https', url: 'https://example.com' }
  },
  {
    input: 'https://example.com/path/',
    expected: { kind: 'url', host: 'example.com', scheme: 'https', url: 'https://example.com/path/' }
  },
  {
    input: 'https://example.com/path#frag',
    expected: { kind: 'url', host: 'example.com', scheme: 'https', url: 'https://example.com/path' }
  }
];

let failures = 0;
for (const t of cases) {
  const actual = normalizeTarget(t.input);
  for (const [key, expected] of Object.entries(t.expected)) {
    try {
      assert.strictEqual(actual[key], expected);
    } catch (err) {
      failures += 1;
      process.stderr.write(`[target-test] ${t.input} expected ${key}=${expected} got ${actual[key]}\n`);
    }
  }
}

if (failures > 0) {
  process.stderr.write(`[target-test] failures: ${failures}\n`);
  process.exit(1);
}

process.stdout.write('ok\n');
