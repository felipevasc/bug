#!/usr/bin/env node
'use strict';

const assert = require('assert');
const { parseTarget, normalizeTarget } = require('../src/lib/targets');
const { targetInScope } = require('../src/lib/scope');

const cases = [
  {
    input: 'Example.COM.',
    expected: { kind: 'domain', host: 'example.com', normalizedTarget: 'example.com' }
  },
  {
    input: ' HTTP://Example.com:80/ ',
    expected: { kind: 'url', host: 'example.com', scheme: 'http', url: 'http://example.com/', origin: 'http://example.com', port: undefined }
  },
  {
    input: 'https://Example.com:443/#frag',
    expected: { kind: 'url', host: 'example.com', scheme: 'https', url: 'https://example.com/', origin: 'https://example.com', port: undefined }
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
    expected: { kind: 'url', host: 'example.com', scheme: 'https', url: 'https://example.com:8080/', port: 8080 }
  },
  {
    input: 'https://example.com/',
    expected: { kind: 'url', host: 'example.com', scheme: 'https', url: 'https://example.com/' }
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

// Helper contract tests (runner/scope consume these semantics).
const parseCases = [
  { input: ' Example.COM. ', expected: { kind: 'domain', host: 'example.com', url: undefined } },
  { input: 'https://Example.com:443/#frag', expected: { kind: 'url', host: 'example.com', url: 'https://example.com/' } },
  { input: 'example.com/path?x=1#frag', expected: { kind: 'url', host: 'example.com', url: 'https://example.com/path?x=1' } }
];
for (const t of parseCases) {
  const actual = parseTarget(t.input);
  for (const [key, expected] of Object.entries(t.expected)) {
    try {
      assert.strictEqual(actual[key], expected);
    } catch (err) {
      failures += 1;
      process.stderr.write(`[targets-parse-test] ${t.input} expected ${key}=${expected} got ${actual[key]}\n`);
    }
  }
}

const scope = [
  'example.com',
  '*.example.net',
  'https://example.org/app'
];
const scopeChecks = [
  ['example.com', true],
  ['sub.example.com', true],
  ['https://sub.example.com/path', true],
  ['https://foo.example.net/', true],
  ['https://example.org/app/x', true],
  ['https://example.org/other', false],
  ['https://evil.com/', false]
];
for (const [target, expected] of scopeChecks) {
  try {
    assert.strictEqual(targetInScope(target, scope), expected);
  } catch (_err) {
    failures += 1;
    process.stderr.write(`[scope-test] ${target} expected in_scope=${expected}\n`);
  }
}

if (failures > 0) {
  process.stderr.write(`[target-test] failures: ${failures}\n`);
  process.exit(1);
}

process.stdout.write('ok\n');
