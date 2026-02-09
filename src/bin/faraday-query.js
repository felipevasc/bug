#!/usr/bin/env node
'use strict';

/**
 * Minimal Faraday query helper.
 *
 * Commands:
 * - list-hosts --workspace <ws>
 * - find-host --workspace <ws> --target <ip|hostname>
 * - create-workspace --workspace <ws>
 */

const { loadEnv } = require('../lib/load-env');
const { baseUrlFromEnv, authHeaders, listHosts, createWorkspace } = require('../lib/faraday');

loadEnv();

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const key = argv[i];
    const val = argv[i + 1];

    if (key.startsWith('--') && val && !val.startsWith('--')) {
      args[key.slice(2)] = val;
      i += 1;
      continue;
    }

    args._.push(key);
  }
  return args;
}

function usage() {
  process.stderr.write('Usage:\n');
  process.stderr.write('  faraday-query list-hosts --workspace <ws>\n');
  process.stderr.write('  faraday-query find-host --workspace <ws> --target <ip|hostname>\n');
  process.stderr.write('  faraday-query create-workspace --workspace <ws>\n');
}

function findHost(hosts, target) {
  if (!Array.isArray(hosts)) return null;
  for (const h of hosts) {
    if (!h) continue;
    if (h.ip === target) return h;
    if (Array.isArray(h.hostnames) && h.hostnames.includes(target)) return h;
  }
  return null;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const cmd = args._[0];
  if (!cmd) {
    usage();
    process.exit(1);
  }

  const baseUrl = baseUrlFromEnv();
  if (!baseUrl) {
    process.stderr.write('FARADAY_URL not set/invalid\n');
    process.exit(1);
  }

  const ws = args.workspace || process.env.FARADAY_WORKSPACE;
  if (!ws) {
    process.stderr.write('Missing workspace. Use --workspace or FARADAY_WORKSPACE\n');
    process.exit(1);
  }

  const headers = await authHeaders(baseUrl);
  if (!headers || Object.keys(headers).length === 0) {
    process.stderr.write('Missing auth. Set FARADAY_TOKEN or FARADAY_USER/FARADAY_PASS\n');
    process.exit(1);
  }

  if (cmd === 'list-hosts') {
    const res = await listHosts(baseUrl, ws, headers);
    if (!res.ok) {
      process.stderr.write(`Request failed (status ${res.status})\n`);
      process.exit(1);
    }

    process.stdout.write(`${JSON.stringify(res.data)}\n`);
    return;
  }

  if (cmd === 'create-workspace') {
    const res = await createWorkspace(baseUrl, ws, headers, { description: 'Created by bugbounty-automation-hub' });
    if (!res.ok) {
      process.stderr.write(`Request failed (status ${res.status})\n`);
      if (res.text) process.stderr.write(`${res.text}\n`);
      process.exit(1);
    }
    process.stdout.write(`${JSON.stringify(res.json || res.text || { ok: true })}\n`);
    return;
  }

  if (cmd === 'find-host') {
    const target = args.target;
    if (!target) {
      usage();
      process.exit(1);
    }

    const res = await listHosts(baseUrl, ws, headers);
    if (!res.ok) {
      process.stderr.write(`Request failed (status ${res.status})\n`);
      process.exit(1);
    }

    const host = findHost(res.data, target);
    if (!host) {
      process.stderr.write('Host not found\n');
      process.exit(2);
    }

    process.stdout.write(`${JSON.stringify(host)}\n`);
    return;
  }

  process.stderr.write(`Unknown command: ${cmd}\n`);
  usage();
  process.exit(1);
}

main().catch((err) => {
  process.stderr.write(`[faraday-query] fatal: ${err && err.message ? err.message : String(err)}\n`);
  process.exit(1);
});
