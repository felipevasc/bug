// Lightweight .env loader (no external deps).
// - Only loads from repo root ".env" by default.
// - Does not override existing process.env keys.
// - Supports: KEY=VALUE, quoted values, and comments (# ...).
'use strict';

const fs = require('fs');
const path = require('path');

function parseEnvLine(line) {
  const trimmed = line.trim();
  if (!trimmed) return null;
  if (trimmed.startsWith('#')) return null;

  const eq = trimmed.indexOf('=');
  if (eq === -1) return null;

  const key = trimmed.slice(0, eq).trim();
  if (!key) return null;

  let value = trimmed.slice(eq + 1).trim();

  // Strip inline comments for unquoted values: FOO=bar # comment
  if (!(value.startsWith('"') || value.startsWith("'"))) {
    const hash = value.indexOf('#');
    if (hash !== -1) value = value.slice(0, hash).trim();
  }

  // Unquote simple quoted values.
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    value = value.slice(1, -1);
  }

  return { key, value };
}

function loadEnv(opts = {}) {
  const rootDir = opts.rootDir || path.resolve(__dirname, '..', '..');
  const envPath = opts.envPath || path.join(rootDir, '.env');

  if (!fs.existsSync(envPath)) return { loaded: false, path: envPath };

  const content = fs.readFileSync(envPath, 'utf8');
  const lines = content.split(/\r?\n/);
  let count = 0;

  for (const line of lines) {
    const parsed = parseEnvLine(line);
    if (!parsed) continue;
    if (Object.prototype.hasOwnProperty.call(process.env, parsed.key)) continue;
    process.env[parsed.key] = parsed.value;
    count += 1;
  }

  return { loaded: true, path: envPath, count };
}

module.exports = { loadEnv };

