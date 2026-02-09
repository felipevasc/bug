/* eslint-disable no-param-reassign */
'use strict';

function nowIso() {
  return new Date().toISOString();
}

function asArray(value) {
  if (Array.isArray(value)) return value;
  if (value === undefined || value === null) return [];
  return [value];
}

function normalizeSeverity(value) {
  const s = String(value || '').toLowerCase();
  if (!s) return 'info';
  if (s === 'med') return 'medium';
  if (s === 'crit') return 'critical';
  if (['info', 'low', 'medium', 'high', 'critical'].includes(s)) return s;
  return 'info';
}

/**
 * Normalize a JSONL record to ensure the pipeline schema keys exist.
 * Required keys (repo invariant): type, tool, stage, target, ts, timestamp, severity, evidence
 */
function normalizeRecord(raw, defaults = {}) {
  const r = raw && typeof raw === 'object' ? { ...raw } : {};

  // Identity-ish fields
  r.type = r.type || defaults.type || 'note';
  r.tool = r.tool || defaults.tool || 'unknown';
  r.stage = r.stage || defaults.stage || 'unknown';
  r.target = r.target || defaults.target || '';

  // Time
  r.ts = r.ts || r.timestamp || defaults.ts || nowIso();
  r.timestamp = r.timestamp || r.ts;

  // Triage
  r.severity = normalizeSeverity(r.severity || defaults.severity);
  r.evidence = asArray(r.evidence || defaults.evidence);

  return r;
}

module.exports = {
  normalizeRecord
};
