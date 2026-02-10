'use strict';

const WATCHLIST_SEVERITY_ORDER = ['crit', 'high', 'med', 'low', 'info', 'unknown'];
const WATCHLIST_APPLICABILITY_ORDER = { likely: 0, unknown: 1 };

function getWatchlistEntryTimestamp(entry) {
  return entry && (entry.timestamp || entry.ts || '');
}

function watchlistScore(entry) {
  if (!entry) return -1;
  const score = entry.score;
  if (score === null || score === undefined) return -1;
  return Number.isFinite(score) ? score : Number(score) || -1;
}

function shouldReplaceWatchlistEntry(existing, candidate) {
  if (!existing) return true;
  if (!candidate) return false;
  const existingTs = getWatchlistEntryTimestamp(existing);
  const candidateTs = getWatchlistEntryTimestamp(candidate);
  if (candidateTs && existingTs && candidateTs !== existingTs) {
    return candidateTs > existingTs;
  }
  const existingScore = watchlistScore(existing);
  const candidateScore = watchlistScore(candidate);
  if (candidateScore !== existingScore) return candidateScore > existingScore;
  return true;
}

function formatTechKey(tech = {}) {
  return [tech.vendor, tech.product, tech.version, tech.detail]
    .map((value) => String(value || '').trim().toLowerCase())
    .join('|');
}

function collectWatchlistEntries(notes = []) {
  const dedup = new Map();
  notes.forEach((note) => {
    const entries = note?.data?.watchlist;
    if (!Array.isArray(entries)) return;
    entries.forEach((entry) => {
      if (!entry || !entry.cveId) return;
      const key = `${entry.cveId}|${formatTechKey(entry.tech || {})}`;
      const existing = dedup.get(key);
      if (!existing || shouldReplaceWatchlistEntry(existing, entry)) {
        dedup.set(key, entry);
      }
    });
  });
  return Array.from(dedup.values());
}

function addReferencesToSet(store, list) {
  if (!list || !Array.isArray(list)) return;
  list.forEach((value) => {
    if (value) store.add(value);
  });
}

function addSources(store, list) {
  if (!list || !Array.isArray(list)) return;
  list.forEach((value) => {
    if (value) store.add(value);
  });
}

function addTechVariant(store, tech) {
  if (!tech) return;
  const key = formatTechKey(tech);
  if (!key) return;
  if (store.has(key)) return;
  store.set(key, {
    vendor: tech.vendor || tech.product || null,
    product: tech.product || tech.vendor || null,
    version: tech.version || null,
    detail: tech.detail || null
  });
}

function pickBetterWatchlistEntry(existing, candidate) {
  if (!existing) return candidate;
  if (!candidate) return existing;
  if (shouldReplaceWatchlistEntry(existing, candidate)) return candidate;
  return existing;
}

function severityRank(entry) {
  const severity = String(entry?.severityBand || 'unknown').toLowerCase();
  const idx = WATCHLIST_SEVERITY_ORDER.indexOf(severity);
  return idx === -1 ? WATCHLIST_SEVERITY_ORDER.length : idx;
}

function sortAggregatedEntries(entries) {
  return entries.sort((a, b) => {
    const aApplicability = WATCHLIST_APPLICABILITY_ORDER[a.applicability] ?? WATCHLIST_APPLICABILITY_ORDER.unknown;
    const bApplicability = WATCHLIST_APPLICABILITY_ORDER[b.applicability] ?? WATCHLIST_APPLICABILITY_ORDER.unknown;
    if (aApplicability !== bApplicability) return aApplicability - bApplicability;

    const aSeverity = severityRank(a);
    const bSeverity = severityRank(b);
    if (aSeverity !== bSeverity) return aSeverity - bSeverity;

    const aScore = watchlistScore(a);
    const bScore = watchlistScore(b);
    if (aScore !== bScore) return bScore - aScore;

    if (a.published && b.published) {
      const cmp = b.published.localeCompare(a.published);
      if (cmp !== 0) return cmp;
    }

    return String(a.cveId || '').localeCompare(String(b.cveId || ''));
  });
}

function aggregateWatchlistByCve(entries = []) {
  const groups = new Map();
  entries.forEach((entry) => {
    if (!entry || !entry.cveId) return;
    const key = entry.cveId;
    const group = groups.get(key) || {
      best: entry,
      references: new Set(entry.references || []),
      exploitReferences: new Set(entry.exploitReferences || []),
      sources: new Set(entry.sources || []),
      techVariants: new Map(),
      count: 0
    };
    group.count += 1;
    group.best = pickBetterWatchlistEntry(group.best, entry);
    addTechVariant(group.techVariants, entry.tech);
    addReferencesToSet(group.references, entry.references);
    addReferencesToSet(group.exploitReferences, entry.exploitReferences);
    addSources(group.sources, entry.sources);
    groups.set(key, group);
  });
  const aggregated = Array.from(groups.values()).map((group) => ({
    ...group.best,
    references: Array.from(group.references),
    exploitReferences: Array.from(group.exploitReferences),
    sources: Array.from(group.sources),
    techVariants: Array.from(group.techVariants.values()),
    variantCount: group.techVariants.size,
    matchCount: group.count
  }));
  return sortAggregatedEntries(aggregated);
}

module.exports = {
  collectWatchlistEntries,
  aggregateWatchlistByCve
};
