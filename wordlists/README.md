# Wordlists

This repo keeps **curated, incrementally improved wordlists** for bug bounty workflows.

Principles:
- Do **not** vendor huge third-party lists into git.
- Start from well-known upstream lists (e.g. SecLists) and keep our **custom deltas** here.
- Keep multiple lists for different purposes (paths, params, users, subdomains...).
- Everything we discover during recon/enum (dirs/files, endpoints in JS, params) can feed these lists.

Structure:
- `wordlists/base/`   → documentation/pointers to upstream sources (not committed data dumps)
- `wordlists/custom/` → our curated lists (tracked in git)

Update:
- Use `bash scripts/update-wordlists.sh --from-run data/runs/<RUN_TS>` to ingest new tokens.
