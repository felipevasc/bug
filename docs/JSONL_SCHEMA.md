# JSONL Schema (Repo Invariant)

All skills must write **JSONL** to stdout (1 JSON object per line). No logs in stdout (send logs to stderr).

## Required fields (do not remove)

- `type`: `asset` | `finding` | `note`
- `tool`: string (skill/tool name)
- `stage`: `recon` | `enum` | `exploit` | `report`
- `target`: string
- `ts`: ISO 8601 timestamp (string)
- `timestamp`: ISO 8601 timestamp (string). Kept for compatibility; usually equals `ts`.
- `severity`: `info` | `low` | `medium` | `high` | `critical`
- `evidence`: array (can be empty). Prefer small text snippets and paths to saved artifacts.

## Common optional fields

- `data`: object (free-form payload)
- `source`: script path (e.g. `src/skills/python/enum/01-port-scan.py`)
- `workspace`: Faraday workspace name

## Notes

- The pipeline runner normalizes missing fields where possible, but skills should emit schema-compliant records directly.
- Intrusive actions must be explicitly gated (see `src/bin/run-pipeline.js` exploit stage gate).

