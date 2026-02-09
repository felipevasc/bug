# Base (Upstream) Wordlists

We intentionally do **not** commit large upstream wordlists into this repo.

Recommended sources:
- SecLists (Kali: `/usr/share/seclists`)
  - Discovery/Web-Content/common.txt
  - Discovery/Web-Content/raft-large-words.txt
  - Discovery/Web-Content/directory-list-2.3-medium.txt
  - Discovery/Web-Content/api/ (API-centric lists)
  - Usernames/ (user lists)

Strategy:
- Skills should prefer `wordlists/custom/*` when present.
- If missing, fall back to SecLists paths.

Why:
- Keeps the repo small and portable.
- Still lets us persist our *findings-derived* deltas.
