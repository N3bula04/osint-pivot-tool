# Changelog

## Unreleased

Markdown reports now open with a generated Assessment that ranks priority
links, gives one alternative explanation, and highlights the biggest source gap.

- README: personal-project framing, quick start with the offline demo, and an
  ethics / public-data-only section. Older hand-made samples are distinguished
  from the synthetic offline demo.
- Tests, docs and demo fixtures use fictional `co.uk` names for the Public
  Suffix List cases instead of real or government-style `.gov.sg` names. The
  committed sample report is regenerated to match.
- `.gitignore`: also ignore `.env.*`, key files, `secrets/` and saved
  `*.crtsh.json` lookups.
- CI: test on Python 3.10 and 3.12. GitHub's current `ubuntu-latest` image no
  longer provides Python 3.9 (end of life), so the 3.9 job could not start.

## 0.3.2 (2026-09-30)

CI and a fully offline demo. Rating rules are unchanged apart from the PSL fix below.

### Added
- `--demo`: runs the whole pipeline against synthetic fixtures in
  `examples/offline_demo/` (seed `example-demo.test`, reserved/fictional names,
  documentation IP ranges only) with a pinned timestamp.
- `--offline DIR`: the same for your own fixtures (`dns.json`, `crtsh.json`, `rdap/`).
  While it runs, sockets, DNS resolution and `requests` are replaced by a guard
  that raises `NetworkBlockedError`, so no network call can happen silently.
- `--fixed-time ISO8601`: pins all timestamps and certificate/domain age maths
  so output is reproducible.
- `samples/`: committed synthetic demo report (Markdown + CSV).
- `tests/`: pytest suite (offline end-to-end, sample diff, determinism, no
  network calls, fixture resolver, `normalise_domain`, self-check script);
  `requirements-dev.txt` pins pytest and pyflakes.
- GitHub Actions CI (`.github/workflows/ci.yml`): Python 3.9 and 3.12, pyflakes,
  `test_rating.py`, pytest, offline demo, and a diff against `samples/`.

### Fixed
- Registrable domain for TLDs not on the Public Suffix List (`.test`,
  `.internal`, ...) now follows the PSL default rule (`www.example-demo.test`
  -> `example-demo.test`), instead of treating the whole host as the owner.
- The crt.sh file log entry shows only the file name, not the full local path.

### Changed
- Reports from offline runs carry a SYNTHETIC banner and an accurate Method line.

## 0.3.1 (2026-09-30)

Accuracy and safety fixes from a code review. No new data sources.

### Rating accuracy
- Provider matching (MX, NS, SPF include/redirect, DMARC) is now a suffix match on a
  label boundary instead of a substring match. `mx.google.com.evil.net`,
  `ns1.myname.com` and `_spf.salesforce.com.attacker.io` no longer match Google,
  Name.com or Salesforce. Multi-TLD DNS providers (Route 53, UltraDNS, Azure DNS)
  are matched on the registrable label only.
- Reverse-DNS provider patterns (amazonaws.com, googleusercontent.com, ...) are
  anchored on a label boundary.
- "Same owner" now uses the Public Suffix List via `tldextract`, from its bundled
  snapshot (no network fetch). `www.shop-a.co.uk` -> `shop-a.co.uk`, and `shop-a.co.uk`
  is no longer the same owner as `ns.shop-b.co.uk`. A small built-in suffix list
  remains as an offline fallback if `tldextract` is unavailable.
- Netblock holder keywords are matched as whole words; the overly broad bare
  words `colo`, `server`, `cloud` and `constant` were dropped or made specific
  (so "Colombia Movil" is no longer "hosting").
- The "seed name appears in netblock holder" rule needs the full registrable
  label (4+ characters, whole word, not a generic word such as "online" or
  "data"). Seed `online.com` no longer matches "Hetzner Online GmbH".
- Lowered over-confident ratings to Medium:
  - `possible_origin_ip` unless PTR (under the seed's domain) or RDAP confirms it;
  - shared certificates that have expired;
  - unredacted RDAP contact email at a different domain;
  - `shared_ip` links unless PTR/RDAP confirms the IP belongs to the seed;
  - A/AAAA links for third-party hosts found in the IP pivot (new flag
    `unverified_third_party_ip`).
- RDAP now also looks up the non-CDN IPs of related third-party hosts (capped at
  4 per run, on top of the 8 seed IPs).
- `shared_ip` links carry the IP in `meta["ip"]` instead of it being parsed back
  out of the evidence text.

### Collection
- RDAP: on the first HTTP 429 the tool stops all RDAP requests for the run, logs the
  rest as `skipped`, and stores the `Retry-After` window (default 10 minutes) so
  later runs wait too.
- User-Agent now reports version 0.3.1.

### Reports
- CSV cells starting with `=`, `+`, `-`, `@`, tab or CR are prefixed with `'` to
  prevent spreadsheet formula injection.
- Markdown escaping also handles backticks and carriage returns.
- Long error messages are truncated to 200 characters in the report and console.
- Wording: "Authoritative DNS answer" -> "DNS answer (recursive resolver)";
  removed the stale "(RDAP in Stage 3)"; "passive / no direct contact" claims
  replaced with "no direct connections from this tool to the target's web/app
  servers".

### Setup and docs
- `setup.sh` uses `set -o pipefail`, so a failing self-check fails setup;
  `setup.bat` stops on a failing self-check; `run.sh` / `run.bat` propagate errors.
- Dependencies pinned in `requirements.txt` (dnspython, requests, tldextract),
  with Python 3.9-compatible pins for older interpreters.
- README: clone/ZIP instructions point at `main`, dependency count, report
  heading name, RDAP 429 behaviour, and a short "How this was built" note.
- Self-check grew from 49 to 94 checks covering each fix.

## 0.3.0

- Stage 3: RDAP registration data for the seed domain and its netblocks; origin-IP
  hints for seed-owned hosts behind a CDN; double-click setup/run scripts.
