# Changelog

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
