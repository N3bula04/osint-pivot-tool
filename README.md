# osint-pivot-tool

Passive OSINT infrastructure pivot tool with evidence-rated links.

Give it one seed domain. It collects passive, public data about that domain,
pivots one hop to related domains and IPs, and writes:

- a **Markdown report** you can read and hand to someone else, and
- a **CSV of links** (`source_entity, related_entity, link_type, evidence,
  data_source, timestamp, confidence, confidence_reason, flags`) you can filter
  in a spreadsheet.

Every link cites its evidence and data source. Every link carries a
High / Medium / Low confidence rating with a one-line reason. Shared
infrastructure (CDNs, managed DNS, mail providers, cloud hosting) is flagged
and downgraded. Sources that fail or return nothing are logged so gaps are
visible. The tool never attributes activity to a named actor.

**Current version: Stage 3 (DNS + certificate transparency + RDAP).** This completes the version 1 scope.

---

## Setup

You need Python 3.9 or newer.

### Fastest way (no git needed)

1. Download the tool as a ZIP: https://github.com/N3bula04/osint-pivot-tool/archive/refs/heads/claude/stoic-hawking-n2hlmg.zip
2. Unzip it. You get a folder called `osint-pivot-tool-claude-stoic-hawking-n2hlmg`. Rename it to `osint-pivot-tool` if you like.
3. **Windows:** double-click `setup.bat`. **Mac:** open Terminal, type `bash ` (with a space), drag `setup.sh` into the window, press Enter.
4. Wait for `49/49 checks passed`.
5. Run a report from a terminal opened in that folder:
   - Windows: `.\run.bat example.com`
   - Mac: `bash run.sh example.com`

The `run` script uses the private environment automatically, so you never need to activate anything.

### Manual way (git)

### macOS

```bash
# 1. Get the code
git clone https://github.com/n3bula04/osint-pivot-tool.git
cd osint-pivot-tool

# 2. Create an isolated Python environment (keeps this tool's packages separate)
python3 -m venv .venv
source .venv/bin/activate

# 3. Install the one dependency
pip install -r requirements.txt
```

### Windows (PowerShell)

```powershell
git clone https://github.com/n3bula04/osint-pivot-tool.git
cd osint-pivot-tool
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

If PowerShell refuses to run the activate script, run
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, then try again.

Each time you open a new terminal, re-run the `activate` line before using the tool.

---

## Usage

```bash
python pivot.py example.com
```

Output goes to `reports/`:

```
reports/example.com_20260917T163627Z_report.md
reports/example.com_20260917T163627Z_links.csv
```

Useful options:

| Option | What it does |
|---|---|
| `--refresh` | Ignore the cache and re-query every source. |
| `--no-cache` | Do not read or write the cache at all. |
| `--resolver 1.1.1.1` | Send DNS queries to a specific recursive resolver instead of the system default. |
| `--timeout 10` | Per-query timeout in seconds (default 5). |
| `--no-ptr` | Skip reverse-DNS lookups on discovered IPs. |
| `--skip-ct` | Skip certificate transparency entirely (DNS-only run). |
| `--ct-file FILE.json` | Read crt.sh results from a JSON file you saved, instead of the network. |
| `--ct-timeout 90` | crt.sh request timeout in seconds (default 60; crt.sh is often slow). |
| `--max-resolve 50` | How many discovered names to resolve for the IP pivot (default 30; 0 disables). |
| `--skip-rdap` | Skip RDAP registration lookups. |
| `--rdap-dir DIR` | Read RDAP JSON from saved files instead of the network (see below). |
| `--rdap-timeout 45` | RDAP request timeout in seconds (default 30). |
| `-o DIR` | Write reports somewhere other than `reports/`. |

Run `python pivot.py --help` for the full list.

### Cache

Raw responses are stored under `cache/` as small JSON files, one per query,
and reused for 24 hours. Timeouts and errors are never cached, so a transient
failure does not poison later runs. Delete the `cache/` folder, or use
`--refresh`, to start clean.

---

## What Stage 1 collects

All queries go through your recursive DNS resolver (your ISP's, or the one
you pass with `--resolver`). The tool never connects to the target domain,
never scans ports, never logs in anywhere.

| Query | Link type produced | What it tells you |
|---|---|---|
| `A`, `AAAA` on the seed | `dns_a`, `dns_aaaa` | Where the domain is hosted. |
| `MX` on the seed | `dns_mx` | Who handles its inbound mail. |
| `NS` on the seed | `dns_ns` | Who serves its DNS. |
| `TXT` on the seed (SPF) | `spf_include`, `spf_redirect` | Which third parties may send mail as the domain. |
| `TXT` on `_dmarc.<seed>` | `dmarc_report_recipient` | Where DMARC reports go (often a parent company, MSSP or vendor). |
| `PTR` on each IP found | `dns_ptr` | What hostname the IP's owner has assigned to it. |

## What Stage 2 adds: certificate transparency and the IP pivot

Certificate transparency (CT) logs are public records of every TLS certificate
a browser-trusted CA issues. The tool asks **crt.sh**, a free search front-end
for those logs, two questions: certificates naming the seed itself, and
certificates naming anything under it (`%.seed`). It pauses two seconds
between the requests, retries on crt.sh's frequent 502/503 errors with
backoff, and caches the raw JSON.

| Link type | What it means |
|---|---|
| `ct_subdomain` | A certificate was issued for a name under the seed. This is the main way to enumerate subdomains passively. |
| `ct_shared_certificate` | Another domain appears on the same certificate as a seed-owned name. Whoever requested the certificate controlled both names at the time. |
| `shared_ip` | A discovered domain resolves to the same IP as the seed right now. |

For the IP pivot, the tool resolves up to `--max-resolve` discovered names
(subdomains and non-bulk shared-certificate domains) and links any that land
on one of the seed's IPs. These are ordinary DNS lookups through your
resolver; nothing touches the target.

Renewals produce many near-identical certificates, so the tool collapses
them: one link per pair of names, citing the most recent certificate and
the count of certificates that carry the pairing. Every certificate link
includes a `https://crt.sh/?id=...` URL you can open to verify it.

### Working from a saved crt.sh file

crt.sh is slow and sometimes down. For a demo, or when it fails, download
the JSON once in a browser and feed it to the tool:

1. Open `https://crt.sh/?q=%25.example.com&output=json` (the `%25` is a URL-encoded `%`). Save the page as `example.com.crtsh.json`.
2. Run `python pivot.py example.com --ct-file example.com.crtsh.json`.

`examples/crtsh_sample_ietf.json` is a small **synthetic** file in the same
format, used by the self-check. The certificate IDs in it are made up; do
not cite them.

## What Stage 3 adds: registration data via RDAP

RDAP (Registration Data Access Protocol) is the structured successor to
WHOIS, served by registries and the five regional internet registries. The
tool asks `rdap.org`, a public redirector that forwards each query to the
right authoritative server, for the seed domain and for the netblock behind
each of the seed's IPs (at most 8). If rdap.org is down, it falls back to
IANA's bootstrap files and queries the authoritative server directly. It
pauses one second between requests and caches every answer for 24 hours.

| Link type | What it means |
|---|---|
| `rdap_registrar` | Which registrar sponsors the domain. Always Low on its own; useful only in combination. |
| `rdap_nameserver` | The registry's view of the delegation. Rated like DNS NS. The report notes if it disagrees with what DNS answers. |
| `rdap_registrant_org`, `rdap_registrant_email`, `rdap_technical_email`, ... | Unredacted contact details. An email at a different domain is a classic pivot (High); privacy-proxy addresses are Low. |
| `rdap_netblock` | The IP's netblock and its holder. Hosting/cloud holders are Low and trigger a downgrade of the domain-to-IP link. A holder matching the seed's registrant is High. |

The "Registration data (RDAP)" section of the report also shows registration,
last-changed and expiry dates, domain age (with a warning under 90 days),
status codes, DNSSEC, and the registry's nameservers.

### Working from saved RDAP files

Use `--rdap-dir DIR` to run without the network. The tool looks for
`DIR/domain_<seed>.json` and `DIR/ip_<ip>.json`, with colons in IPv6
addresses replaced by hyphens (Windows cannot write colons in filenames).
Save them in a browser from `https://rdap.org/domain/example.com` and
`https://rdap.org/ip/93.184.216.34`. `examples/rdap_sample/` holds
**synthetic** files in this format for the self-check; the registrar and
contacts in them are made up.

## How confidence is rated

Confidence answers one question: *how strongly does this single observation
support an infrastructure relationship between the two entities, for
pivoting purposes?* The rules live in `rating.py` and are deliberately plain
so you can explain each one.

| Rating | Meaning |
|---|---|
| **High** | The observation ties the entities together and is unlikely to be explained by a shared third-party service. Example: an MX or NS host under the seed's own domain. |
| **Medium** | A relationship is plausible but a shared provider or coincidence has not been ruled out. Example: an SPF include for a vendor not on the known-provider list. |
| **Low** | The observation is real, but the related entity is shared by many unrelated organisations. Pivoting on it will mostly return noise. Example: a Cloudflare IP, Google mail servers, Route 53 nameservers. |

Downgrade rules currently applied:

- IP inside a published **Cloudflare or Fastly** range: Low, flag `shared_cdn`.
- Nameserver at a known **managed DNS provider**: Low, flag `shared_dns_provider`.
- MX / SPF / DMARC pointing at a known **mail or reporting provider**: Low, flag `shared_mail_provider`.
- Reverse DNS that is **auto-generated by a hosting provider** (AWS, GCP, OVH, Hetzner...): Low, flag `generic_hosting_rdns`.
- A domain-to-IP link whose IP has generic hosting reverse DNS drops from High to Medium, flag `cloud_hosted_ip`.
- A certificate with **more than 50 names**, or issued by a CDN, or carrying a CDN placeholder name such as `sni.cloudflaressl.com`: Low, flag `shared_bulk_certificate`. Related domains from such certificates are collapsed to one link per registrable domain and are not resolved in the IP pivot.
- A certificate with **21 to 50 names**: Medium, flag `large_san_list`.
- An **expired** certificate keeps its rating but is flagged `expired_certificate`, and the reason notes the relationship may be historical.
- A `shared_ip` link inherits the seed IP's rating: shared CDN IP is Low, cloud-hosted IP is Medium, otherwise High.
- RDAP shows the seed IP's netblock holder is a **hosting or cloud provider** (matched against a keyword list): the netblock link is Low with flag `bulk_hosting_netblock`, and the domain-to-IP link drops from High to Medium with flag `cloud_hosted_ip`.
- RDAP contact email or organisation naming a **privacy/proxy service**: Low, flag `privacy_proxy`.
- Registrar links are always Low, flag `shared_registrar`.

The provider lists in `rating.py` are starting points, not gospel. If you see
a provider that should be there, add one line.

---

## Manual validation checks for Stage 1

Do these by hand after a run to show human quality control over the tool.

1. **Cross-check the raw records against a second resolver.**
   Run `dig example.com A +short`, `dig example.com MX +short`, `dig example.com NS +short`
   (macOS) or `nslookup -type=MX example.com` (Windows), or use an
   independent web tool such as Google's `https://dns.google/query?name=example.com&type=MX`.
   The "Raw DNS records observed" table in the report should match. Differences
   usually mean a change in progress (TTL) or a resolver that filters answers.

2. **Verify one shared-infrastructure flag.**
   Pick an IP flagged `shared_cdn` and confirm it sits inside a range on
   `https://www.cloudflare.com/ips/` (or Fastly's list). Pick a nameserver
   flagged `shared_dns_provider` and confirm the provider domain matches.
   If a flag is wrong, the fix is one line in `rating.py`.

3. **Verify one High-confidence link the hard way.**
   Take a `dns_mx` or `dns_ns` link rated High and confirm the host really is
   under the seed's own domain, then resolve that host yourself
   (`dig mx.example.com A +short`). Also confirm the collection log lists every
   query you expect (A, AAAA, MX, NS, TXT, `_dmarc` TXT, one PTR per IP) and that
   every failed or empty query is marked, not silently dropped.

## Manual validation checks for Stage 2

1. **Compare subdomains against crt.sh in a browser.** Open
   `https://crt.sh/?q=%25.example.com`, sort by "Logged At", and check that
   the names in the report's `ct_subdomain` links appear there. Every
   certificate link carries an `https://crt.sh/?id=...` URL; open one and
   confirm the SAN list matches the evidence text.

2. **Verify one shared-certificate link the hard way.** Take a High-rated
   `ct_shared_certificate` link, open its crt.sh id, and confirm both names
   are on the certificate. Then check the issuer: a public CA with a short
   SAN list means someone proved control of both names. If the issuer is a
   CDN or the SAN list is long, the tool should have rated it Low or Medium.
   If it did not, that is a bug in `rating.py`.

3. **Verify one shared-IP link with a second resolver.** Take a `shared_ip`
   link and resolve both names yourself (`dig name A +short` on Mac,
   `nslookup name` on Windows). Both should return the IP in the evidence.
   Then look the IP up on `https://www.cloudflare.com/ips/` or a WHOIS site:
   if it belongs to a CDN or a cloud provider, the link should be Low or
   Medium, not High.

## Manual validation checks for Stage 3

1. **Compare the registration section with ICANN's lookup.** Open
   `https://lookup.icann.org/lookup?name=example.com` and check registrar,
   creation date, expiry date, status codes and nameservers against the
   report's "Registration data (RDAP)" section. Both read the same RDAP
   data, so they should agree exactly.

2. **Verify one netblock link with the RIR directly.** Take an
   `rdap_netblock` link and open `https://rdap.org/ip/<ip>` in a browser, or
   the RIR's own WHOIS page (ARIN, RIPE, APNIC, LACNIC, AFRINIC). Confirm the
   CIDR and holder name match the evidence. Then judge the rating: a cloud or
   hosting holder should be Low, a holder that is clearly the seed's own
   organisation should be High.

3. **Check the cross-source consistency notes.** If the report flags a
   nameserver mismatch between DNS and the registry, confirm it with
   `dig example.com NS +short` against the registry's list. If the domain is
   flagged as registered within 90 days, confirm the creation date in the
   ICANN lookup. If neither note appears, confirm by hand that DNS and
   registry nameservers really do match, so you know the check ran.

---

## Safety and terms of use

- Passive only. DNS lookups go through a recursive resolver; the tool never
  contacts the target's own servers, never scans, never logs in.
- crt.sh is a free public service run by Sectigo. The tool makes two requests
  per seed, pauses between them, backs off on errors, identifies itself with a
  User-Agent, and caches results for 24 hours so re-runs cost crt.sh nothing.
- RDAP servers are run by registries and RIRs with strict rate limits. The
  tool makes one domain query plus one per seed IP (at most 8), pauses
  between them, honours 429 responses by stopping rather than hammering, and
  caches for 24 hours.
- The tool produces leads. The analyst decides what they mean.

## Roadmap

- **Stage 1 (done):** DNS collection, one-hop reverse-DNS pivot, rating, Markdown + CSV output, cache.
- **Stage 2 (done):** Certificate transparency via crt.sh; subdomain enumeration, shared-certificate pivot, shared-IP pivot.
- **Stage 3 (this version):** RDAP registration data for the domain and each seed IP; netblock ownership sharpens the bulk-hosting downgrade.
- **Ideas for version 2:** RDAP on the High-rated related domains to compare registrars and creation dates; a full Public Suffix List; passive DNS if you have an API key.

## Files

| File | Purpose |
|---|---|
| `pivot.py` | Command-line entry point and orchestration. |
| `collectors.py` | Passive data collectors and the on-disk cache: DNS, crt.sh, IP pivot, RDAP. |
| `rating.py` | Analytical rules: confidence ratings and shared-infrastructure lists. |
| `report.py` | Markdown and CSV writers. |
| `models.py` | Small data classes shared by the modules above. |
| `test_rating.py` | Offline self-check of rating rules, CT parsing, the IP pivot and RDAP parsing (`python test_rating.py`). |
| `examples/crtsh_sample_ietf.json` | Synthetic crt.sh output used by the self-check and for offline demos. |
| `examples/rdap_sample/` | Synthetic RDAP responses in the `--rdap-dir` layout. |
