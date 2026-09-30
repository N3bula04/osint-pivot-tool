"""Quick self-check of the analytical rules. Run: python test_rating.py

No network needed. If a rule changes, update the expectation here so the
rating logic stays honest and explainable.
"""

import json
import pathlib
import tempfile

from collectors import Cache, collect_ct, collect_rdap, collect_shared_ips, parse_ct_entries
from models import Link, RunResult
from rating import rate, rate_all, registrable_domain, same_owner, shared_cdn_provider

SEED = "example.co.uk"


def mk(link_type, related, source=SEED):
    return Link(source, related, link_type, "test evidence", "test", "2026-01-01T00:00:00+00:00")


def check(name, got, want):
    status = "PASS" if got == want else "FAIL"
    print(f"[{status}] {name}: got {got!r}, want {want!r}")
    return got == want


results = []

# registrable domain handles two-level suffixes
results.append(check("registrable co.uk", registrable_domain("mail.example.co.uk"), "example.co.uk"))
results.append(check("registrable com", registrable_domain("a.b.example.com"), "example.com"))

# CDN ranges
results.append(check("cloudflare v4", shared_cdn_provider("104.16.44.99"), "Cloudflare"))
results.append(check("cloudflare v6", shared_cdn_provider("2606:4700::6810:2c63"), "Cloudflare"))
results.append(check("non-cdn", shared_cdn_provider("93.184.216.34"), None))

# A record ratings
results.append(check("A on CDN -> Low", rate(mk("dns_a", "104.16.44.99"), SEED).confidence, "Low"))
results.append(check("A dedicated -> High", rate(mk("dns_a", "93.184.216.34"), SEED).confidence, "High"))

# MX ratings
results.append(check("MX own domain -> High", rate(mk("dns_mx", "mx.example.co.uk"), SEED).confidence, "High"))
results.append(check("MX google -> Low", rate(mk("dns_mx", "aspmx.l.google.com"), SEED).confidence, "Low"))
results.append(check("MX unknown 3rd party -> Medium", rate(mk("dns_mx", "mail.smallhost.net"), SEED).confidence, "Medium"))

# NS ratings
results.append(check("NS route53 -> Low", rate(mk("dns_ns", "ns-1.awsdns-00.com"), SEED).confidence, "Low"))
results.append(check("NS own -> High", rate(mk("dns_ns", "ns1.example.co.uk"), SEED).confidence, "High"))

# PTR ratings
results.append(check("PTR ec2 -> Low", rate(mk("dns_ptr", "ec2-1-2-3-4.compute.amazonaws.com", "1.2.3.4"), SEED).confidence, "Low"))
results.append(check("PTR own -> High", rate(mk("dns_ptr", "web1.example.co.uk", "1.2.3.4"), SEED).confidence, "High"))
results.append(check("PTR other org -> Medium", rate(mk("dns_ptr", "srv.otherorg.org", "1.2.3.4"), SEED).confidence, "Medium"))

# Cross-link rule: cloud-hosted IP downgrades the A link to Medium
links = [mk("dns_a", "35.190.14.201"), mk("dns_ptr", "201.14.190.35.bc.googleusercontent.com", "35.190.14.201")]
rate_all(links, SEED)
results.append(check("A on cloud IP -> Medium", links[0].confidence, "Medium"))
results.append(check("A on cloud IP flagged", "cloud_hosted_ip" in links[0].flags, True))

# ---- Stage 2: certificate transparency parsing and rating (offline, from the sample file) ----
sample = pathlib.Path(__file__).parent / "examples" / "crtsh_sample_ietf.json"
entries = json.loads(sample.read_text())
certs = parse_ct_entries(entries, "ietf.org")
results.append(check("CT dedupes repeated cert ids", len(certs), 6))
results.append(check("CT strips wildcard and merges CN", "ietf.org" in certs[1000001]["names"] and "www.ietf.org" in certs[1000001]["names"], True))
results.append(check("CT issuer shortened", certs[1000001]["issuer"], "R11"))

rr = RunResult(seed="ietf.org", started="2026-01-01T00:00:00+00:00")
subs, related = collect_ct(rr, Cache(pathlib.Path(tempfile.mkdtemp()), enabled=False), ct_file=sample)
rate_all(rr.links, "ietf.org")
by = {(l.link_type, l.related_entity): l for l in rr.links}
results.append(check("CT subdomains found", subs, {"www.ietf.org", "datatracker.ietf.org", "mailarchive.ietf.org"}))
results.append(check("CT subdomain -> High", by[("ct_subdomain", "www.ietf.org")].confidence, "High"))
results.append(check("CT small but expired shared cert -> Medium", by[("ct_shared_certificate", "rfc-editor.org")].confidence, "Medium"))
results.append(check("CT expired cert flagged", "expired_certificate" in by[("ct_shared_certificate", "rfc-editor.org")].flags, True))
results.append(check("CT bulk CDN cert -> Low", by[("ct_shared_certificate", "example-shop-1.com")].confidence, "Low"))
results.append(check("CT CDN placeholder excluded", ("ct_shared_certificate", "cloudflaressl.com") in by, False))
results.append(check("CT bulk-cert domains not queued for resolve", "example-shop-1.com" in related, False))
results.append(check("CT unrelated cert ignored", ("ct_subdomain", "unrelated.example") in by, False))

# ---- Stage 2: shared-IP pivot, driven from pre-seeded cache entries (no network) ----
tmp = pathlib.Path(tempfile.mkdtemp())
cache = Cache(tmp, enabled=True)
cache.put("dns", "other.example:A", {"status": "ok", "answers": ["93.184.216.34"]})
cache.put("dns", "other.example:AAAA", {"status": "empty", "answers": []})
cache.put("dns", "cdn-twin.example:A", {"status": "ok", "answers": ["104.16.44.99"]})
cache.put("dns", "cdn-twin.example:AAAA", {"status": "empty", "answers": []})
rr = RunResult(seed="example.co.uk", started="2026-01-01T00:00:00+00:00")
rr.links.append(mk("dns_a", "93.184.216.34"))
rr.links.append(mk("dns_a", "104.16.44.99"))
collect_shared_ips(rr, cache, ["other.example", "cdn-twin.example"], None, 2.0, 30)
rate_all(rr.links, SEED)
shared = {l.related_entity: l for l in rr.links if l.link_type == "shared_ip"}
results.append(check("shared IP link created", set(shared), {"other.example", "cdn-twin.example"}))
results.append(check("shared IP without PTR/RDAP confirmation -> Medium", shared["other.example"].confidence, "Medium"))
results.append(check("shared IP stored in meta, not parsed from evidence", shared["other.example"].meta.get("ip"), "93.184.216.34"))
results.append(check("shared CDN IP -> Low", shared["cdn-twin.example"].confidence, "Low"))
results.append(check("shared-IP evidence cites both names", "other.example" in shared["other.example"].evidence and "93.184.216.34" in shared["other.example"].evidence, True))

# ---- Stage 3: RDAP parsing, rating and the bulk-hosting downgrade (offline, from sample files) ----
rdap_dir = pathlib.Path(__file__).parent / "examples" / "rdap_sample"
rr = RunResult(seed="ietf.org", started="2026-01-01T00:00:00+00:00")
rr.links.append(Link("ietf.org", "104.16.44.99", "dns_a", "ev", "DNS", "t"))
rr.links.append(Link("ietf.org", "35.190.14.201", "dns_a", "ev", "DNS", "t"))
rr.links.append(Link("ietf.org", "192.0.2.10", "dns_a", "ev", "DNS", "t"))
rr.links.append(Link("ietf.org", "jill.ns.cloudflare.com", "dns_ns", "ev", "DNS", "t"))
collect_rdap(rr, Cache(pathlib.Path(tempfile.mkdtemp()), enabled=False), rdap_dir=rdap_dir)
rate_all(rr.links, "ietf.org")
by = {(l.link_type, l.related_entity): l for l in rr.links}
a_by_ip = {l.related_entity: l for l in rr.links if l.link_type == "dns_a"}
section = "\n".join(rr.sections.get("Registration data (RDAP)", []))
results.append(check("RDAP registrar parsed", by[("rdap_registrar", "Sample Registrar LLC")].confidence, "Low"))
results.append(check("RDAP registration date in section", "1995-03-11" in section, True))
results.append(check("RDAP registrant org -> Medium", by[("rdap_registrant_org", "IETF Administration LLC")].confidence, "Medium"))
results.append(check("RDAP unredacted tech email at other domain -> Medium", by[("rdap_technical_email", "hostmaster@sample-msp.example")].confidence, "Medium"))
results.append(check("RDAP abuse mailbox not linked", any(k[1] == "abuse@sample-registrar.example" for k in by), False))
results.append(check("RDAP nameserver cloudflare -> Low", by[("rdap_nameserver", "jill.ns.cloudflare.com")].confidence, "Low"))
results.append(check("RDAP NS mismatch noted (DNS lacks ken)", "Nameserver mismatch" in section, True))
results.append(check("netblock Cloudflare -> Low", by[("rdap_netblock", "104.16.0.0/12")].confidence, "Low"))
results.append(check("netblock Google Cloud -> bulk", "bulk_hosting_netblock" in by[("rdap_netblock", "35.184.0.0/13")].flags, True))
results.append(check("netblock dedicated to seed org -> High", by[("rdap_netblock", "192.0.2.8/29")].confidence, "High"))
results.append(check("A on bulk-hosting IP downgraded to Medium", a_by_ip["35.190.14.201"].confidence, "Medium"))
results.append(check("A on dedicated IP stays High", a_by_ip["192.0.2.10"].confidence, "High"))
results.append(check("privacy-proxy email -> Low", rate(mk("rdap_registrant_email", "abc123@withheldforprivacy.com"), SEED).confidence, "Low"))

# ---- Origin-IP hint: a seed-owned host on a non-CDN IP the seed does not use ----
tmp = pathlib.Path(tempfile.mkdtemp())
cache = Cache(tmp, enabled=True)
cache.put("dns", "mail.example.co.uk:A", {"status": "ok", "answers": ["198.51.100.7"]})
cache.put("dns", "mail.example.co.uk:AAAA", {"status": "empty", "answers": []})
cache.put("dns", "7.100.51.198.in-addr.arpa:PTR", {"status": "ok", "answers": ["srv1.some-hoster.example."]})
rr = RunResult(seed="example.co.uk", started="2026-01-01T00:00:00+00:00")
rr.links.append(mk("dns_a", "104.16.44.99"))
collect_shared_ips(rr, cache, ["mail.example.co.uk"], None, 2.0, 30)
rate_all(rr.links, SEED)
mail_a = next(l for l in rr.links if l.source_entity == "mail.example.co.uk" and l.link_type == "dns_a")
results.append(check("origin candidate flagged", "possible_origin_ip" in mail_a.flags, True))
results.append(check("unconfirmed origin candidate -> Medium", mail_a.confidence, "Medium"))
results.append(check("origin IP gets PTR link", any(l.link_type == "dns_ptr" and l.source_entity == "198.51.100.7" for l in rr.links), True))
results.append(check("origin noted in IP pivot section", any("mail.example.co.uk -> 198.51.100.7" in x for x in rr.sections["IP pivot"]), True))

# ---- 0.3.1: origin IP confirmed by PTR under the seed's own domain -> High ----
tmp = pathlib.Path(tempfile.mkdtemp())
cache = Cache(tmp, enabled=True)
cache.put("dns", "mail.example.co.uk:A", {"status": "ok", "answers": ["198.51.100.8"]})
cache.put("dns", "mail.example.co.uk:AAAA", {"status": "empty", "answers": []})
cache.put("dns", "8.100.51.198.in-addr.arpa:PTR", {"status": "ok", "answers": ["origin1.example.co.uk."]})
rr = RunResult(seed="example.co.uk", started="2026-01-01T00:00:00+00:00")
rr.links.append(mk("dns_a", "104.16.44.99"))
collect_shared_ips(rr, cache, ["mail.example.co.uk"], None, 2.0, 30)
rate_all(rr.links, SEED)
mail_a = next(l for l in rr.links if l.source_entity == "mail.example.co.uk" and l.link_type == "dns_a")
results.append(check("origin confirmed by own-domain PTR -> High", mail_a.confidence, "High"))

# ---- 0.3.1: shared IP confirmed by PTR under the seed's own domain -> High ----
links = [mk("dns_a", "203.0.113.5"), mk("dns_ptr", "web.example.co.uk", "203.0.113.5"),
         Link(SEED, "twin.example", "shared_ip", "ev", "DNS", "t", meta={"ip": "203.0.113.5"})]
rate_all(links, SEED)
results.append(check("shared IP confirmed by own-domain PTR -> High", links[2].confidence, "High"))

# ---- 0.3.1: third-party host IPs from the IP pivot are not High ----
tp = Link("m.testexample.com", "13.248.169.48", "dns_a", "ev", "DNS", "t",
          meta={"seed_owned_host": False, "outside_seed_ips": True})
results.append(check("third-party host IP (unverified) -> Medium", rate(tp, "example.com").confidence, "Medium"))
tp2 = Link("m.testexample.com", "13.248.169.48", "dns_a", "ev", "DNS", "t",
           meta={"seed_owned_host": False, "outside_seed_ips": True})
nb = Link("13.248.169.48", "13.248.0.0/16", "rdap_netblock", "ev", "RDAP", "t",
          meta={"owner": "Amazon Technologies Inc.", "name": "AMAZON-2011L", "registrant_org": "", "related_ip": True})
rate_all([tp2, nb], "example.com")
results.append(check("third-party host IP in Amazon netblock -> not High", tp2.confidence != "High", True))
results.append(check("related-host Amazon netblock -> bulk", "bulk_hosting_netblock" in nb.flags, True))

# ---- 0.3.1: provider matching is a label-boundary suffix match, not a substring ----
results.append(check("MX spoof mx.google.com.evil.net not Google", rate(mk("dns_mx", "mx.google.com.evil.net"), SEED).confidence, "Medium"))
results.append(check("MX real google still Low", rate(mk("dns_mx", "alt1.aspmx.l.google.com"), SEED).confidence, "Low"))
results.append(check("NS ns1.myname.com not Name.com", rate(mk("dns_ns", "ns1.myname.com"), SEED).confidence, "Medium"))
results.append(check("NS ns1.name.com is Name.com", rate(mk("dns_ns", "ns1.name.com"), SEED).confidence, "Low"))
results.append(check("SPF spoof _spf.salesforce.com.attacker.io not Salesforce",
                     rate(mk("spf_include", "_spf.salesforce.com.attacker.io"), SEED).confidence, "Medium"))
results.append(check("SPF real _spf.salesforce.com is Low", rate(mk("spf_include", "_spf.salesforce.com"), SEED).confidence, "Low"))
results.append(check("NS route53 other TLD (awsdns-12.co.uk) -> Low", rate(mk("dns_ns", "ns-9.awsdns-12.co.uk"), SEED).confidence, "Low"))
results.append(check("NS awsdns spoof suffix not Route 53", rate(mk("dns_ns", "ns-1.awsdns-00.com.evil.net"), SEED).confidence, "Medium"))
results.append(check("PTR spoof amazonaws.com.evil.net not generic",
                     rate(mk("dns_ptr", "x.notamazonaws.com", "1.2.3.4"), SEED).confidence, "Medium"))

# ---- 0.3.1: Public Suffix List (bundled snapshot, no network) ----
results.append(check("PSL www.shop-a.co.uk", registrable_domain("www.shop-a.co.uk"), "shop-a.co.uk"))
results.append(check("PSL shop-a.co.uk vs ns.shop-b.co.uk not same owner", same_owner("shop-a.co.uk", "ns.shop-b.co.uk"), False))
results.append(check("PSL a.b.example.com.au", registrable_domain("a.b.example.com.au"), "example.com.au"))
results.append(check("PSL IP returned unchanged", registrable_domain("192.0.2.1"), "192.0.2.1"))
results.append(check("NS ns.shop-b.co.uk for seed shop-a.co.uk not High",
                     rate(Link("shop-a.co.uk", "ns.shop-b.co.uk", "dns_ns", "ev", "t", "t"), "shop-a.co.uk").confidence != "High", True))
import rating as _rating
_saved_psl = _rating._PSL
_rating._PSL = None  # simulate tldextract missing: offline fallback list
results.append(check("fallback www.shop-a.co.uk", registrable_domain("www.shop-a.co.uk"), "shop-a.co.uk"))
results.append(check("fallback mail.example.co.uk", registrable_domain("mail.example.co.uk"), "example.co.uk"))
_rating._PSL = _saved_psl

# ---- 0.3.1: netblock holder keywords are whole words; generic seed names do not match ----
def netblock(owner, name, seed, reg_org=""):
    l = Link("192.0.2.1", "192.0.2.0/24", "rdap_netblock", "ev", "RDAP", "t",
             meta={"owner": owner, "name": name, "registrant_org": reg_org})
    return rate(l, seed)
results.append(check("seed online.com vs 'Hetzner Online GmbH' not dedicated",
                     "dedicated_netblock" in netblock("Hetzner Online GmbH", "HETZNER-NET", "online.com").flags, False))
results.append(check("seed online.com vs Hetzner -> bulk Low", netblock("Hetzner Online GmbH", "HETZNER-NET", "online.com").confidence, "Low"))
results.append(check("seed data.com vs 'Amazon Data Services' not dedicated",
                     "dedicated_netblock" in netblock("Amazon Data Services Japan", "AMAZON-NRT", "data.com").flags, False))
results.append(check("'Colombia Movil' not bulk hosting (no 'colo' substring)",
                     netblock("COLOMBIA MOVIL", "CO-COMV-LACNIC", "somebank.com.co").confidence, "Medium"))
results.append(check("'Cloudbank Holdings' not bulk (bare 'cloud' dropped)",
                     netblock("Cloudbank Holdings", "CB-NET", "other.org").confidence, "Medium"))
results.append(check("seed ietf.org vs 'IETF-ADMIN-NET' dedicated",
                     netblock("", "IETF-ADMIN-NET", "ietf.org").confidence, "High"))
results.append(check("seed label must be a whole word (ietf vs 'ietfx networks')",
                     netblock("IETFX Networks", "X-NET", "ietf.org").confidence, "Medium"))
results.append(check("privacy registrant org ignored", netblock("Redacted For Privacy Hosting", "N", "zz.org", "REDACTED FOR PRIVACY").confidence != "High", True))

# ---- 0.3.1: report safety: CSV formula injection, Markdown escaping, error truncation ----
from report import _csv_safe, _md_escape, write_csv, write_markdown
from collectors import truncate
results.append(check("CSV '=' escaped", _csv_safe("=HYPERLINK(\"http://x\")"), "'=HYPERLINK(\"http://x\")"))
results.append(check("CSV '+' escaped", _csv_safe("+1"), "'+1"))
results.append(check("CSV '-' escaped", _csv_safe("-2+3"), "'-2+3"))
results.append(check("CSV '@' escaped", _csv_safe("@SUM(A1)"), "'@SUM(A1)"))
results.append(check("CSV normal cell untouched", _csv_safe("example.com"), "example.com"))
rr = RunResult(seed="example.com", started="2026-01-01T00:00:00+00:00")
rr.links.append(Link("example.com", "=cmd|'/c calc'!A1", "rdap_registrant_org", "@evil", "RDAP", "t"))
rate_all(rr.links, "example.com")
csv_path = pathlib.Path(tempfile.mkdtemp()) / "t.csv"
write_csv(rr, csv_path)
import csv as _csv
row = list(_csv.reader(csv_path.open(encoding="utf-8")))[1]
results.append(check("CSV file cells escaped", (row[1], row[3]), ("'=cmd|'/c calc'!A1", "'@evil")))
results.append(check("MD backtick escaped", _md_escape("a`b|c\nd"), "a'b\\|c d"))
results.append(check("error text truncated to 200", len(truncate("x" * 1000)), 200))
from models import LogEntry
rr.log.append(LogEntry("RDAP", "rdap ip 1.2.3.4", "error", "SSLError " * 100, "t"))
md_path = csv_path.with_suffix(".md")
write_markdown(rr, md_path, csv_path.name)
results.append(check("report log detail truncated", ("SSLError " * 100) not in md_path.read_text(encoding="utf-8"), True))

# ---- 0.3.1: RDAP 429 stops further RDAP requests for the run and records Retry-After ----
import collectors as _collectors
calls = []
class _Resp:
    status_code = 429
    headers = {"Retry-After": "120"}
    url = "https://rdap.org/domain/example.com"
_orig_get = _collectors.requests.get
_collectors.requests.get = lambda *a, **k: (calls.append(a[0]), _Resp())[1]
try:
    tmp = pathlib.Path(tempfile.mkdtemp())
    cache = Cache(tmp, enabled=True)
    rr = RunResult(seed="example.com", started="2026-01-01T00:00:00+00:00")
    rr.links += [Link("example.com", "192.0.2.1", "dns_a", "ev", "DNS", "t"),
                 Link("example.com", "192.0.2.2", "dns_a", "ev", "DNS", "t")]
    collect_rdap(rr, cache)
    results.append(check("429: only one HTTP request made", len(calls), 1))
    statuses = [e.status for e in rr.log if e.source == "RDAP"]
    results.append(check("429: later RDAP queries skipped", statuses, ["error", "skipped", "skipped"]))
    results.append(check("429: Retry-After window remembered", _collectors._rdap_backoff_until(cache) is not None, True))
    calls.clear()
    rr2 = RunResult(seed="example.com", started="2026-01-01T00:00:00+00:00")
    collect_rdap(rr2, cache)
    results.append(check("429: next run inside Retry-After makes no request", len(calls), 0))
finally:
    _collectors.requests.get = _orig_get
results.append(check("Retry-After seconds parsed", _collectors._parse_retry_after("30"), 30))
results.append(check("User-Agent carries 0.3.1", "osint-pivot-tool/0.3.1" in _collectors.USER_AGENT, True))

print(f"\n{sum(results)}/{len(results)} checks passed")
raise SystemExit(0 if all(results) else 1)
