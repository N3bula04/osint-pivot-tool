"""Quick self-check of the analytical rules. Run: python test_rating.py

No network needed. If a rule changes, update the expectation here so the
rating logic stays honest and explainable.
"""

import json
import pathlib
import tempfile

from collectors import Cache, collect_ct, collect_shared_ips, parse_ct_entries
from models import Link, RunResult
from rating import rate, rate_all, registrable_domain, shared_cdn_provider

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
results.append(check("CT small shared cert -> High", by[("ct_shared_certificate", "rfc-editor.org")].confidence, "High"))
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
results.append(check("shared dedicated IP -> High", shared["other.example"].confidence, "High"))
results.append(check("shared CDN IP -> Low", shared["cdn-twin.example"].confidence, "Low"))
results.append(check("shared-IP evidence cites both names", "other.example" in shared["other.example"].evidence and "93.184.216.34" in shared["other.example"].evidence, True))

print(f"\n{sum(results)}/{len(results)} checks passed")
raise SystemExit(0 if all(results) else 1)
