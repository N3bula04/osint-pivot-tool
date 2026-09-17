"""Quick self-check of the analytical rules. Run: python test_rating.py

No network needed. If a rule changes, update the expectation here so the
rating logic stays honest and explainable.
"""

from models import Link
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

print(f"\n{sum(results)}/{len(results)} checks passed")
raise SystemExit(0 if all(results) else 1)
