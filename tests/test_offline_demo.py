"""End-to-end tests for the offline demo. Run: python -m pytest -q"""

import csv
import filecmp
import pathlib
import socket
import subprocess
import sys

import pytest
import requests

import collectors
import offline
import pivot
import rating

ROOT = pathlib.Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"
STEM = "example-demo.test_20260930T000000Z"


def run_demo(tmp_path, *extra):
    out = tmp_path / "out"
    rc = pivot.main(["--demo", "-o", str(out), *extra])
    assert rc == 0
    return out / f"{STEM}_report.md", out / f"{STEM}_links.csv"


def rows(csv_path):
    with csv_path.open(encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def find(rs, link_type, related, source=None):
    hits = [r for r in rs if r["link_type"] == link_type and r["related_entity"] == related
            and (source is None or r["source_entity"] == source)]
    assert hits, f"no {link_type} link to {related}"
    return hits[0]


# --- end to end -------------------------------------------------------------------

def test_demo_matches_committed_sample(tmp_path):
    md, csv_path = run_demo(tmp_path)
    for produced in (md, csv_path):
        committed = SAMPLES / produced.name
        assert committed.exists(), f"missing committed sample {committed.name}; regenerate with: python pivot.py --demo -o samples"
        assert filecmp.cmp(produced, committed, shallow=False), (
            f"{produced.name} differs from samples/; regenerate with: python pivot.py --demo -o samples")


def test_demo_is_deterministic(tmp_path):
    a = run_demo(tmp_path / "a")
    b = run_demo(tmp_path / "b")
    for x, y in zip(a, b):
        assert x.read_bytes() == y.read_bytes()


def test_demo_exercises_interesting_cases(tmp_path):
    _, csv_path = run_demo(tmp_path)
    rs = rows(csv_path)
    cdn = find(rs, "dns_a", "203.0.113.140", "example-demo.test")
    assert cdn["confidence"] == "Low" and "shared_cdn" in cdn["flags"]
    cloud = find(rs, "dns_aaaa", "2001:db8:c10d::5")
    assert cloud["confidence"] == "Medium" and "cloud_hosted_ip" in cloud["flags"]
    assert find(rs, "rdap_netblock", "2001:db8:c10d::/48")["confidence"] == "Low"
    assert find(rs, "ct_shared_certificate", "partner-demo.test")["confidence"] == "High"
    expired = find(rs, "ct_shared_certificate", "legacy-partner.test")
    assert expired["confidence"] == "Medium" and "expired_certificate" in expired["flags"]
    origin = find(rs, "dns_a", "198.51.100.50", "api.example-demo.test")
    assert origin["confidence"] == "Medium" and "possible_origin_ip" in origin["flags"]
    shared = find(rs, "shared_ip", "partner-demo.test")
    assert shared["confidence"] == "High"
    # PSL: two co.uk names stay separate owners (not collapsed into "co.uk")
    assert find(rs, "ct_shared_certificate", "portal.fictional-partner.co.uk")
    assert find(rs, "ct_shared_certificate", "www.fictional-supplier.co.uk")
    assert rating.registrable_domain("portal.fictional-partner.co.uk") == "fictional-partner.co.uk"
    # Spoofed provider hosts are not treated as the real provider
    assert find(rs, "dns_mx", "aspmx.l.google.com.mail-spoof.test")["confidence"] == "Medium"
    assert find(rs, "spf_include", "_spf.salesforce.com.attacker.invalid")["confidence"] == "Medium"
    # CSV-injection-looking value is neutralised
    org = find(rs, "rdap_technical_org", "'=HYPERLINK(\"http://attacker.invalid/\",\"click me\")")
    assert org["related_entity"].startswith("'=")
    for r in rs:
        for v in r.values():
            assert not v.startswith(("=", "+", "-", "@")), v


def test_report_is_labelled_synthetic(tmp_path):
    md, _ = run_demo(tmp_path)
    text = md.read_text(encoding="utf-8")
    assert "SYNTHETIC DEMO" in text
    assert "no network connections at all" in text
    assert "## Links (sorted by confidence)" in text
    assert "## Collection log" in text


def test_demo_uses_only_reserved_ips(tmp_path):
    import ipaddress
    doc = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
    _, csv_path = run_demo(tmp_path)
    for r in rows(csv_path):
        for field in ("source_entity", "related_entity"):
            try:
                ip = ipaddress.ip_address(r[field])
            except ValueError:
                continue
            assert any(ip in n for n in doc), f"{ip} is not in a documentation range"


# --- no network -------------------------------------------------------------------

def test_offline_mode_makes_no_network_calls(tmp_path, monkeypatch):
    attempts = []

    def tripwire(*a, **kw):
        attempts.append(a)
        raise AssertionError("network call attempted")

    # Tripwires underneath the offline guard: if the guard were missing, these would fire.
    monkeypatch.setattr(socket, "create_connection", tripwire)
    monkeypatch.setattr(socket, "getaddrinfo", tripwire)
    monkeypatch.setattr(requests.Session, "request", tripwire)
    run_demo(tmp_path)
    assert attempts == []


def test_network_guard_blocks_requests_socket_and_dns(tmp_path):
    with offline.offline_session(offline.DEMO_DIR):
        with pytest.raises(offline.NetworkBlockedError):
            requests.get("https://example.com/", timeout=1)
        with pytest.raises(offline.NetworkBlockedError):
            socket.create_connection(("192.0.2.1", 443), timeout=1)
        with pytest.raises(offline.NetworkBlockedError):
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        with pytest.raises(offline.NetworkBlockedError):
            collectors.crtsh_fetch(collectors.Cache(tmp_path, enabled=False), "example.com")
    # Everything is restored afterwards.
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.close()
    assert rating.shared_cdn_provider("203.0.113.140") is None


def test_fixture_resolver_statuses():
    r = offline.FixtureResolver({"a.test:A": {"status": "ok", "answers": ["192.0.2.1"]},
                                 "a.test:AAAA": {"status": "empty", "answers": []},
                                 "192.0.2.1:PTR": {"status": "ok", "answers": ["a.test."]}})
    assert [x.to_text() for x in r.resolve("a.test", "A")] == ["192.0.2.1"]
    import dns.resolver
    import dns.reversename
    with pytest.raises(dns.resolver.NoAnswer):
        r.resolve("a.test", "AAAA")
    with pytest.raises(dns.resolver.NoAnswer):
        r.resolve("a.test", "MX")
    with pytest.raises(dns.resolver.NXDOMAIN):
        r.resolve("missing.test", "A")
    rev = str(dns.reversename.from_address("192.0.2.1"))
    assert [x.to_text() for x in r.resolve(rev, "PTR")] == ["a.test."]


# --- CLI helpers --------------------------------------------------------------------

@pytest.mark.parametrize("raw, want", [
    ("example.com", "example.com"),
    ("EXAMPLE.com.", "example.com"),
    ("https://www.example.com/path?q=1", "example.com"),
    ("http://sub.example.co.uk", "sub.example.co.uk"),
    ("example-demo.test", "example-demo.test"),
])
def test_normalise_domain_ok(raw, want):
    assert pivot.normalise_domain(raw) == want


@pytest.mark.parametrize("raw", ["", "localhost", "-bad.com", "exa mple.com", "a..b.com", "x" * 64 + ".com"])
def test_normalise_domain_rejects(raw):
    with pytest.raises(ValueError):
        pivot.normalise_domain(raw)


def test_missing_domain_is_an_error(capsys):
    assert pivot.main([]) == 2


def test_bad_fixed_time_is_an_error(tmp_path):
    assert pivot.main(["--demo", "--fixed-time", "not-a-time", "-o", str(tmp_path)]) == 2


def test_self_check_script_still_passes():
    proc = subprocess.run([sys.executable, str(ROOT / "test_rating.py")], cwd=ROOT,
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout[-2000:]
