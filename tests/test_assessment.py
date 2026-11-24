import re

from models import Link, LogEntry, RunResult
from report import build_assessment, write_markdown


SEED = "seed.test"
NOW = "2026-09-30T00:00:00+00:00"


def link(kind, entity, confidence="High", flags=(), source=SEED):
    return Link(source, entity, kind, "Recorded observation", "Fixture", NOW,
                confidence, "The records show an infrastructure overlap. Verify it.", list(flags))


def entry(query, status, detail=""):
    return LogEntry("DNS", query, status, detail, NOW)


def test_priority_ranking_and_deduplication():
    result = RunResult(SEED, NOW, links=[
        link("dns_a", "203.0.113.19", "Low", ["shared_cdn"]),
        link("ct_subdomain", "www.seed.test"),
        link("shared_ip", "Partner.test."),
        link("ct_shared_certificate", "partner.test"),
        link("dns_a", "192.0.2.40", flags=["cloud_hosted_ip"]),
        link("dns_a", "192.0.2.20", "Medium", ["possible_origin_ip"], "api.seed.test"),
        link("rdap_netblock", "198.51.100.0/25", flags=["dedicated_netblock"]),
        link("dns_cname", SEED),
    ])
    lines = build_assessment(result)
    leads = [line for line in lines if re.match(r"\d+\. ", line)]
    assert len(leads) == 3
    assert "`partner.test`" in leads[0] and "`ct_shared_certificate`" in leads[0]
    assert "`shared_ip`" in leads[0]
    assert "`198.51.100.0/25`" in leads[1]
    assert "`192.0.2.40`" in leads[2]
    alternative = next(line for line in lines if "Alternative explanation" in line)
    assert "partner.test" in alternative
    assert re.search(r"\b(actor|attacker|apt)\b", alternative, re.IGNORECASE) is None

    result.links = [item for item in result.links if "cloud_hosted_ip" not in item.flags]
    assert any(line.startswith("3. `192.0.2.20`") for line in build_assessment(result))


def test_gap_prefers_failure_then_relevance():
    result = RunResult(SEED, NOW, links=[
        link("dns_a", "192.0.2.20", "Medium", ["possible_origin_ip"], "api.seed.test"),
    ], log=[
        entry("192.0.2.20 PTR", "nxdomain"),
        entry("api.seed.test AAAA", "empty"),
        entry("other.test A", "error"),
        entry("api.seed.test A", "timeout", "resolver timed out"),
    ])
    gap = build_assessment(result)[-1]
    assert "`api.seed.test A`" in gap and "`timeout`" in gap
    assert "resolver timed out" in gap
    assert "2 failed and 2 no-data queries" in gap

    result.log = result.log[:3]
    assert "`other.test A`" in build_assessment(result)[-1]
    result.log = result.log[:2]
    assert "`192.0.2.20 PTR`" in build_assessment(result)[-1]


def test_no_priority_leads_or_source_gaps():
    result = RunResult(SEED, NOW, links=[
        link("dns_a", "203.0.113.19", "Low", ["shared_cdn"]),
    ], log=[entry("seed.test A", "ok")])
    lines = build_assessment(result)
    assert "No priority leads" in "\n".join(lines)
    assert "No source gaps were logged" in lines[-1]
    assert any("multiple tenants" in line for line in lines)


def test_assessment_and_markdown_are_deterministic(tmp_path):
    result = RunResult(SEED, NOW, links=[
        link("shared_ip", "partner.test", source="b.seed.test"),
        link("shared_ip", "partner.test", source="a.seed.test"),
    ], log=[entry("partner.test A", "empty")])
    result.links[1].reason = "Both names resolve to the same IP"
    assessment = build_assessment(result)
    assert any("Both names resolve to the same IP." in line for line in assessment)
    result.links.reverse()
    assert build_assessment(result) == assessment

    first, second = tmp_path / "first.md", tmp_path / "second.md"
    for path in (first, second):
        write_markdown(result, path, "links.csv")
    assert first.read_bytes() == second.read_bytes()
