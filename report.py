"""Report writers: Markdown for reading, CSV for pivoting in a spreadsheet."""

import csv
import pathlib
import re
import unicodedata
from collections import Counter, defaultdict
from typing import List

from collectors import truncate
from models import Link, LogEntry, RunResult
from rating import confidence_counts, registrable_label, same_owner

CSV_COLUMNS = [
    "source_entity", "related_entity", "link_type", "evidence", "data_source",
    "timestamp", "confidence", "confidence_reason", "flags",
]

_CONF_ORDER = {"High": 0, "Medium": 1, "Low": 2}


def _md_escape(text: str) -> str:
    """Make text safe inside a Markdown table cell or `code` span.

    Pipes would split the cell, newlines would end the row, and a backtick
    would close the code span early; backticks become a plain apostrophe.
    """
    return (
        str(text).replace("&", "&amp;").replace("<", "&lt;")
        .replace("|", "\\|").replace("\r", " ").replace("\n", " ").replace("`", "'")
    )


_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value) -> str:
    """Neutralise spreadsheet formula injection (CSV injection).

    Check for formula prefixes after leading whitespace and control characters.
    Tabs and carriage returns are themselves risky prefixes, so check for them
    before skipping whitespace and controls.
    """
    text = str(value)
    for char in text:
        if char in _CSV_FORMULA_PREFIXES:
            return "'" + text
        if not char.isspace() and unicodedata.category(char) != "Cc":
            break
    return text


def _sorted_links(links: List[Link]) -> List[Link]:
    return sorted(links, key=lambda l: (_CONF_ORDER.get(l.confidence, 9), l.link_type, l.related_entity))


_SHARED_FLAGS = {
    "shared_cdn", "shared_mail_provider", "shared_dns_provider", "shared_registrar",
    "shared_bulk_certificate", "bulk_hosting_netblock", "privacy_proxy",
    "large_san_list", "generic_hosting_rdns",
}
_ORIGIN_FLAGS = {"possible_origin_ip", "origin_confirmed"}
_VENDOR_TYPES = {
    "dns_mx", "dns_ns", "spf_include", "spf_redirect", "dmarc_report_recipient",
    "rdap_nameserver", "rdap_technical_email", "rdap_technical_org",
}
_FAILED = {"timeout", "error"}
_NO_DATA = {"empty", "nxdomain"}


def _entity_key(entity: str) -> str:
    return entity.strip().rstrip(".").casefold()


def _third_party(link: Link, seed: str) -> bool:
    if link.link_type.endswith("_org") or link.link_type in {"rdap_netblock", "rdap_registrar"}:
        return False
    host = link.related_entity.rsplit("@", 1)[-1]
    return bool(registrable_label(host)) and not same_owner(host, seed)


def _assessment_rank(link: Link, seed: str) -> tuple:
    flags = set(link.flags)
    value = (
        4 * _third_party(link, seed)
        + 2 * bool(flags & _ORIGIN_FLAGS)
        + 3 * ("dedicated_netblock" in flags)
        - 2 * ("cloud_hosted_ip" in flags)
        - ("expired_certificate" in flags)
    )
    inventory = same_owner(link.related_entity.rsplit("@", 1)[-1], seed)
    return (inventory, _CONF_ORDER.get(link.confidence, 9), -value,
            link.link_type, link.related_entity, link.source_entity)


def _alternative(links: List[Link], seed: str) -> str:
    for link in links:
        flags = set(link.flags)
        third_party = _third_party(link, seed)
        if "expired_certificate" in flags:
            return f"The expired certificate for `{_md_escape(link.related_entity)}` may reflect a past relationship."
        if third_party and link.link_type in {"ct_shared_certificate", "shared_ip"}:
            return (f"`{_md_escape(link.related_entity)}` may be a customer or vendor using the same "
                    "infrastructure, so the overlap could reflect a service relationship.")
        if (third_party and link.link_type in _VENDOR_TYPES
                or flags & {"shared_mail_provider", "shared_dns_provider"}):
            return "An outsourced mail, DNS, or technical service may account for the third-party record."
        if flags & _ORIGIN_FLAGS:
            return (f"`{_md_escape(link.related_entity)}` could serve mail or DNS even if it is "
                    "associated with the seed domain.")
        if flags & {"shared_cdn", "shared_bulk_certificate", "bulk_hosting_netblock",
                    "large_san_list", "generic_hosting_rdns", "cloud_hosted_ip"}:
            return "A hosting or CDN provider may serve multiple tenants on the observed infrastructure."
        if flags & {"shared_registrar", "privacy_proxy"}:
            return "A shared registration service may account for the observed registration record."
    return "The observations may reflect routine configuration or a snapshot of what was published during collection."


def _source_gap(result: RunResult, priority: List[Link], ranked: List[Link]) -> str:
    failed = [entry for entry in result.log if entry.status in _FAILED]
    empty = [entry for entry in result.log if entry.status in _NO_DATA]
    if not (failed or empty):
        return "No source gaps were logged."

    priority_ids = {id(link) for link in priority}
    relevance = defaultdict(int)
    implications = {}
    for link in ranked:
        is_priority = id(link) in priority_ids
        if not is_priority and link.confidence not in {"High", "Medium"}:
            continue
        related = _entity_key(link.related_entity)
        source = _entity_key(link.source_entity)
        relevance[related] = max(relevance[related], 4 if is_priority else 2)
        relevance[source] = max(relevance[source], 3 if is_priority else 1)
        checks = {}
        if "possible_origin_ip" in link.flags:
            checks["ptr"] = "This lookup would help check the possible origin IP."
        if link.link_type == "ct_shared_certificate":
            checks["a"] = "This limits verification of current IPv4 hosting for a name on the certificate."
        for record_type, implication in checks.items():
            key = (related, record_type)
            relevance[key] = max(relevance[key], 8 if is_priority else 6)
            implications[key] = implication

    def query_tokens(entry: LogEntry) -> tuple:
        return tuple(_entity_key(token) for token in entry.query.split())

    def gap_rank(entry: LogEntry) -> tuple:
        tokens = query_tokens(entry)
        impact = max((relevance[token] for token in tokens), default=0)
        if entry.source == "DNS":
            impact = max(impact, relevance[tokens])
        return (-impact, entry.source, entry.query, entry.status, entry.detail)

    gap = min(failed or empty, key=gap_rank)
    detail = f" — `{_md_escape(truncate(gap.detail))}`" if gap.detail else ""
    implication = implications.get(query_tokens(gap), "") if gap.source == "DNS" else ""
    return (f"{_md_escape(gap.source)} query `{_md_escape(gap.query)}` returned "
            f"`{gap.status}`{detail}. {implication + ' ' if implication else ''}"
            f"Collection logged {len(failed)} failed "
            f"and {len(empty)} no-data queries.")


def build_assessment(result: RunResult) -> List[str]:
    """Summarise evidence-backed leads and the most relevant collection gap."""
    ranked = sorted(_sorted_links(result.links), key=lambda link: _assessment_rank(link, result.seed))
    by_entity = defaultdict(list)
    candidates = {}
    seed = _entity_key(result.seed)
    for link in ranked:
        entity = _entity_key(link.related_entity)
        by_entity[entity].append(link)
        if entity and entity != seed and not _SHARED_FLAGS.intersection(link.flags):
            candidates.setdefault(entity, link)

    priority = list(candidates.values())[:3]
    out = [
        "## Assessment\n",
        "This lead summary draws on the collected links and collection log. "
        "Use it to guide verification without drawing conclusions or assigning responsibility.\n",
        "**Priority leads**\n",
    ]
    for index, link in enumerate(priority, 1):
        reason = re.split(r"(?<=[.!?])\s+", _md_escape(link.reason).strip(), maxsplit=1)[0]
        if set(link.flags) & _ORIGIN_FLAGS:
            reason = reason.split(";", 1)[0]
        reason = reason.rstrip(".!?") or "See the recorded evidence for this relationship"
        if "expired_certificate" in link.flags:
            reason += " (certificate expired)"
        other_types = sorted({
            other.link_type for other in by_entity[_entity_key(link.related_entity)]
            if other.link_type != link.link_type
        })
        corroboration = ", ".join(f"`{_md_escape(kind)}`" for kind in other_types)
        also_observed = f" (also observed via {corroboration})" if corroboration else ""
        out.append(f"{index}. `{_md_escape(link.related_entity)}` from `{_md_escape(link.source_entity)}` "
                   f"(**{link.confidence}**, `{_md_escape(link.link_type)}`) — {reason}{also_observed}.")
    if not priority:
        out.append("No priority leads were identified.")
    out.extend([
        "",
        f"**Alternative explanation:** {_alternative(priority + ranked, result.seed)}\n",
        f"**Biggest source gap:** {_source_gap(result, priority, ranked)}\n",
    ])
    return out


def write_csv(result: RunResult, path: pathlib.Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(CSV_COLUMNS)
        for l in _sorted_links(result.links):
            w.writerow([_csv_safe(v) for v in (
                l.source_entity, l.related_entity, l.link_type, l.evidence, l.data_source,
                l.timestamp, l.confidence, l.reason, ";".join(l.flags),
            )])


def write_markdown(result: RunResult, path: pathlib.Path, csv_name: str) -> None:
    links = _sorted_links(result.links)
    high, med, low = confidence_counts(links)
    entities = {l.related_entity for l in links} | {l.source_entity for l in links}
    flagged = [l for l in links if l.flags]
    failed = [e for e in result.log if e.status in ("timeout", "error")]
    empty = [e for e in result.log if e.status in ("empty", "nxdomain")]

    out: List[str] = []
    out.append(f"# Infrastructure pivot report: `{result.seed}`\n")
    out.append(f"- **Run started:** {result.started}  ")
    out.append(f"- **Run finished:** {result.finished}  ")
    out.append(f"- **Stage:** {result.stage}  ")
    if result.data_note:
        out.append("- **Method:** offline replay of committed fixtures; no network connections at all  ")
    else:
        out.append("- **Method:** public third-party sources (DNS via recursive resolver, crt.sh, RDAP); "
                   "no direct connections from this tool to the target's web/app servers  ")
    if result.data_note:
        out.append(f"- **Data:** {result.data_note}  ")
    out.append(f"- **Cache:** {result.cache_hits} hit(s), {result.cache_misses} miss(es)  ")
    out.append(f"- **Links CSV:** `{csv_name}`\n")

    if result.data_note:
        out.append("> **SYNTHETIC DEMO.** Every name, IP address and registration record in this report comes "
                   "from committed offline fixtures. The names use reserved or fictional domains and the IPs sit in "
                   "documentation ranges (RFC 5737 / RFC 3849). Nothing here describes real infrastructure.\n")
    out.append("> **Analyst note.** Every link below is a lead, not a conclusion. "
               "Confidence reflects how well a single observation supports an infrastructure "
               "relationship; it is not an attribution. This tool does not name actors.\n")

    out.extend(build_assessment(result))
    out.append("## Summary\n")
    out.append("| Metric | Value |")
    out.append("|---|---|")
    out.append(f"| Entities observed | {len(entities)} |")
    out.append(f"| Links | {len(links)} |")
    out.append(f"| High confidence | {high} |")
    out.append(f"| Medium confidence | {med} |")
    out.append(f"| Low confidence (shared infrastructure) | {low} |")
    out.append(f"| Sources failed | {len(failed)} |")
    out.append(f"| Queries with no data | {len(empty)} |\n")

    for title, lines in result.sections.items():
        out.append(f"## {title}\n")
        out.extend(lines)
        out.append("")

    out.append("## Raw records observed\n")
    if any(result.records.values()):
        out.append("| Query | Answer |")
        out.append("|---|---|")
        for q, answers in result.records.items():
            if answers:
                for a in answers:
                    out.append(f"| `{_md_escape(q)}` | `{_md_escape(a)}` |")
            else:
                out.append(f"| `{_md_escape(q)}` | *(no data)* |")
        out.append("")
    else:
        out.append("*No records were returned for any query.*\n")

    out.append("## Links (sorted by confidence)\n")
    if links:
        out.append("| # | Source | Related entity | Link type | Confidence | Reason | Evidence | Data source |")
        out.append("|---|---|---|---|---|---|---|---|")
        for i, l in enumerate(links, 1):
            out.append(
                f"| {i} | `{_md_escape(l.source_entity)}` | `{_md_escape(l.related_entity)}` | "
                f"{l.link_type} | **{l.confidence}** | {_md_escape(l.reason)} | "
                f"`{_md_escape(l.evidence)}` | {_md_escape(l.data_source)} |"
            )
        out.append("")
    else:
        out.append("*No links were produced. See the collection log for why.*\n")

    out.append("## Shared-infrastructure flags\n")
    if flagged:
        out.append("These links were downgraded because the related entity is shared by many unrelated "
                   "organisations. Pivoting on them will mostly return noise.\n")
        out.append("| Related entity | Flag | Reason |")
        out.append("|---|---|---|")
        for l in flagged:
            out.append(f"| `{_md_escape(l.related_entity)}` | {', '.join(l.flags)} | {_md_escape(l.reason)} |")
        out.append("")
    else:
        out.append("*No shared-infrastructure flags raised.*\n")

    out.append("## Collection log\n")
    out.append("Every query made, including the ones that failed or returned nothing, so gaps are visible.\n")
    out.append("| Source | Query | Status | Detail | Timestamp |")
    out.append("|---|---|---|---|---|")
    for e in result.log:
        marker = "" if e.status in ("ok",) else " ⚠" if e.status in ("timeout", "error") else " ·"
        out.append(f"| {e.source} | `{_md_escape(e.query)}` | {e.status}{marker} | {_md_escape(truncate(e.detail))} | {e.timestamp} |")
    out.append("")

    by_type = Counter(l.link_type for l in links)
    if by_type:
        out.append("## Link types in this report\n")
        for t, n in sorted(by_type.items()):
            out.append(f"- `{t}`: {n}")
        out.append("")

    path.write_text("\n".join(out), encoding="utf-8")


def write_reports(result: RunResult, out_dir: pathlib.Path) -> tuple:
    """Write both files and return their paths."""
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = result.started.replace(":", "").replace("-", "").replace("+0000", "Z")
    base = f"{result.seed}_{stamp}"
    csv_path = out_dir / f"{base}_links.csv"
    md_path = out_dir / f"{base}_report.md"
    write_csv(result, csv_path)
    write_markdown(result, md_path, csv_path.name)
    return md_path, csv_path
