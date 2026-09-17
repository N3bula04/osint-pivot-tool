"""Report writers: Markdown for reading, CSV for pivoting in a spreadsheet."""

import csv
import pathlib
from collections import Counter
from typing import List

from models import Link, RunResult
from rating import confidence_counts

CSV_COLUMNS = [
    "source_entity", "related_entity", "link_type", "evidence", "data_source",
    "timestamp", "confidence", "confidence_reason", "flags",
]

_CONF_ORDER = {"High": 0, "Medium": 1, "Low": 2}


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _sorted_links(links: List[Link]) -> List[Link]:
    return sorted(links, key=lambda l: (_CONF_ORDER.get(l.confidence, 9), l.link_type, l.related_entity))


def write_csv(result: RunResult, path: pathlib.Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(CSV_COLUMNS)
        for l in _sorted_links(result.links):
            w.writerow([
                l.source_entity, l.related_entity, l.link_type, l.evidence, l.data_source,
                l.timestamp, l.confidence, l.reason, ";".join(l.flags),
            ])


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
    out.append(f"- **Method:** passive only (no direct contact with the target)  ")
    out.append(f"- **Cache:** {result.cache_hits} hit(s), {result.cache_misses} miss(es)  ")
    out.append(f"- **Links CSV:** `{csv_name}`\n")

    out.append("> **Analyst note.** Every link below is a lead, not a conclusion. "
               "Confidence reflects how well a single observation supports an infrastructure "
               "relationship; it is not an attribution. This tool does not name actors.\n")

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

    out.append("## Raw DNS records observed\n")
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
        out.append(f"| {e.source} | `{_md_escape(e.query)}` | {e.status}{marker} | {_md_escape(e.detail)} | {e.timestamp} |")
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
