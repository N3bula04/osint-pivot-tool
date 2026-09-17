"""Data structures shared by the collectors, rating rules and report writer.

Keeping these in one small file means every other module agrees on what a
"link" is, and the CSV/Markdown writers never have to guess field names.
"""

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class Link:
    """One evidence-backed relationship between two entities.

    A link is never created without `evidence` and `data_source`.
    `confidence` and `reason` are filled in by rating.py, not by collectors,
    so the analytical rules live in exactly one place.
    """

    source_entity: str
    related_entity: str
    link_type: str        # e.g. dns_a, dns_mx, dns_ptr, spf_include
    evidence: str         # the raw observation, quoted as closely as possible
    data_source: str      # e.g. "DNS (system resolver)"
    timestamp: str        # ISO 8601 UTC, when the observation was made
    confidence: str = ""  # High / Medium / Low
    reason: str = ""      # one-line justification for the confidence rating
    flags: List[str] = field(default_factory=list)  # e.g. ["shared_cdn"]
    meta: Dict[str, object] = field(default_factory=dict)  # extra facts rating.py may use


@dataclass
class LogEntry:
    """One line in the collection log: what was asked, what came back."""

    source: str     # e.g. "DNS"
    query: str      # e.g. "example.com A"
    status: str     # ok / empty / nxdomain / timeout / error / cached
    detail: str     # human-readable note (record count, error text, ...)
    timestamp: str


@dataclass
class RunResult:
    """Everything one run produced, handed to the report writer."""

    seed: str
    started: str
    finished: str = ""
    stage: str = "Stage 2 - DNS + certificate transparency"
    links: List[Link] = field(default_factory=list)
    log: List[LogEntry] = field(default_factory=list)
    # Raw records grouped for display: {"example.com A": ["1.2.3.4", ...]}
    records: Dict[str, List[str]] = field(default_factory=dict)
    # Free-form per-source summaries for the report: {"Certificate transparency": ["line", ...]}
    sections: Dict[str, List[str]] = field(default_factory=dict)
    cache_hits: int = 0
    cache_misses: int = 0
