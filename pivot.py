#!/usr/bin/env python3
"""osint-pivot-tool: passive infrastructure pivoting from one seed domain.

Usage:
    python pivot.py example.com
    python pivot.py example.com --refresh          # ignore cache, re-query
    python pivot.py example.com --resolver 1.1.1.1 # use a specific recursive resolver

Stage 1: DNS only (A, AAAA, MX, NS, TXT, DMARC TXT, plus reverse DNS on each IP).
"""

import argparse
import pathlib
import re
import sys

from collectors import Cache, collect_dns, now_iso
from models import RunResult
from rating import confidence_counts, rate_all
from report import write_reports

TOOL_VERSION = "0.1.0 (Stage 1: DNS)"

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z0-9-]{2,63}$"
)


def normalise_domain(raw: str) -> str:
    """Lower-case, strip scheme/path/trailing dot, and validate."""
    d = raw.strip().lower()
    d = re.sub(r"^[a-z]+://", "", d)   # http://
    d = d.split("/")[0].split("?")[0]  # any path or query string
    d = d.rstrip(".")
    if d.startswith("www."):
        # keep www. as given? No: the apex is the better seed. Tell the user.
        print(f"[!] Stripping leading 'www.' -> seed is {d[4:]}", file=sys.stderr)
        d = d[4:]
    if not _DOMAIN_RE.match(d):
        raise ValueError(f"'{raw}' does not look like a valid domain name")
    return d


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="pivot.py",
        description="Passive OSINT infrastructure pivot tool. Produces a Markdown report and a CSV of evidence-backed links.",
    )
    p.add_argument("domain", help="seed domain, e.g. example.com")
    p.add_argument("-o", "--output-dir", default="reports", help="where to write reports (default: reports/)")
    p.add_argument("--cache-dir", default="cache", help="where raw responses are cached (default: cache/)")
    p.add_argument("--refresh", action="store_true", help="ignore cached responses and re-query every source")
    p.add_argument("--no-cache", action="store_true", help="do not read or write the cache at all")
    p.add_argument("--resolver", metavar="IP", help="recursive DNS resolver to use instead of the system default, e.g. 1.1.1.1")
    p.add_argument("--timeout", type=float, default=5.0, help="per-query timeout in seconds (default: 5)")
    p.add_argument("--no-ptr", action="store_true", help="skip reverse DNS lookups on discovered IPs")
    p.add_argument("--version", action="version", version=f"%(prog)s {TOOL_VERSION}")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        seed = normalise_domain(args.domain)
    except ValueError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 2

    print(f"[*] osint-pivot-tool {TOOL_VERSION}")
    print(f"[*] Seed domain: {seed}")

    cache = Cache(pathlib.Path(args.cache_dir), enabled=not args.no_cache, refresh=args.refresh)
    result = RunResult(seed=seed, started=now_iso())

    print("[*] Collecting DNS records (passive, via recursive resolver)...")
    collect_dns(result, cache, nameserver=args.resolver, timeout=args.timeout, do_ptr=not args.no_ptr)

    rate_all(result.links, seed)
    result.finished = now_iso()
    result.cache_hits, result.cache_misses = cache.hits, cache.misses

    md_path, csv_path = write_reports(result, pathlib.Path(args.output_dir))

    high, med, low = confidence_counts(result.links)
    failed = [e for e in result.log if e.status in ("timeout", "error")]
    print(f"[*] Links: {len(result.links)}  (High {high} / Medium {med} / Low {low})")
    for e in result.log:
        tag = {"ok": " ", "cached": " ", "empty": "-", "nxdomain": "-"}.get(e.status, "!")
        print(f"    [{tag}] {e.query:<45} {e.status:<9} {e.detail}")
    if failed:
        print(f"[!] {len(failed)} query/queries failed; gaps are recorded in the report.")
    print(f"[*] Report:  {md_path}")
    print(f"[*] Links:   {csv_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
