#!/usr/bin/env python3
"""osint-pivot-tool: OSINT infrastructure pivoting from one seed domain, using public third-party sources.

Usage:
    python pivot.py example.com
    python pivot.py example.com --refresh          # ignore cache, re-query
    python pivot.py example.com --resolver 1.1.1.1 # use a specific recursive resolver
    python pivot.py example.com --ct-file saved.json  # use a crt.sh JSON you downloaded

Stage 1: DNS (A, AAAA, MX, NS, TXT, DMARC TXT, plus reverse DNS on each IP).
Stage 2: certificate transparency via crt.sh, then a capped resolve of discovered
         names to find domains sharing an IP with the seed.
Stage 3: RDAP registration data for the seed domain and the netblock of each seed IP.

Offline demo (no network at all, synthetic fixtures, reproducible output):
    python pivot.py --demo
    python pivot.py example-demo.test --offline examples/offline_demo --fixed-time 2026-09-30T00:00:00+00:00
"""

import argparse
import datetime as _dt
import pathlib
import re
import sys

import collectors
import offline
from collectors import Cache, collect_ct, collect_dns, collect_rdap, collect_shared_ips, now_iso, truncate
from models import TOOL_VERSION_NUMBER, RunResult
from rating import confidence_counts, rate_all, same_owner
from report import write_reports

TOOL_VERSION = f"{TOOL_VERSION_NUMBER} (Stage 3: DNS + crt.sh + RDAP)"

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
        description="OSINT infrastructure pivot tool (DNS via your resolver, crt.sh, RDAP; no direct connections to the target's web/app servers). Produces a Markdown report and a CSV of evidence-backed links.",
    )
    p.add_argument("domain", nargs="?", help="seed domain, e.g. example.com (optional with --demo)")
    p.add_argument("-o", "--output-dir", default="reports", help="where to write reports (default: reports/)")
    p.add_argument("--cache-dir", default="cache", help="where raw responses are cached (default: cache/)")
    p.add_argument("--refresh", action="store_true", help="ignore cached responses and re-query every source")
    p.add_argument("--no-cache", action="store_true", help="do not read or write the cache at all")
    p.add_argument("--resolver", metavar="IP", help="recursive DNS resolver to use instead of the system default, e.g. 1.1.1.1")
    p.add_argument("--timeout", type=float, default=5.0, help="per-query timeout in seconds (default: 5)")
    p.add_argument("--no-ptr", action="store_true", help="skip reverse DNS lookups on discovered IPs")
    p.add_argument("--skip-ct", action="store_true", help="skip certificate transparency (crt.sh)")
    p.add_argument("--ct-file", metavar="JSON", help="read crt.sh results from a saved JSON file instead of the network")
    p.add_argument("--ct-timeout", type=float, default=60.0, help="crt.sh request timeout in seconds (default: 60; crt.sh can be slow)")
    p.add_argument("--skip-rdap", action="store_true", help="skip RDAP registration lookups")
    p.add_argument("--rdap-dir", metavar="DIR", help="read RDAP JSON from DIR/domain_<seed>.json and DIR/ip_<ip>.json instead of the network")
    p.add_argument("--rdap-timeout", type=float, default=30.0, help="RDAP request timeout in seconds (default: 30)")
    p.add_argument("--max-resolve", type=int, default=30, help="max discovered names to resolve for the IP pivot (default: 30; 0 disables)")
    p.add_argument("--offline", metavar="DIR", help="answer DNS, crt.sh and RDAP only from fixtures in DIR "
                   "(dns.json, crtsh.json, rdap/); any network call aborts the run")
    p.add_argument("--demo", action="store_true", help="synthetic offline demo: seed example-demo.test, fixtures in "
                   "examples/offline_demo/, fixed timestamp; no network")
    p.add_argument("--fixed-time", metavar="ISO8601", help="pin all timestamps (e.g. 2026-09-30T00:00:00+00:00) so "
                   "output is reproducible; mainly for --offline/--demo")
    p.add_argument("--version", action="version", version=f"%(prog)s {TOOL_VERSION}")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    if args.demo:
        args.offline = args.offline or str(offline.DEMO_DIR)
        args.domain = args.domain or offline.DEMO_SEED
        args.fixed_time = args.fixed_time or offline.DEMO_FIXED_TIME
    if not args.domain:
        print("[!] a seed domain is required (or use --demo)", file=sys.stderr)
        return 2
    try:
        seed = normalise_domain(args.domain)
    except ValueError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 2
    if args.fixed_time:
        try:
            _dt.datetime.fromisoformat(args.fixed_time)
        except ValueError:
            print(f"[!] --fixed-time '{args.fixed_time}' is not an ISO 8601 timestamp", file=sys.stderr)
            return 2

    if args.offline:
        fixtures = pathlib.Path(args.offline)
        if not (fixtures / "dns.json").exists():
            print(f"[!] --offline: {fixtures}/dns.json not found", file=sys.stderr)
            return 2
        args.no_cache = True
        args.ct_file = None if args.skip_ct else str(fixtures / "crtsh.json")
        args.rdap_dir = str(fixtures / "rdap")
        with offline.offline_session(fixtures, args.fixed_time):
            return _run(args, seed, data_note=(
                f"SYNTHETIC offline fixtures from `{fixtures.name}/` (no network used); "
                "fictional/reserved names and documentation IP ranges only"))
    if args.fixed_time:
        collectors.set_fixed_time(_dt.datetime.fromisoformat(args.fixed_time))
        try:
            return _run(args, seed)
        finally:
            collectors.set_fixed_time(None)
    return _run(args, seed)


def _run(args: argparse.Namespace, seed: str, data_note: str = "") -> int:
    print(f"[*] osint-pivot-tool {TOOL_VERSION}")
    print(f"[*] Seed domain: {seed}")
    if data_note:
        print("[*] OFFLINE mode: fixtures only, network calls are blocked")

    cache = Cache(pathlib.Path(args.cache_dir), enabled=not args.no_cache, refresh=args.refresh)
    result = RunResult(seed=seed, started=now_iso(), data_note=data_note)

    print("[*] Collecting DNS records" + (" (offline fixtures)..." if data_note else " (via recursive resolver)..."))
    collect_dns(result, cache, nameserver=args.resolver, timeout=args.timeout, do_ptr=not args.no_ptr)

    discovered = set()
    if args.skip_ct:
        result.sections["Certificate transparency"] = ["Skipped (--skip-ct)."]
    else:
        print("[*] Querying certificate transparency (crt.sh)..." if not args.ct_file
              else f"[*] Loading certificate transparency data from {args.ct_file}...")
        subdomains, related = collect_ct(result, cache, ct_file=args.ct_file, timeout=args.ct_timeout)
        discovered = subdomains | related

    # Seed-owned mail and name servers are worth resolving too: they often sit
    # outside the CDN and expose the real hosting provider.
    for l in result.links:
        if l.link_type in ("dns_mx", "dns_ns") and same_owner(l.related_entity, seed):
            discovered.add(l.related_entity)

    if args.max_resolve > 0 and discovered:
        print(f"[*] IP pivot: resolving up to {args.max_resolve} of {len(discovered)} discovered names...")
        collect_shared_ips(result, cache, sorted(discovered), args.resolver, args.timeout, args.max_resolve)

    if args.skip_rdap:
        result.sections["Registration data (RDAP)"] = ["Skipped (--skip-rdap)."]
    else:
        print("[*] Querying RDAP for the domain and its IPs..." if not args.rdap_dir
              else f"[*] Loading RDAP data from {args.rdap_dir}/...")
        collect_rdap(result, cache, rdap_dir=pathlib.Path(args.rdap_dir) if args.rdap_dir else None,
                     timeout=args.rdap_timeout)

    rate_all(result.links, seed)
    result.finished = now_iso()
    result.cache_hits, result.cache_misses = cache.hits, cache.misses

    md_path, csv_path = write_reports(result, pathlib.Path(args.output_dir))

    high, med, low = confidence_counts(result.links)
    failed = [e for e in result.log if e.status in ("timeout", "error")]
    print(f"[*] Links: {len(result.links)}  (High {high} / Medium {med} / Low {low})")
    for e in result.log:
        tag = {"ok": " ", "cached": " ", "empty": "-", "nxdomain": "-"}.get(e.status, "!")
        print(f"    [{tag}] {e.query:<45} {e.status:<9} {truncate(e.detail)}")
    if failed:
        print(f"[!] {len(failed)} query/queries failed; gaps are recorded in the report.")
    print(f"[*] Report:  {md_path}")
    print(f"[*] Links:   {csv_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
