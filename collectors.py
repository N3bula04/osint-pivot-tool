"""Passive data collectors. Stage 1: DNS only.

Design rules that every collector follows:
  * Never contact the target directly. DNS goes through your recursive
    resolver; later stages use third-party archives (crt.sh, RDAP).
  * Never raise. Every failure becomes a LogEntry so the report shows gaps.
  * Cache every raw answer on disk so re-runs do not re-query.
  * Return Links with evidence and a data_source, nothing else. Confidence
    is assigned later by rating.py.
"""

import datetime as _dt
import hashlib
import json
import pathlib
import re
from typing import Dict, List, Optional, Tuple

import dns.exception
import dns.resolver
import dns.reversename

from models import Link, LogEntry, RunResult

DNS_SOURCE_LABEL = "DNS (system resolver via dnspython)"
CACHE_TTL_HOURS = 24  # cached answers older than this are re-queried

# Statuses that are safe to cache. Timeouts and errors are never cached, so a
# transient failure does not poison later runs.
_CACHEABLE = {"ok", "empty", "nxdomain"}


def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


class Cache:
    """Tiny JSON-file cache. One file per query, keyed by a hash of the query."""

    def __init__(self, root: pathlib.Path, enabled: bool = True, refresh: bool = False):
        self.root = root
        self.enabled = enabled
        self.refresh = refresh  # True = ignore existing entries but still write new ones
        self.hits = 0
        self.misses = 0
        if enabled:
            root.mkdir(parents=True, exist_ok=True)

    def _path(self, namespace: str, key: str) -> pathlib.Path:
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", key)[:80]
        digest = hashlib.sha1(key.encode()).hexdigest()[:10]
        d = self.root / namespace
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{safe}_{digest}.json"

    def get(self, namespace: str, key: str) -> Optional[dict]:
        if not self.enabled or self.refresh:
            return None
        p = self._path(namespace, key)
        if not p.exists():
            self.misses += 1
            return None
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            fetched = _dt.datetime.fromisoformat(data["fetched_at"])
            age = _dt.datetime.now(_dt.timezone.utc) - fetched
            if age > _dt.timedelta(hours=CACHE_TTL_HOURS):
                self.misses += 1
                return None
            self.hits += 1
            return data
        except (ValueError, KeyError, OSError):
            self.misses += 1
            return None

    def put(self, namespace: str, key: str, payload: dict) -> None:
        if not self.enabled:
            return
        payload = dict(payload)
        payload["fetched_at"] = now_iso()
        payload["query"] = key
        self._path(namespace, key).write_text(json.dumps(payload, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------


def _make_resolver(nameserver: Optional[str], timeout: float) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    if nameserver:
        r.nameservers = [nameserver]
    r.timeout = timeout          # per-attempt
    r.lifetime = timeout * 2     # total for the query
    return r


def dns_query(resolver, cache: Cache, name: str, rtype: str) -> Tuple[str, List[str], str]:
    """Return (status, answers, detail). Never raises.

    status is one of: ok, empty, nxdomain, timeout, error.
    answers are the raw record strings as dnspython prints them.
    """
    key = f"{name.lower().rstrip('.')}:{rtype}"
    cached = cache.get("dns", key)
    if cached is not None:
        return cached["status"], cached["answers"], f"cached ({cached['fetched_at']})"

    try:
        answer = resolver.resolve(name, rtype)
        answers = sorted(rr.to_text() for rr in answer)
        result = ("ok", answers, f"{len(answers)} record(s)")
    except dns.resolver.NoAnswer:
        result = ("empty", [], "name exists but has no records of this type")
    except dns.resolver.NXDOMAIN:
        result = ("nxdomain", [], "name does not exist")
    except dns.resolver.NoNameservers:
        result = ("error", [], "no nameserver answered (SERVFAIL/REFUSED)")
    except dns.resolver.LifetimeTimeout:
        result = ("timeout", [], "query timed out")
    except dns.exception.DNSException as e:  # catch-all for anything else in dnspython
        result = ("error", [], f"{type(e).__name__}: {e}")
    except OSError as e:  # e.g. network unreachable
        result = ("error", [], f"network error: {e}")

    status, answers, detail = result
    if status in _CACHEABLE:
        cache.put("dns", key, {"status": status, "answers": answers, "rtype": rtype, "name": name})
    return status, answers, detail


# --- parsing helpers --------------------------------------------------------

_SPF_INCLUDE = re.compile(r"\binclude:([A-Za-z0-9._%-]+)")
_SPF_REDIRECT = re.compile(r"\bredirect=([A-Za-z0-9._%-]+)")
_DMARC_MAILTO = re.compile(r"mailto:([^,;\s\"]+)")


def _unquote_txt(txt: str) -> str:
    """dnspython prints TXT as one or more quoted strings; join and unquote."""
    return "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', txt)) or txt.strip('"')


def _strip_dot(name: str) -> str:
    return name.rstrip(".").lower()


# --- the collector ----------------------------------------------------------


def collect_dns(result: RunResult, cache: Cache, nameserver: Optional[str] = None,
                timeout: float = 5.0, do_ptr: bool = True) -> None:
    """Populate result.links, result.records and result.log from DNS."""
    seed = result.seed
    resolver = _make_resolver(nameserver, timeout)
    ts = now_iso()
    ips: List[str] = []

    def log(query: str, status: str, detail: str) -> None:
        result.log.append(LogEntry("DNS", query, status, detail, now_iso()))

    def add(link_type: str, related: str, evidence: str, source_entity: str = seed) -> None:
        result.links.append(Link(source_entity, related, link_type, evidence, DNS_SOURCE_LABEL, ts))

    # ---- A / AAAA ----
    for rtype, ltype in (("A", "dns_a"), ("AAAA", "dns_aaaa")):
        status, answers, detail = dns_query(resolver, cache, seed, rtype)
        log(f"{seed} {rtype}", status, detail)
        result.records[f"{seed} {rtype}"] = answers
        for ip in answers:
            ips.append(ip)
            add(ltype, ip, f"{seed} {rtype} -> {ip}")

    # ---- MX ----
    status, answers, detail = dns_query(resolver, cache, seed, "MX")
    log(f"{seed} MX", status, detail)
    result.records[f"{seed} MX"] = answers
    for rec in answers:
        pref, _, host = rec.partition(" ")
        host = _strip_dot(host)
        if host in ("", "."):
            continue  # "0 ." is the null MX: domain explicitly receives no mail
        add("dns_mx", host, f"{seed} MX {pref} {host}")

    # ---- NS ----
    status, answers, detail = dns_query(resolver, cache, seed, "NS")
    log(f"{seed} NS", status, detail)
    result.records[f"{seed} NS"] = answers
    for rec in answers:
        add("dns_ns", _strip_dot(rec), f"{seed} NS {_strip_dot(rec)}")

    # ---- TXT (SPF) ----
    status, answers, detail = dns_query(resolver, cache, seed, "TXT")
    log(f"{seed} TXT", status, detail)
    result.records[f"{seed} TXT"] = answers
    for rec in answers:
        txt = _unquote_txt(rec)
        if not txt.lower().startswith("v=spf1"):
            continue
        for host in _SPF_INCLUDE.findall(txt):
            add("spf_include", _strip_dot(host), f'{seed} TXT "{txt}"')
        for host in _SPF_REDIRECT.findall(txt):
            add("spf_redirect", _strip_dot(host), f'{seed} TXT "{txt}"')

    # ---- TXT at _dmarc (DMARC report recipients) ----
    dmarc_name = f"_dmarc.{seed}"
    status, answers, detail = dns_query(resolver, cache, dmarc_name, "TXT")
    log(f"{dmarc_name} TXT", status, detail)
    result.records[f"{dmarc_name} TXT"] = answers
    seen = set()
    for rec in answers:
        txt = _unquote_txt(rec)
        if not txt.lower().startswith("v=dmarc1"):
            continue
        for addr in _DMARC_MAILTO.findall(txt):
            domain = _strip_dot(addr.split("@")[-1].split("!")[0])
            if domain and domain not in seen:
                seen.add(domain)
                add("dmarc_report_recipient", domain, f'{dmarc_name} TXT "{txt}"')

    # ---- One-hop pivot: reverse DNS for each IP ----
    if do_ptr:
        for ip in ips:
            try:
                rev = dns.reversename.from_address(ip)
            except Exception as e:  # malformed address; should not happen
                log(f"{ip} PTR", "error", f"could not build reverse name: {e}")
                continue
            rev_name = str(rev)
            status, answers, detail = dns_query(resolver, cache, rev_name, "PTR")
            log(f"{ip} PTR", status, detail)
            result.records[f"{ip} PTR"] = answers
            for host in answers:
                host = _strip_dot(host)
                add("dns_ptr", host, f"{ip} PTR -> {host}  ({rev_name})", source_entity=ip)
