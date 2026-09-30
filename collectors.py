"""Passive data collectors and the on-disk cache.

Stage 1: DNS (A, AAAA, MX, NS, TXT, _dmarc TXT, PTR on each IP).
Stage 2: Certificate transparency via crt.sh, plus a capped DNS resolve of
         the names it discovers so we can find domains sharing an IP.

Design rules every collector follows:
  * Never contact the target directly. DNS goes through your recursive
    resolver; crt.sh is a third-party archive of public CT logs.
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
import time
from collections import Counter, defaultdict
from typing import Dict, List, Optional, Set, Tuple

import dns.exception
import dns.resolver
import dns.reversename
import requests

from models import Link, LogEntry, RunResult
from rating import registrable_domain

DNS_SOURCE_LABEL = "DNS (system resolver via dnspython)"
CT_SOURCE_LABEL = "Certificate Transparency (crt.sh)"
CRTSH_URL = "https://crt.sh/"
USER_AGENT = "osint-pivot-tool/0.2 (+https://github.com/N3bula04/osint-pivot-tool; passive research)"
CACHE_TTL_HOURS = 24  # cached answers older than this are re-queried
CRTSH_PAUSE_SECONDS = 2.0   # polite gap between crt.sh requests
CRTSH_RETRIES = 3           # crt.sh returns 502/503 fairly often; retry with backoff

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

    result = None
    for use_tcp in (False, True):  # large TXT answers sometimes only arrive over TCP
        try:
            answer = resolver.resolve(name, rtype, tcp=use_tcp)
            answers = sorted(rr.to_text() for rr in answer)
            result = ("ok", answers, f"{len(answers)} record(s)" + (" (via TCP retry)" if use_tcp else ""))
            break
        except dns.resolver.NoAnswer:
            result = ("empty", [], "name exists but has no records of this type"); break
        except dns.resolver.NXDOMAIN:
            result = ("nxdomain", [], "name does not exist"); break
        except dns.resolver.NoNameservers:
            result = ("error", [], "no nameserver answered (SERVFAIL/REFUSED)"); break
        except dns.resolver.LifetimeTimeout:
            result = ("timeout", [], "query timed out (UDP and TCP)")
            continue
        except dns.exception.DNSException as e:  # catch-all for anything else in dnspython
            result = ("error", [], f"{type(e).__name__}: {e}"); break
        except OSError as e:  # e.g. network unreachable
            result = ("error", [], f"network error: {e}"); break

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


# --- the DNS collector ------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Certificate transparency (crt.sh)
# ---------------------------------------------------------------------------


def crtsh_fetch(cache: Cache, query: str, timeout: float = 60.0) -> Tuple[str, list, str]:
    """Fetch crt.sh JSON for one identity query. Returns (status, entries, detail). Never raises."""
    cached = cache.get("crtsh", query)
    if cached is not None:
        return cached["status"], cached["entries"], f"cached ({cached['fetched_at']})"

    status, entries, detail = "error", [], "not attempted"
    for attempt in range(1, CRTSH_RETRIES + 1):
        try:
            resp = requests.get(CRTSH_URL, params={"q": query, "output": "json"},
                                headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
                                timeout=timeout)
        except requests.Timeout:
            status, detail = "timeout", f"crt.sh did not answer within {timeout:.0f}s (attempt {attempt})"
        except requests.RequestException as e:
            status, detail = "error", f"network error: {type(e).__name__}: {e}"
            break  # connection-level failures rarely fix themselves in seconds
        else:
            if resp.status_code == 200:
                try:
                    entries = resp.json()
                except ValueError:
                    status, detail = "error", "crt.sh returned HTTP 200 but the body was not JSON"
                    break
                if not isinstance(entries, list):
                    entries = []
                status = "ok" if entries else "empty"
                detail = f"{len(entries)} certificate entries" if entries else "no certificates found"
                break
            if resp.status_code in (429, 500, 502, 503, 504):
                status, detail = "error", f"crt.sh HTTP {resp.status_code} (attempt {attempt})"
            else:
                status, detail = "error", f"crt.sh HTTP {resp.status_code}"
                break
        if attempt < CRTSH_RETRIES:
            time.sleep(2 ** attempt)  # 2s, 4s

    if status in _CACHEABLE:
        cache.put("crtsh", query, {"status": status, "entries": entries})
    return status, entries, detail


def _cert_names(entry: dict) -> Set[str]:
    """All DNS names on a crt.sh entry, lower-cased, wildcards stripped, emails dropped."""
    raw = set((entry.get("name_value") or "").split("\n"))
    raw.add(entry.get("common_name") or "")
    names = set()
    for n in raw:
        n = n.strip().lower().rstrip(".")
        if not n or "@" in n or " " in n:
            continue
        if n.startswith("*."):
            n = n[2:]
        names.add(n)
    return names


# Names CDNs put on their own shared certificates; they are not customer domains.
_CDN_PLACEHOLDERS = ("cloudflaressl.com", "sni.cloudflaressl.com", "fastly.net", "akamaized.net",
                     "cloudfront.net", "azureedge.net", "incapdns.net", "sucuri.net")


def _is_cdn_placeholder(name: str) -> bool:
    return any(name == p or name.endswith("." + p) for p in _CDN_PLACEHOLDERS)


def _issuer_short(issuer: str) -> str:
    m = re.search(r"CN=([^,]+)", issuer or "")
    return m.group(1).strip() if m else (issuer or "unknown issuer")[:60]


def parse_ct_entries(entries: list, seed: str) -> Dict[int, dict]:
    """Collapse raw crt.sh rows into one record per certificate id."""
    certs: Dict[int, dict] = {}
    for e in entries:
        try:
            cid = int(e.get("id"))
        except (TypeError, ValueError):
            continue
        if cid in certs:
            certs[cid]["names"] |= _cert_names(e)
            continue
        certs[cid] = {
            "id": cid,
            "issuer": _issuer_short(e.get("issuer_name", "")),
            "not_before": (e.get("not_before") or "")[:10],
            "not_after": (e.get("not_after") or "")[:10],
            "names": _cert_names(e),
        }
    return certs


def collect_ct(result: RunResult, cache: Cache, ct_file: Optional[pathlib.Path] = None,
               timeout: float = 60.0) -> Tuple[Set[str], Set[str]]:
    """Populate links from certificate transparency.

    Returns (subdomains, related_domains): names worth resolving in the IP pivot.
    """
    seed = result.seed
    seed_reg = registrable_domain(seed)
    ts = now_iso()
    today = _dt.date.today().isoformat()

    def log(query: str, status: str, detail: str) -> None:
        result.log.append(LogEntry("crt.sh", query, status, detail, now_iso()))

    entries: list = []
    if ct_file is not None:
        try:
            entries = json.loads(pathlib.Path(ct_file).read_text(encoding="utf-8"))
            log(f"file:{ct_file}", "ok", f"{len(entries)} entries loaded from file (no network)")
        except (OSError, ValueError) as e:
            log(f"file:{ct_file}", "error", f"could not read crt.sh JSON: {e}")
            return set(), set()
    else:
        # Two identity queries: the apex itself, and everything beneath it.
        for i, q in enumerate((seed, f"%.{seed}")):
            if i:
                time.sleep(CRTSH_PAUSE_SECONDS)
            status, got, detail = crtsh_fetch(cache, q, timeout=timeout)
            log(f"crt.sh q={q}", status, detail)
            entries.extend(got)

    certs = parse_ct_entries(entries, seed)
    if not certs:
        result.sections["Certificate transparency"] = ["No certificates were found or crt.sh was unavailable. See the collection log."]
        return set(), set()

    # ---- Names under the seed (subdomains) ----
    sub_seen: Dict[str, dict] = {}          # name -> most recent cert
    sub_count: Counter = Counter()
    # ---- Other domains sharing a certificate with a seed-owned name ----
    pair_seen: Dict[Tuple[str, str], dict] = {}
    pair_count: Counter = Counter()
    issuers: Counter = Counter()
    bulk_certs = 0

    for c in certs.values():
        issuers[c["issuer"]] += 1
        own = sorted(n for n in c["names"] if registrable_domain(n) == seed_reg)
        others = sorted(n for n in c["names"]
                        if registrable_domain(n) != seed_reg and not _is_cdn_placeholder(n))
        if not own:
            continue  # crt.sh matched on something we do not treat as the seed's
        for n in own:
            if n != seed:
                sub_count[n] += 1
                if n not in sub_seen or c["not_before"] > sub_seen[n]["not_before"]:
                    sub_seen[n] = c
        san_count = len(c["names"])
        is_bulk = san_count > 50 or any("cloudflaressl" in n for n in c["names"]) or "cloudflare" in c["issuer"].lower()
        if is_bulk:
            bulk_certs += 1
        src = seed if seed in own else own[0]
        # Bulk certs: collapse to one link per registrable domain to keep the noise readable.
        targets = sorted({registrable_domain(o) for o in others}) if is_bulk else others
        for o in targets:
            key = (src, o)
            pair_count[key] += 1
            if key not in pair_seen or c["not_before"] > pair_seen[key]["not_before"]:
                pair_seen[key] = dict(c, is_bulk=is_bulk, san_count=san_count)

    for name, c in sorted(sub_seen.items()):
        ev = (f"crt.sh cert {c['id']} (issuer '{c['issuer']}', valid {c['not_before']} to {c['not_after']}) "
              f"lists {name}; seen on {sub_count[name]} certificate(s); https://crt.sh/?id={c['id']}")
        result.links.append(Link(seed, name, "ct_subdomain", ev, CT_SOURCE_LABEL, ts,
                                 meta={"expired": c["not_after"] < today}))

    for (src, o), c in sorted(pair_seen.items()):
        ev = (f"crt.sh cert {c['id']} (issuer '{c['issuer']}', valid {c['not_before']} to {c['not_after']}, "
              f"{c['san_count']} names) lists both {src} and {o}; seen on {pair_count[(src, o)]} certificate(s); "
              f"https://crt.sh/?id={c['id']}")
        result.links.append(Link(src, o, "ct_shared_certificate", ev, CT_SOURCE_LABEL, ts,
                                 meta={"san_count": c["san_count"], "issuer": c["issuer"],
                                       "is_bulk": c["is_bulk"], "expired": c["not_after"] < today}))

    all_names = set().union(*(c["names"] for c in certs.values()))
    result.records[f"crt.sh names under {seed}"] = sorted(sub_seen)
    result.sections["Certificate transparency"] = [
        f"- Certificates matched: {len(certs)} ({bulk_certs} look like bulk/CDN-managed certificates)",
        f"- Unique names on those certificates: {len(all_names)}",
        f"- Names under the seed domain (subdomains): {len(sub_seen)}",
        f"- Other domains sharing a certificate with the seed: {len({o for _, o in pair_seen})}",
        "- Top issuers: " + ", ".join(f"{k} ({v})" for k, v in issuers.most_common(5)),
        f"- Manual check: https://crt.sh/?q={seed}",
    ]
    related = {o for (_, o), c in pair_seen.items() if not c["is_bulk"]}
    return set(sub_seen), related


# ---------------------------------------------------------------------------
# IP pivot: resolve discovered names and find ones sharing an IP with the seed
# ---------------------------------------------------------------------------


def collect_shared_ips(result: RunResult, cache: Cache, names: List[str], nameserver: Optional[str],
                       timeout: float, max_resolve: int) -> None:
    """Resolve up to max_resolve discovered names and link any that share an IP with the seed."""
    seed = result.seed
    seed_reg = registrable_domain(seed)
    resolver = _make_resolver(nameserver, timeout)
    ts = now_iso()

    seed_ips = {l.related_entity for l in result.links
                if l.source_entity == seed and l.link_type in ("dns_a", "dns_aaaa")}
    ip_owners: Dict[str, Set[str]] = defaultdict(set)
    for ip in seed_ips:
        ip_owners[ip].add(seed)

    def log(query: str, status: str, detail: str) -> None:
        result.log.append(LogEntry("DNS", query, status, detail, now_iso()))

    todo = sorted(set(names) - {seed})
    skipped = max(0, len(todo) - max_resolve)
    todo = todo[:max_resolve]
    if skipped:
        log("IP pivot budget", "empty", f"{skipped} discovered name(s) not resolved (raise --max-resolve to include them)")

    origin_candidates: List[str] = []
    for name in todo:
        own = registrable_domain(name) == seed_reg
        for rtype, ltype in (("A", "dns_a"), ("AAAA", "dns_aaaa")):
            status, answers, detail = dns_query(resolver, cache, name, rtype)
            log(f"{name} {rtype}", status, detail)
            for ip in answers:
                ip_owners[ip].add(name)
                link = Link(name, ip, ltype, f"{name} {rtype} -> {ip}", DNS_SOURCE_LABEL, ts,
                            meta={"seed_owned_host": own, "outside_seed_ips": ip not in seed_ips})
                result.links.append(link)
                if own and ip not in seed_ips:
                    origin_candidates.append(f"{name} -> {ip}")
                    # Reverse DNS on a seed-owned host's IP often names the real hosting provider.
                    try:
                        rev_name = str(dns.reversename.from_address(ip))
                    except Exception:
                        continue
                    pstatus, panswers, pdetail = dns_query(resolver, cache, rev_name, "PTR")
                    log(f"{ip} PTR", pstatus, pdetail)
                    result.records[f"{ip} PTR"] = panswers
                    for host in panswers:
                        host = host.rstrip(".").lower()
                        result.links.append(Link(ip, host, "dns_ptr", f"{ip} PTR -> {host}  ({rev_name})",
                                                 DNS_SOURCE_LABEL, ts))

    # Which non-seed-owned names landed on one of the seed's IPs?
    found = 0
    for ip in sorted(seed_ips):
        for name in sorted(ip_owners[ip]):
            if name == seed or registrable_domain(name) == seed_reg:
                continue
            found += 1
            ev = f"{seed} A/AAAA -> {ip}; {name} A/AAAA -> {ip} (both observed {ts})"
            result.links.append(Link(seed, name, "shared_ip", ev, DNS_SOURCE_LABEL, ts))
    result.sections["IP pivot"] = [
        f"- Discovered names resolved: {len(todo)} (skipped {skipped})",
        f"- Seed IPs: {len(seed_ips)}",
        f"- Other domains sharing an IP with the seed: {found}",
    ]
    if origin_candidates:
        result.sections["IP pivot"].append(
            "- **Seed-owned hosts on IPs outside the seed's own records** (possible origin infrastructure behind a CDN): "
            + "; ".join(origin_candidates))


# ---------------------------------------------------------------------------
# Registration data (RDAP): the domain, and the netblock behind each seed IP
# ---------------------------------------------------------------------------

RDAP_SOURCE_LABEL = "RDAP (registry/RIR via rdap.org)"
RDAP_REDIRECTOR = "https://rdap.org/"
IANA_BOOTSTRAP = {"domain": "https://data.iana.org/rdap/dns.json",
                  "ipv4": "https://data.iana.org/rdap/ipv4.json",
                  "ipv6": "https://data.iana.org/rdap/ipv6.json"}
RDAP_PAUSE_SECONDS = 1.0
RDAP_MAX_IPS = 8  # RDAP the seed's own IPs only; RIR rate limits are strict


def _rdap_get(url: str, timeout: float) -> Tuple[str, Optional[dict], str]:
    """One HTTP GET with RDAP headers. Returns (status, json_or_None, detail)."""
    try:
        resp = requests.get(url, headers={"Accept": "application/rdap+json, application/json",
                                          "User-Agent": USER_AGENT}, timeout=timeout, allow_redirects=True)
    except requests.Timeout:
        return "timeout", None, f"no answer within {timeout:.0f}s"
    except requests.RequestException as e:
        return "error", None, f"network error: {type(e).__name__}: {e}"
    if resp.status_code == 200:
        try:
            return "ok", resp.json(), f"HTTP 200 from {resp.url.split('/')[2]}"
        except ValueError:
            return "error", None, "HTTP 200 but body was not JSON"
    if resp.status_code == 404:
        return "empty", None, "HTTP 404: no RDAP record (unregistered, or registry has no RDAP)"
    if resp.status_code == 429:
        return "error", None, f"HTTP 429 rate limited (Retry-After: {resp.headers.get('Retry-After', '?')})"
    return "error", None, f"HTTP {resp.status_code} from {resp.url.split('/')[2]}"


def _bootstrap_server(cache: Cache, kind: str, target: str, timeout: float) -> Optional[str]:
    """Look up the authoritative RDAP base URL from IANA's bootstrap files."""
    key = IANA_BOOTSTRAP[kind]
    cached = cache.get("rdap", f"bootstrap:{kind}")
    data = cached["data"] if cached else None
    if data is None:
        status, data, _ = _rdap_get(key, timeout)
        if status != "ok" or not isinstance(data, dict):
            return None
        cache.put("rdap", f"bootstrap:{kind}", {"status": "ok", "data": data})
    try:
        import ipaddress as _ip
        for entry in data.get("services", []):
            keys, urls = entry[0], entry[1]
            if kind == "domain":
                if target.rsplit(".", 1)[-1].lower() in [k.lower() for k in keys]:
                    return urls[0]
            else:
                addr = _ip.ip_address(target)
                if any(addr in _ip.ip_network(k, strict=False) for k in keys):
                    return urls[0]
    except (ValueError, IndexError, TypeError):
        return None
    return None


def rdap_fetch(cache: Cache, kind: str, target: str, timeout: float = 30.0) -> Tuple[str, Optional[dict], str]:
    """Fetch an RDAP object ('domain' or 'ip'). Tries rdap.org, then IANA bootstrap. Never raises."""
    key = f"{kind}:{target}"
    cached = cache.get("rdap", key)
    if cached is not None:
        return cached["status"], cached.get("data"), f"cached ({cached['fetched_at']})"

    status, data, detail = _rdap_get(f"{RDAP_REDIRECTOR}{kind}/{target}", timeout)
    if status not in ("ok", "empty"):
        bkind = "domain" if kind == "domain" else ("ipv6" if ":" in target else "ipv4")
        base = _bootstrap_server(cache, bkind, target, timeout)
        if base:
            status2, data2, detail2 = _rdap_get(f"{base.rstrip('/')}/{kind}/{target}", timeout)
            detail = f"rdap.org failed ({detail}); bootstrap server: {detail2}"
            status, data = status2, data2
        else:
            detail = f"rdap.org failed ({detail}); IANA bootstrap lookup also unavailable"
    if status in _CACHEABLE:
        cache.put("rdap", key, {"status": status, "data": data})
    return status, data, detail


# --- RDAP JSON helpers (defensive: registries differ a lot) -----------------


def _vcard(entity: dict) -> Dict[str, str]:
    """Flatten a jCard into {fn, org, email, country}."""
    out: Dict[str, str] = {}
    try:
        for item in entity.get("vcardArray", [None, []])[1]:
            name, _, _, value = item[0], item[1], item[2], item[3]
            if name in ("fn", "org", "email") and isinstance(value, str) and value.strip():
                out.setdefault(name, value.strip())
            elif name == "adr":
                if isinstance(value, list) and len(value) >= 7 and value[6]:
                    out.setdefault("country", str(value[6]))
                label = item[1].get("cc") if isinstance(item[1], dict) else None
                if label:
                    out.setdefault("country", label)
    except (IndexError, TypeError, AttributeError):
        pass
    return out


def _entities_by_role(obj: dict) -> Dict[str, List[dict]]:
    out: Dict[str, List[dict]] = defaultdict(list)
    for ent in obj.get("entities", []) or []:
        for role in ent.get("roles", []) or []:
            out[role].append(ent)
        for sub in ent.get("entities", []) or []:     # nested (registrar -> abuse contact etc.)
            for role in sub.get("roles", []) or []:
                out[role].append(sub)
    return out


def _events(obj: dict) -> Dict[str, str]:
    return {e.get("eventAction", ""): (e.get("eventDate") or "")[:10] for e in obj.get("events", []) or []}


def _rdap_ip_block(obj: dict) -> str:
    """Best-effort CIDR (or start-end) for an ip network object."""
    cidrs = obj.get("cidr0_cidrs") or []
    parts = []
    for c in cidrs:
        pfx = c.get("v4prefix") or c.get("v6prefix")
        if pfx and "length" in c:
            parts.append(f"{pfx}/{c['length']}")
    if parts:
        return ", ".join(parts)
    return f"{obj.get('startAddress', '?')}-{obj.get('endAddress', '?')}"


# --- the collector ----------------------------------------------------------


def _load_saved_rdap(rdap_dir: pathlib.Path, kind: str, target: str) -> Tuple[str, Optional[dict], str]:
    p = rdap_dir / f"{kind}_{target.replace(':', '-')}.json"  # colons are illegal in Windows filenames
    if not p.exists():
        return "empty", None, f"no saved file {p.name} in offline mode"
    try:
        return "ok", json.loads(p.read_text(encoding="utf-8")), f"loaded from {p.name} (no network)"
    except (OSError, ValueError) as e:
        return "error", None, f"could not read {p.name}: {e}"


def collect_rdap(result: RunResult, cache: Cache, rdap_dir: Optional[pathlib.Path] = None,
                 timeout: float = 30.0) -> None:
    """Populate registration-data links and sections for the seed and its IPs."""
    seed = result.seed
    ts = now_iso()
    today = _dt.date.today()

    def log(query: str, status: str, detail: str) -> None:
        result.log.append(LogEntry("RDAP", query, status, detail, now_iso()))

    def fetch(kind: str, target: str):
        if rdap_dir is not None:
            return _load_saved_rdap(rdap_dir, kind, target)
        return rdap_fetch(cache, kind, target, timeout=timeout)

    # ---------------- domain ----------------
    lines: List[str] = []
    status, dom, detail = fetch("domain", seed)
    log(f"rdap domain {seed}", status, detail)
    registrant_org = ""
    if status == "ok" and isinstance(dom, dict):
        roles = _entities_by_role(dom)
        ev = _events(dom)
        registrar = next((_vcard(e).get("fn") for e in roles.get("registrar", []) if _vcard(e).get("fn")), "")
        iana_id = next((p.get("identifier") for e in roles.get("registrar", [])
                        for p in e.get("publicIds", []) or [] if "IANA" in p.get("type", "")), "")
        rdap_ns = sorted({(n.get("ldhName") or "").lower().rstrip(".") for n in dom.get("nameservers", []) or []} - {""})
        dns_ns = sorted({l.related_entity for l in result.links if l.link_type == "dns_ns"})
        statuses = ", ".join(dom.get("status", []) or []) or "none listed"
        dnssec = (dom.get("secureDNS") or {}).get("delegationSigned")
        created, expires, changed = ev.get("registration", ""), ev.get("expiration", ""), ev.get("last changed", "")

        lines.append(f"- Registrar: {registrar or 'not disclosed'}" + (f" (IANA ID {iana_id})" if iana_id else ""))
        lines.append(f"- Registered: {created or 'unknown'} | Last changed: {changed or 'unknown'} | Expires: {expires or 'unknown'}")
        if created:
            try:
                age_days = (today - _dt.date.fromisoformat(created)).days
                lines.append(f"- Domain age: {age_days} days" + ("  **(registered within the last 90 days)**" if age_days < 90 else ""))
            except ValueError:
                pass
        lines.append(f"- Status: {statuses}")
        lines.append(f"- DNSSEC signed: {dnssec if dnssec is not None else 'unknown'}")
        lines.append(f"- Registry nameservers: {', '.join(rdap_ns) or 'none listed'}")
        if rdap_ns and dns_ns and set(rdap_ns) != set(dns_ns):
            lines.append(f"- **Nameserver mismatch**: DNS answers {', '.join(dns_ns)} but the registry lists "
                         f"{', '.join(rdap_ns)}. Delegation change in progress, or a lame delegation. Worth a look.")
        for role in ("registrant", "administrative", "technical"):
            for e in roles.get(role, []):
                vc = _vcard(e)
                if not vc:
                    continue
                lines.append(f"- {role.capitalize()} contact: " + ", ".join(
                    f"{k}={v}" for k, v in vc.items()))
                if role == "registrant":
                    registrant_org = vc.get("org") or vc.get("fn") or registrant_org
                for field_name in ("email", "org"):
                    val = vc.get(field_name)
                    if val and val.lower() != seed:
                        evid = (f"RDAP domain record for {seed}: {role} contact {field_name}={val}; "
                                f"https://rdap.org/domain/{seed}")
                        result.links.append(Link(seed, val, f"rdap_{role}_{field_name}", evid, RDAP_SOURCE_LABEL, ts,
                                                 meta={"role": role}))
        if registrar:
            evid = f"RDAP domain record for {seed}: registrar '{registrar}'" + (f", IANA ID {iana_id}" if iana_id else "") + f"; https://rdap.org/domain/{seed}"
            result.links.append(Link(seed, registrar, "rdap_registrar", evid, RDAP_SOURCE_LABEL, ts))
        for ns in rdap_ns:
            result.links.append(Link(seed, ns, "rdap_nameserver", f"RDAP domain record for {seed} lists nameserver {ns}; https://rdap.org/domain/{seed}",
                                     RDAP_SOURCE_LABEL, ts))
        result.records[f"rdap domain {seed} nameservers"] = rdap_ns
        lines.append(f"- Manual check: https://rdap.org/domain/{seed} or https://lookup.icann.org/lookup?name={seed}")
    else:
        lines.append(f"Domain RDAP unavailable: {detail}")
    result.sections["Registration data (RDAP)"] = lines

    # ---------------- IPs ----------------
    seed_ips = sorted({l.related_entity for l in result.links
                       if l.source_entity == seed and l.link_type in ("dns_a", "dns_aaaa")})
    lines = []
    if len(seed_ips) > RDAP_MAX_IPS:
        log("rdap ip budget", "empty", f"{len(seed_ips) - RDAP_MAX_IPS} seed IP(s) skipped (RDAP_MAX_IPS={RDAP_MAX_IPS})")
        seed_ips = seed_ips[:RDAP_MAX_IPS]
    for i, ip in enumerate(seed_ips):
        if i and rdap_dir is None:
            time.sleep(RDAP_PAUSE_SECONDS)
        status, net, detail = fetch("ip", ip)
        log(f"rdap ip {ip}", status, detail)
        if status != "ok" or not isinstance(net, dict):
            lines.append(f"- `{ip}`: RDAP unavailable ({detail})")
            continue
        block = _rdap_ip_block(net)
        roles = _entities_by_role(net)
        owner = ""
        for role in ("registrant", "administrative", "technical", "abuse"):
            owner = next((_vcard(e).get("fn") or _vcard(e).get("org") for e in roles.get(role, []) if _vcard(e)), "")
            if owner:
                break
        name = net.get("name") or ""
        country = net.get("country") or ""
        ntype = net.get("type") or ""
        lines.append(f"- `{ip}` is in `{block}` ({name or 'unnamed'}), holder: {owner or 'not disclosed'}"
                     + (f", country {country}" if country else "") + (f", type {ntype}" if ntype else ""))
        evid = (f"RDAP ip record for {ip}: network {block} name='{name}' holder='{owner}'"
                + (f" country={country}" if country else "") + f"; https://rdap.org/ip/{ip}")
        result.links.append(Link(ip, block, "rdap_netblock", evid, RDAP_SOURCE_LABEL, ts,
                                 meta={"owner": owner, "name": name, "block": block,
                                       "registrant_org": registrant_org}))
    if not seed_ips:
        lines.append("No seed IPs to look up.")
    result.sections["IP ownership (RDAP)"] = lines
