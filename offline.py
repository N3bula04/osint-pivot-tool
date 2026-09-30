"""Offline / demo mode: answer DNS, crt.sh and RDAP from committed fixtures.

Used by `python pivot.py --demo` and `--offline DIR`. While an offline
session is active:

  * DNS queries go to FixtureResolver, which reads DIR/dns.json;
  * crt.sh data comes from DIR/crtsh.json;
  * RDAP data comes from DIR/rdap/ (same layout as --rdap-dir);
  * optional DIR/cdn_ranges.json adds fictional CDN ranges for the demo;
  * every network entry point (sockets, DNS resolution, requests) is
    replaced by a guard that raises NetworkBlockedError, so an accidental
    network call fails the run loudly instead of silently leaking traffic;
  * timestamps can be pinned (--fixed-time) so output is byte-for-byte
    reproducible and CI can diff it against the committed sample.

dns.json format:  {"name:RTYPE": {"status": "ok", "answers": ["..."]}, ...}
PTR keys use the IP address: "192.0.2.10:PTR". Status may be ok / empty /
nxdomain. A name with no key at all answers NXDOMAIN.
"""

import contextlib
import datetime as _dt
import json
import pathlib
import socket
from typing import Dict, Iterator, List, Optional

import dns.name
import dns.resolver
import dns.reversename
import requests

import collectors
import rating

DEMO_DIR = pathlib.Path(__file__).parent / "examples" / "offline_demo"
DEMO_SEED = "example-demo.test"
DEMO_FIXED_TIME = "2026-09-30T00:00:00+00:00"


class NetworkBlockedError(RuntimeError):
    """Raised when anything tries to use the network during an offline run."""


class _Rdata:
    def __init__(self, text: str):
        self._text = text

    def to_text(self) -> str:
        return self._text


class FixtureResolver:
    """Drop-in for dns.resolver.Resolver.resolve(), backed by a dict."""

    def __init__(self, records: Dict[str, dict]):
        self.records = {k.lower(): v for k, v in records.items()}
        self.names = {k.rsplit(":", 1)[0] for k in self.records}
        self.queries: List[str] = []

    def resolve(self, name, rtype, tcp: bool = False, **_kw):
        name = str(name).lower().rstrip(".")
        if rtype == "PTR" and name.endswith((".in-addr.arpa", ".ip6.arpa")):
            name = str(dns.reversename.to_address(dns.name.from_text(name)))
        key = f"{name}:{rtype}".lower()
        self.queries.append(key)
        entry = self.records.get(key)
        if entry is None:
            if name in self.names:
                raise dns.resolver.NoAnswer()
            raise dns.resolver.NXDOMAIN()
        status = entry.get("status", "ok")
        if status == "nxdomain":
            raise dns.resolver.NXDOMAIN()
        if status == "empty" or not entry.get("answers"):
            raise dns.resolver.NoAnswer()
        return [_Rdata(a) for a in entry["answers"]]


# --- network guard ------------------------------------------------------------

def _blocked(*_a, **_kw):
    raise NetworkBlockedError("network access attempted during an offline run")


class _BlockedSocket(socket.socket):
    def __init__(self, *a, **kw):
        _blocked()


@contextlib.contextmanager
def network_blocked() -> Iterator[None]:
    """Make every common network entry point raise NetworkBlockedError."""
    saved = {
        "socket": socket.socket, "create_connection": socket.create_connection,
        "getaddrinfo": socket.getaddrinfo, "gethostbyname": socket.gethostbyname,
        "session_request": requests.Session.request, "requests_get": requests.get,
        "collectors_get": collectors.requests.get,
    }
    socket.socket = _BlockedSocket
    socket.create_connection = _blocked
    socket.getaddrinfo = _blocked
    socket.gethostbyname = _blocked
    requests.Session.request = _blocked
    requests.get = _blocked
    try:
        yield
    finally:
        socket.socket = saved["socket"]
        socket.create_connection = saved["create_connection"]
        socket.getaddrinfo = saved["getaddrinfo"]
        socket.gethostbyname = saved["gethostbyname"]
        requests.Session.request = saved["session_request"]
        requests.get = saved["requests_get"]


# --- the session ----------------------------------------------------------------

@contextlib.contextmanager
def offline_session(fixtures_dir: pathlib.Path, fixed_time: Optional[str] = None) -> Iterator[FixtureResolver]:
    """Activate fixtures, the network guard and (optionally) a pinned clock."""
    fixtures_dir = pathlib.Path(fixtures_dir)
    records = json.loads((fixtures_dir / "dns.json").read_text(encoding="utf-8"))
    resolver = FixtureResolver(records)
    cdn_file = fixtures_dir / "cdn_ranges.json"
    extra_cdn = json.loads(cdn_file.read_text(encoding="utf-8")) if cdn_file.exists() else {}
    collectors.set_resolver_factory(lambda nameserver, timeout: resolver)
    rating.set_extra_cdn_ranges(extra_cdn)
    if fixed_time:
        collectors.set_fixed_time(_dt.datetime.fromisoformat(fixed_time))
    try:
        with network_blocked():
            yield resolver
    finally:
        collectors.set_resolver_factory(None)
        rating.set_extra_cdn_ranges({})
        collectors.set_fixed_time(None)
