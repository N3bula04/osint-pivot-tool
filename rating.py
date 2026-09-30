"""Analytical rules: confidence ratings and shared-infrastructure flags.

Every rule here is deliberately simple and readable, because the analyst has
to be able to explain each rating in an interview or a report review.

Confidence means: how strongly does this single observation support an
infrastructure relationship between the two entities, for pivoting purposes?
  High   - the observation ties the entities together and is unlikely to be
           explained by shared third-party services.
  Medium - a real relationship is plausible, but a shared provider or
           coincidence has not been ruled out. Verify before relying on it.
  Low    - the observation is real, but the related entity is shared by many
           unrelated organisations (CDN, bulk hosting, managed DNS, mail
           providers). Pivoting on it will mostly return noise.

The tool never attributes activity to a named actor. It produces leads.
"""

import ipaddress
import re
from typing import List, Optional, Tuple

from models import Link

# ---------------------------------------------------------------------------
# Shared-infrastructure reference data
# ---------------------------------------------------------------------------

# Published CDN / anycast ranges. Any IP inside these is shared by thousands
# of unrelated tenants, so an IP pivot on it is close to meaningless.
# Cloudflare: https://www.cloudflare.com/ips/   Fastly: https://api.fastly.com/public-ip-list
SHARED_CDN_RANGES = {
    "Cloudflare": [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
        "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
    ],
    "Fastly": [
        "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24", "103.245.222.0/23",
        "103.245.224.0/24", "104.156.80.0/20", "140.248.64.0/18", "140.248.128.0/17",
        "146.75.0.0/17", "151.101.0.0/16", "157.52.64.0/18", "167.82.0.0/17",
        "167.82.128.0/20", "167.82.160.0/20", "167.82.224.0/20", "172.111.64.0/18",
        "185.31.16.0/22", "199.27.72.0/21", "199.232.0.0/16",
        "2a04:4e40::/32", "2a04:4e42::/32",
    ],
}

# Managed DNS providers. A nameserver in one of these domains says "uses a
# popular DNS host", not "is related to the other customers of that host".
SHARED_NS_PROVIDERS = {
    "cloudflare.com": "Cloudflare DNS",
    "googledomains.com": "Google Domains DNS",
    "google.com": "Google Cloud DNS",
    "domaincontrol.com": "GoDaddy DNS",
    "registrar-servers.com": "Namecheap DNS",
    "nsone.net": "NS1",
    "dnsimple.com": "DNSimple",
    "akam.net": "Akamai DNS",
    "dns.he.net": "Hurricane Electric DNS",
    "digitalocean.com": "DigitalOcean DNS",
    "wixdns.net": "Wix DNS",
    "squarespacedns.com": "Squarespace DNS",
    "dnsmadeeasy.com": "DNS Made Easy",
    "linode.com": "Linode DNS",
    "hostgator.com": "HostGator DNS",
    "bluehost.com": "Bluehost DNS",
    "ovh.net": "OVH DNS",
    "gandi.net": "Gandi DNS",
    "name.com": "Name.com DNS",
    "hover.com": "Hover DNS",
    "dnsowl.com": "Namesilo DNS",
    "dreamhost.com": "DreamHost DNS",
    "vercel-dns.com": "Vercel DNS",
    "netlify.com": "Netlify DNS",
    "inmotionhosting.com": "InMotion DNS",
    "siteground.net": "SiteGround DNS",
}

# Some managed DNS providers spread their nameservers over many TLDs
# (ns-1.awsdns-00.com / .net / .org / .co.uk). These patterns are matched
# against the registrable label only (the "awsdns-00" in awsdns-00.co.uk),
# never as a free substring, so "ns1.awsdns-00.com.evil.net" does not match.
SHARED_NS_LABEL_PATTERNS = {
    r"awsdns-\d{2}": "Amazon Route 53",
    r"ultradns": "UltraDNS",
    r"azure-dns": "Azure DNS",
}

# Mail providers. Sharing Google or Microsoft mail servers with another
# domain is not a relationship; it is the default state of the internet.
SHARED_MAIL_PROVIDERS = {
    "google.com": "Google Workspace",
    "googlemail.com": "Google Workspace",
    "outlook.com": "Microsoft 365",
    "protection.outlook.com": "Microsoft 365",
    "pphosted.com": "Proofpoint",
    "mimecast.com": "Mimecast",
    "messagelabs.com": "Broadcom/Symantec Email Security",
    "barracudanetworks.com": "Barracuda",
    "zoho.com": "Zoho Mail",
    "zohomail.com": "Zoho Mail",
    "zohomail.eu": "Zoho Mail",
    "protonmail.ch": "Proton Mail",
    "secureserver.net": "GoDaddy Email",
    "emailsrvr.com": "Rackspace Email",
    "mailgun.org": "Mailgun",
    "sendgrid.net": "SendGrid",
    "amazonses.com": "Amazon SES",
    "mail.protection.outlook.com": "Microsoft 365",
    "fastmail.com": "Fastmail",
    "messagingengine.com": "Fastmail",
    "icloud.com": "iCloud Mail",
    "yandex.net": "Yandex Mail",
    "mailchannels.net": "MailChannels",
    "spf.protection.outlook.com": "Microsoft 365",
    "_spf.google.com": "Google Workspace",
    "servers.mcsv.net": "Mailchimp",
    "spf.mandrillapp.com": "Mailchimp/Mandrill",
    "mktomail.com": "Marketo",
    "salesforce.com": "Salesforce",
    "hubspot.com": "HubSpot",
    "sendinblue.com": "Brevo",
    "mailjet.com": "Mailjet",
    "postmarkapp.com": "Postmark",
    "dmarcian.com": "dmarcian (DMARC reporting)",
    "valimail.com": "Valimail (DMARC reporting)",
    "vali.email": "Valimail (DMARC reporting)",
    "agari.com": "Agari (DMARC reporting)",
    "ondmarc.com": "Red Sift OnDMARC (DMARC reporting)",
    "dmarc.postmarkapp.com": "Postmark DMARC",
    "easydmarc.com": "EasyDMARC (DMARC reporting)",
    "rua.easydmarc.us": "EasyDMARC (DMARC reporting)",
}

# Reverse-DNS names from hosting providers are auto-generated and tell you
# only who owns the netblock, not who rents the server.
GENERIC_PTR_PATTERNS = [
    (re.compile(r"(^|\.)amazonaws\.com$"), "Amazon EC2 auto-generated rDNS"),
    (re.compile(r"(^|\.)googleusercontent\.com$"), "Google Cloud auto-generated rDNS"),
    (re.compile(r"(^|\.)linode\.com$|(^|\.)linodeusercontent\.com$"), "Linode auto-generated rDNS"),
    (re.compile(r"(^|\.)digitalocean\.com$"), "DigitalOcean auto-generated rDNS"),
    (re.compile(r"(^|\.)ovh\.net$|(^|\.)ovh\.ca$"), "OVH auto-generated rDNS"),
    (re.compile(r"(^|\.)hetzner\.com$|(^|\.)your-server\.de$|(^|\.)clients\.your-server\.de$"), "Hetzner auto-generated rDNS"),
    (re.compile(r"(^|\.)vultr\.com$|(^|\.)vultrusercontent\.com$"), "Vultr auto-generated rDNS"),
    (re.compile(r"(^|\.)cloudfront\.net$"), "Amazon CloudFront edge"),
    (re.compile(r"(^|\.)akamaitechnologies\.com$"), "Akamai edge"),
    (re.compile(r"(^|\.)1e100\.net$"), "Google edge"),
    (re.compile(r"static\..*\.(com|net)$"), "Generic static-IP rDNS"),
    (re.compile(r"\d{1,3}[-.]\d{1,3}[-.]\d{1,3}[-.]\d{1,3}"), "IP address embedded in hostname (auto-generated)"),
    (re.compile(r"^ip-?\d"), "IP-style hostname (auto-generated)"),
    (re.compile(r"\.(dynamic|dyn|dhcp|pool|cust|customer|client|clients)\."), "ISP customer/dynamic pool rDNS"),
]

# Netblock holders that rent address space to the public. An IP inside one of
# these blocks says "hosted at provider X", not "owned by the same people".
# Matched as whole words (see _has_keyword), so "colocation" does not fire on
# "Colombia Movil". Bare generic words such as "cloud", "server" and "colo"
# are deliberately absent: they matched far too many ordinary company names.
BULK_HOSTING_KEYWORDS = [
    "amazon", "aws", "google", "microsoft", "azure", "cloudflare", "fastly", "akamai",
    "digitalocean", "linode", "akamai connected cloud", "vultr", "choopa", "the constant company",
    "ovh", "hetzner", "leaseweb", "godaddy", "namecheap", "hostinger", "ionos", "1&1",
    "alibaba", "aliyun", "tencent", "huawei", "oracle", "ibm cloud", "softlayer",
    "rackspace", "contabo", "scaleway", "online s.a.s", "upcloud", "kamatera", "psychz",
    "quadranet", "colocrossing", "hostwinds", "m247", "datacamp", "cdn77", "edgecast",
    "stackpath", "sucuri", "imperva", "incapsula", "wix", "squarespace", "shopify",
    "webflow", "vercel", "netlify", "github", "heroku", "salesforce", "hosting",
    "web hosting", "cloud services", "cloud computing", "datacenter", "data center",
    "colocation", "vps", "dedicated servers",
]

# Words too generic to count as "the seed's name appears in the netblock
# holder". Without this, seed online.com would match "Hetzner Online GmbH"
# and data.com would match "Amazon Data Services".
GENERIC_NAME_WORDS = {
    "online", "data", "cloud", "net", "network", "networks", "web", "host", "hosting", "server",
    "servers", "service", "services", "internet", "digital", "global", "tech", "technology",
    "technologies", "systems", "system", "group", "telecom", "communications", "solutions",
    "media", "mail", "info", "home", "shop", "store", "world", "international", "company",
    "corp", "inc", "limited", "ltd", "llc", "gmbh", "business", "center", "centre",
}
SEED_NAME_MIN_LEN = 4

# Privacy / proxy services that stand in for the real registrant.
PRIVACY_PROXY_KEYWORDS = [
    "privacy", "proxy", "whoisguard", "withheldforprivacy", "domainsbyproxy", "contactprivacy",
    "privacyprotect", "identity protect", "redacted", "gdpr", "data protected", "perfect privacy",
    "anonymize", "privateregistration", "whoisprivacy", "identity shield", "registrant of",
]

# Registrable-domain logic uses the Public Suffix List via tldextract, from
# the snapshot bundled inside the package: no network fetch, no cache writes.
# If tldextract is missing, a small built-in list of two-level suffixes is
# used instead so the tool still runs (less accurately).
try:
    import tldextract as _tldextract
    _PSL = _tldextract.TLDExtract(cache_dir=None, suffix_list_urls=(), fallback_to_snapshot=True)
except Exception:  # ImportError, or an unexpected packaging problem
    _PSL = None

# Offline fallback only. Not exhaustive.
FALLBACK_TWO_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "me.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.za", "org.za", "co.in", "net.in", "org.in", "co.jp", "ne.jp", "or.jp",
    "com.br", "com.mx", "com.ar", "com.cn", "com.hk", "com.tr",
    "com.sg", "gov.sg", "edu.sg", "org.sg", "net.sg", "per.sg",
    "co.il", "co.kr", "com.tw", "com.my", "gov.my", "com.ph", "com.pk", "com.ng",
    "org.br", "net.br", "gov.br", "gov.in", "gov.cn", "gov.hk", "gov.za",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _split_registrable(hostname: str) -> Tuple[str, str]:
    """Return (label, suffix) for the registrable part, e.g. ('moh', 'gov.sg').

    Either part may be empty for IPs, bare suffixes or single-label names.
    """
    h = hostname.lower().strip().rstrip(".")
    if not h or _is_ip(h):
        return "", ""
    if _PSL is not None:
        r = _PSL(h)
        if r.suffix:
            return r.domain, r.suffix
        # Not on the PSL (.test, .internal, .lan ...). The PSL's default rule
        # "*" treats an unknown TLD as a one-label public suffix; do the same.
    parts = h.split(".")
    if _PSL is not None:
        return (parts[-2], parts[-1]) if len(parts) >= 2 else ("", "")
    if len(parts) >= 3 and ".".join(parts[-2:]) in FALLBACK_TWO_LEVEL_SUFFIXES:
        return parts[-3], ".".join(parts[-2:])
    if len(parts) >= 2:
        return parts[-2], parts[-1]
    return "", ""


def registrable_domain(hostname: str) -> str:
    """Return the owner-level part of a hostname, e.g. mail.example.co.uk -> example.co.uk.

    IPs, bare public suffixes and single-label names are returned unchanged.
    """
    h = hostname.lower().strip().rstrip(".")
    label, suffix = _split_registrable(h)
    if label and suffix:
        return f"{label}.{suffix}"
    return h


def registrable_label(hostname: str) -> str:
    """The name part of the registrable domain: 'moh' for www.shop-a.co.uk."""
    return _split_registrable(hostname)[0]


def host_in_domain(hostname: str, domain: str) -> bool:
    """True if hostname is `domain` itself or a name under it (label-boundary suffix match)."""
    h = hostname.lower().strip().rstrip(".")
    d = domain.lower().strip().rstrip(".")
    return bool(d) and (h == d or h.endswith("." + d))


def _has_keyword(text: str, keyword: str) -> bool:
    """Whole-word match: the keyword must not be glued to other letters or digits."""
    return re.search(r"(?<![a-z0-9])" + re.escape(keyword) + r"(?![a-z0-9])", text) is not None


def same_owner(host_a: str, host_b: str) -> bool:
    return registrable_domain(host_a) == registrable_domain(host_b)


# Extra ranges used only by the offline demo (fictional CDN in documentation space).
_EXTRA_CDN_RANGES: dict = {}


def set_extra_cdn_ranges(ranges: dict) -> None:
    """Offline demo hook: {provider: [cidr, ...]} added to the published ranges. {} resets."""
    global _EXTRA_CDN_RANGES
    _EXTRA_CDN_RANGES = dict(ranges or {})


def shared_cdn_provider(ip: str) -> Optional[str]:
    """Return the CDN name if `ip` falls inside a published shared range."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for provider, ranges in list(SHARED_CDN_RANGES.items()) + list(_EXTRA_CDN_RANGES.items()):
        for cidr in ranges:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return provider
    return None


def _match_provider(hostname: str, table: dict, label_patterns: Optional[dict] = None) -> Optional[str]:
    """Return the provider label if hostname is the provider's domain or a name under it.

    Suffix match on a label boundary only: mx.google.com.evil.net and
    ns1.myname.com do NOT match google.com / name.com.
    """
    h = hostname.lower().strip().rstrip(".")
    # Longest key first, so "mail.protection.outlook.com" wins over "outlook.com".
    for domain in sorted(table, key=len, reverse=True):
        if host_in_domain(h, domain):
            return table[domain]
    if label_patterns:
        label = registrable_label(h)
        for pattern, name in label_patterns.items():
            if label and re.fullmatch(pattern, label):
                return name
    return None


def generic_ptr_reason(hostname: str) -> Optional[str]:
    h = hostname.lower().rstrip(".")
    for pattern, label in GENERIC_PTR_PATTERNS:
        if pattern.search(h):
            return label
    return None


def _holder_matches_seed(holder_text: str, registrant_org: str, seed: str) -> bool:
    """Does the netblock holder name the seed's organisation?

    Registrant org: must appear as whole words and not be a privacy placeholder.
    Seed name: the full registrable label (e.g. 'ietf' for ietf.org), at least
    SEED_NAME_MIN_LEN characters, not a generic word, matched as a whole word.
    """
    holder_text = holder_text.lower()
    org = (registrant_org or "").lower().strip()
    if (len(org) >= SEED_NAME_MIN_LEN and org not in GENERIC_NAME_WORDS
            and not any(k in org for k in PRIVACY_PROXY_KEYWORDS) and _has_keyword(holder_text, org)):
        return True
    label = registrable_label(seed)
    if len(label) < SEED_NAME_MIN_LEN or label in GENERIC_NAME_WORDS:
        return False
    return _has_keyword(holder_text, label)


# ---------------------------------------------------------------------------
# The rating function
# ---------------------------------------------------------------------------


def rate(link: Link, seed: str) -> Link:
    """Fill in confidence, reason and flags for one link. Returns the same object."""
    lt = link.link_type
    related = link.related_entity
    conf, reason, flags = "Medium", "Unrated link type; review manually.", []

    if lt in ("dns_a", "dns_aaaa"):
        cdn = shared_cdn_provider(related)
        if cdn:
            conf = "Low"
            reason = f"IP is in a published {cdn} anycast/CDN range shared by many unrelated tenants."
            flags.append("shared_cdn")
        elif link.meta.get("seed_owned_host") and link.meta.get("outside_seed_ips"):
            # Upgraded to High in rate_all only if PTR or RDAP confirms the IP.
            conf = "Medium"
            reason = ("A host under the seed's own domain resolves to a non-CDN IP the seed itself does not use; "
                      "this may be the real origin server behind a CDN. Not yet confirmed by PTR or RDAP. Verify.")
            flags.append("possible_origin_ip")
        elif "seed_owned_host" in link.meta and not link.meta.get("seed_owned_host"):
            # A third-party name found via CT and resolved in the IP pivot.
            conf = "Medium"
            reason = ("DNS answer (recursive resolver) for a related third-party domain. The IP has not been "
                      "checked against PTR/RDAP here, so shared or cloud hosting is not ruled out. Verify.")
            flags.append("unverified_third_party_ip")
        else:
            conf = "High"
            reason = ("DNS answer (recursive resolver) ties the domain directly to this IP. "
                      "Check the RDAP netblock for bulk hosting before pivoting.")

    elif lt == "dns_ptr":
        # source_entity is the IP, related_entity is the hostname from rDNS
        generic = generic_ptr_reason(related)
        if same_owner(related, seed):
            conf = "High"
            reason = "Reverse DNS returns a hostname under the seed's own domain; consistent forward/reverse ownership."
        elif generic:
            conf = "Low"
            reason = f"{generic}; identifies the hosting provider, not the tenant."
            flags.append("generic_hosting_rdns")
        else:
            conf = "Medium"
            reason = "Reverse DNS names a different organisation's hostname; could be shared hosting or a genuine related asset. Verify."

    elif lt == "dns_mx":
        provider = _match_provider(related, SHARED_MAIL_PROVIDERS)
        if same_owner(related, seed):
            conf = "High"
            reason = "Mail is handled by a host under the seed's own domain (self-hosted mail)."
        elif provider:
            conf = "Low"
            reason = f"Mail is handled by {provider}, a shared provider used by many unrelated domains."
            flags.append("shared_mail_provider")
        else:
            conf = "Medium"
            reason = "Mail is handled by a third-party host not in the known-provider list; could be a smaller shared provider or a related organisation."

    elif lt == "dns_ns":
        provider = _match_provider(related, SHARED_NS_PROVIDERS, SHARED_NS_LABEL_PATTERNS)
        if same_owner(related, seed):
            conf = "High"
            reason = "Nameserver is under the seed's own domain (self-hosted DNS); strong ownership indicator."
        elif provider:
            conf = "Low"
            reason = f"Nameserver belongs to {provider}, a managed DNS service shared by many unrelated domains."
            flags.append("shared_dns_provider")
        else:
            conf = "Medium"
            reason = "Nameserver is operated by a third party not in the known-provider list; vanity or reseller DNS is common. Verify."

    elif lt in ("spf_include", "spf_redirect"):
        provider = _match_provider(related, SHARED_MAIL_PROVIDERS)
        if same_owner(related, seed):
            conf = "High"
            reason = "SPF delegates to a host under the seed's own domain."
        elif provider:
            conf = "Low"
            reason = f"SPF authorises {provider}, a shared sending service."
            flags.append("shared_mail_provider")
        else:
            conf = "Medium"
            reason = "SPF authorises an unlisted third party to send mail as this domain; indicates a business relationship. Verify who operates it."

    elif lt == "dmarc_report_recipient":
        provider = _match_provider(related, SHARED_MAIL_PROVIDERS)
        if same_owner(related, seed):
            conf = "High"
            reason = "DMARC reports go to an address under the seed's own domain."
        elif provider:
            conf = "Low"
            reason = f"DMARC reports go to {provider}, a shared reporting service."
            flags.append("shared_mail_provider")
        else:
            conf = "Medium"
            reason = "DMARC reports go to a third-party domain; often an MSSP, parent company or consultant. Verify."

    elif lt == "dns_cname":
        if same_owner(related, seed):
            conf = "High"
            reason = "CNAME points inside the seed's own domain."
        else:
            conf = "Medium"
            reason = "CNAME points to a third-party host; usually a SaaS or CDN customer relationship. Verify."

    elif lt == "ct_subdomain":
        conf = "High"
        reason = "A CA issued a certificate for this name under the seed domain; the requester proved control of it."
        if link.meta.get("expired"):
            reason += " Certificate has expired, so the name may no longer be in use."
            flags.append("expired_certificate")

    elif lt == "ct_shared_certificate":
        san_count = int(link.meta.get("san_count", 0))
        if link.meta.get("is_bulk"):
            conf = "Low"
            reason = (f"Certificate carries {san_count} names and looks CDN/hosting-managed; such certificates "
                      "bundle unrelated customers together.")
            flags.append("shared_bulk_certificate")
        elif san_count > 20:
            conf = "Medium"
            reason = (f"Certificate carries {san_count} names; large SAN lists are often a hosting provider's "
                      "multi-tenant certificate. Verify the requester.")
            flags.append("large_san_list")
        else:
            conf = "High"
            reason = ("Both names sit on the same certificate; the requester proved control of both at issuance "
                      "(CA domain validation).")
        if link.meta.get("expired"):
            if conf == "High":
                conf = "Medium"
            reason += " Certificate has expired, so the relationship may be historical; confirm it still holds."
            flags.append("expired_certificate")

    elif lt == "rdap_registrar":
        conf = "Low"
        reason = "Registrar is shared by millions of unrelated domains; useful only in combination with other overlaps."
        flags.append("shared_registrar")

    elif lt == "rdap_nameserver":
        # Same rules as DNS NS: the registry's view of the delegation.
        provider = _match_provider(related, SHARED_NS_PROVIDERS, SHARED_NS_LABEL_PATTERNS)
        if same_owner(related, seed):
            conf, reason = "High", "Registry lists a nameserver under the seed's own domain (self-hosted DNS)."
        elif provider:
            conf = "Low"
            reason = f"Registry lists a {provider} nameserver, a managed DNS service shared by many unrelated domains."
            flags.append("shared_dns_provider")
        else:
            conf, reason = "Medium", "Registry lists a third-party nameserver not in the known-provider list. Verify the operator."

    elif lt.startswith("rdap_") and lt.endswith("_email"):
        low = related.lower()
        if any(k in low for k in PRIVACY_PROXY_KEYWORDS):
            conf = "Low"
            reason = "Contact email belongs to a privacy/proxy service that fronts for many unrelated registrants."
            flags.append("privacy_proxy")
        elif low.split("@")[-1] == registrable_domain(seed) or same_owner(low.split("@")[-1], seed):
            conf, reason = "Medium", "Contact email is under the seed's own domain; confirms ownership but is not a pivot to anything new."
        else:
            conf = "Medium"
            reason = ("Unredacted contact email at a different domain. Searching other registrations for this "
                      "address is a classic pivot, but it is often a registrar, MSP or hosting-company mailbox. Verify.")

    elif lt.startswith("rdap_") and lt.endswith("_org"):
        low = related.lower()
        if any(k in low for k in PRIVACY_PROXY_KEYWORDS):
            conf = "Low"
            reason = "Organisation field names a privacy/proxy service, not the real registrant."
            flags.append("privacy_proxy")
        else:
            conf = "Medium"
            reason = "Unredacted organisation name. Pivot by searching other registrations for it, but names are self-declared and easy to fake."

    elif lt == "rdap_netblock":
        owner = str(link.meta.get("owner", "")).lower()
        name = str(link.meta.get("name", "")).lower()
        reg_org = str(link.meta.get("registrant_org", "")).lower()
        holder_text = f"{owner} {name}"
        if _holder_matches_seed(holder_text, reg_org, seed) and not link.meta.get("related_ip"):
            conf = "High"
            reason = "Netblock holder name matches the seed's registrant/name; the IP space appears dedicated to the same organisation."
            flags.append("dedicated_netblock")
        elif any(_has_keyword(holder_text, k) for k in BULK_HOSTING_KEYWORDS):
            conf = "Low"
            reason = f"Netblock holder '{link.meta.get('owner') or link.meta.get('name')}' is a hosting/cloud provider; many unrelated tenants share this space."
            flags.append("bulk_hosting_netblock")
        else:
            conf = "Medium"
            reason = "Netblock holder is neither the seed organisation nor a known hosting provider; could be an ISP, a reseller or a related entity. Verify."

    elif lt == "shared_ip":
        # Final rating is set in rate_all, once the IP's own links (PTR, RDAP) are rated.
        conf = "Medium"
        reason = ("Both domains resolve to the same IP address right now, but neither PTR nor RDAP confirms the IP "
                  "is dedicated to the seed; shared hosting is not ruled out. Verify.")

    link.confidence = conf
    link.reason = reason
    link.flags = flags
    return link


def rate_all(links: List[Link], seed: str) -> List[Link]:
    """Rate every link, then apply cross-link adjustments.

    Cross-link rule 1: if reverse DNS shows an IP is on a cloud/hosting
    provider, the domain -> IP link drops from High to Medium. The IP is
    probably dedicated to one tenant today, but cloud IPs are reassigned
    often, so historical pivots on it are less trustworthy.
    """
    for l in links:
        rate(l, seed)

    # What PTR and RDAP say about each IP.
    cloud_ips = {l.source_entity for l in links
                 if l.link_type == "dns_ptr" and "generic_hosting_rdns" in l.flags}
    bulk_ips = {l.source_entity for l in links
                if l.link_type == "rdap_netblock" and "bulk_hosting_netblock" in l.flags}
    # "Confirmed" = reverse DNS under the seed's own domain, or an RDAP netblock
    # whose holder matches the seed organisation.
    confirmed_ips = {l.source_entity for l in links
                     if (l.link_type == "dns_ptr" and l.confidence == "High")
                     or (l.link_type == "rdap_netblock" and "dedicated_netblock" in l.flags)}

    for l in links:
        if l.link_type not in ("dns_a", "dns_aaaa"):
            continue
        ip = l.related_entity
        # Cross-link rule 1: reverse DNS shows a cloud/hosting provider IP.
        if ip in cloud_ips and l.confidence != "Low" and "cloud_hosted_ip" not in l.flags:
            l.confidence = "Medium"
            l.reason = ("DNS answer (recursive resolver), but reverse DNS shows a cloud/hosting provider IP; "
                        "likely dedicated today, yet cloud IPs are reassigned often. Verify before pivoting.")
            l.flags.append("cloud_hosted_ip")
        # Cross-link rule 3: RDAP says the IP sits in a hosting/cloud netblock.
        elif ip in bulk_ips and l.confidence != "Low" and "cloud_hosted_ip" not in l.flags:
            l.confidence = "Medium"
            l.reason = ("DNS answer (recursive resolver), but RDAP shows the IP belongs to a hosting/cloud provider's "
                        "netblock; shared or reassignable space. Verify before pivoting.")
            l.flags.append("cloud_hosted_ip")
        # Possible origin IP: only High once PTR or RDAP confirms it belongs to the seed.
        elif "possible_origin_ip" in l.flags and ip in confirmed_ips:
            l.confidence = "High"
            l.reason = ("A host under the seed's own domain resolves to a non-CDN IP the seed itself does not use, "
                        "and PTR/RDAP ties that IP to the seed; likely the real origin server behind a CDN.")
            l.flags.append("origin_confirmed")

    # Cross-link rule 2: a shared-IP link is only as strong as the IP itself.
    ip_rating = {}
    for l in links:
        if l.link_type in ("dns_a", "dns_aaaa") and l.source_entity == seed:
            ip_rating[l.related_entity] = (l.confidence, l.flags)
    for l in links:
        if l.link_type != "shared_ip":
            continue
        ip = str(l.meta.get("ip", ""))
        conf, flags = ip_rating.get(ip, ("Medium", []))
        if "shared_cdn" in flags:
            l.confidence = "Low"
            l.reason = "Both domains resolve to the same CDN anycast IP; thousands of unrelated sites share it."
            l.flags.append("shared_cdn")
        elif "cloud_hosted_ip" in flags or ip in cloud_ips or ip in bulk_ips:
            l.confidence = "Medium"
            l.reason = ("Both domains resolve to the same cloud-provider IP; probably one tenant today, "
                        "but shared load balancers and IP reuse are common. Verify.")
            l.flags.append("cloud_hosted_ip")
        elif ip in confirmed_ips:
            l.confidence = "High"
            l.reason = ("Both domains resolve to the same IP right now, and PTR/RDAP ties that IP to the seed "
                        "organisation; the other domain is likely hosted on the seed's own infrastructure.")
        # otherwise keep the Medium default from rate()
    return links


def confidence_counts(links: List[Link]) -> Tuple[int, int, int]:
    h = sum(1 for l in links if l.confidence == "High")
    m = sum(1 for l in links if l.confidence == "Medium")
    lo = sum(1 for l in links if l.confidence == "Low")
    return h, m, lo
