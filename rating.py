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
    "awsdns-": "Amazon Route 53",
    "googledomains.com": "Google Domains DNS",
    "google.com": "Google Cloud DNS",
    "domaincontrol.com": "GoDaddy DNS",
    "registrar-servers.com": "Namecheap DNS",
    "nsone.net": "NS1",
    "dnsimple.com": "DNSimple",
    "ultradns": "UltraDNS",
    "akam.net": "Akamai DNS",
    "azure-dns": "Azure DNS",
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
    "zohomail": "Zoho Mail",
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
    (re.compile(r"amazonaws\.com$"), "Amazon EC2 auto-generated rDNS"),
    (re.compile(r"googleusercontent\.com$"), "Google Cloud auto-generated rDNS"),
    (re.compile(r"linode\.com$|linodeusercontent\.com$"), "Linode auto-generated rDNS"),
    (re.compile(r"digitalocean\.com$"), "DigitalOcean auto-generated rDNS"),
    (re.compile(r"ovh\.net$|ovh\.ca$"), "OVH auto-generated rDNS"),
    (re.compile(r"hetzner\.com$|your-server\.de$|clients\.your-server\.de$"), "Hetzner auto-generated rDNS"),
    (re.compile(r"vultr\.com$|vultrusercontent\.com$"), "Vultr auto-generated rDNS"),
    (re.compile(r"cloudfront\.net$"), "Amazon CloudFront edge"),
    (re.compile(r"akamaitechnologies\.com$"), "Akamai edge"),
    (re.compile(r"1e100\.net$"), "Google edge"),
    (re.compile(r"static\..*\.(com|net)$"), "Generic static-IP rDNS"),
    (re.compile(r"\d{1,3}[-.]\d{1,3}[-.]\d{1,3}[-.]\d{1,3}"), "IP address embedded in hostname (auto-generated)"),
    (re.compile(r"^ip-?\d"), "IP-style hostname (auto-generated)"),
    (re.compile(r"\.(dynamic|dyn|dhcp|pool|cust|customer|client|clients)\."), "ISP customer/dynamic pool rDNS"),
]

# Two-level public suffixes we handle when working out the "registrable"
# part of a domain. Not exhaustive; enough for common cases. (Stage 2 or 3
# could swap in a full Public Suffix List if needed.)
TWO_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "me.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.za", "org.za", "co.in", "net.in", "org.in", "co.jp", "ne.jp", "or.jp",
    "com.br", "com.mx", "com.ar", "com.cn", "com.hk", "com.sg", "com.tr",
    "co.il", "co.kr", "com.tw", "com.my", "com.ph", "com.pk", "com.ng",
    "gov.au", "org.br", "net.br",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def registrable_domain(hostname: str) -> str:
    """Return the owner-level part of a hostname, e.g. mail.example.co.uk -> example.co.uk."""
    h = hostname.lower().rstrip(".")
    parts = h.split(".")
    if len(parts) <= 2:
        return h
    if ".".join(parts[-2:]) in TWO_LEVEL_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def same_owner(host_a: str, host_b: str) -> bool:
    return registrable_domain(host_a) == registrable_domain(host_b)


def shared_cdn_provider(ip: str) -> Optional[str]:
    """Return the CDN name if `ip` falls inside a published shared range."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for provider, ranges in SHARED_CDN_RANGES.items():
        for cidr in ranges:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return provider
    return None


def _match_provider(hostname: str, table: dict) -> Optional[str]:
    h = hostname.lower().rstrip(".")
    for needle, label in table.items():
        if needle in h:
            return label
    return None


def generic_ptr_reason(hostname: str) -> Optional[str]:
    h = hostname.lower().rstrip(".")
    for pattern, label in GENERIC_PTR_PATTERNS:
        if pattern.search(h):
            return label
    return None


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
        else:
            conf = "High"
            reason = ("Authoritative DNS answer ties the domain directly to this IP. "
                      "Check for bulk hosting before pivoting (RDAP in Stage 3).")

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
        provider = _match_provider(related, SHARED_NS_PROVIDERS)
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
    cloud_ips = {l.source_entity for l in links
                 if l.link_type == "dns_ptr" and "generic_hosting_rdns" in l.flags}
    for l in links:
        if l.link_type in ("dns_a", "dns_aaaa") and l.confidence == "High" and l.related_entity in cloud_ips:
            l.confidence = "Medium"
            l.reason = ("Authoritative DNS answer, but reverse DNS shows a cloud/hosting provider IP; "
                        "likely dedicated today, yet cloud IPs are reassigned often. Verify before pivoting.")
            l.flags.append("cloud_hosted_ip")
    return links


def confidence_counts(links: List[Link]) -> Tuple[int, int, int]:
    h = sum(1 for l in links if l.confidence == "High")
    m = sum(1 for l in links if l.confidence == "Medium")
    lo = sum(1 for l in links if l.confidence == "Low")
    return h, m, lo
