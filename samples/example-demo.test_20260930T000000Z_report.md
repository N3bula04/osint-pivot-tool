# Infrastructure pivot report: `example-demo.test`

- **Run started:** 2026-09-30T00:00:00+00:00  
- **Run finished:** 2026-09-30T00:00:00+00:00  
- **Stage:** Stage 3 - DNS + certificate transparency + RDAP  
- **Method:** offline replay of committed fixtures; no network connections at all  
- **Data:** SYNTHETIC offline fixtures from `offline_demo/` (no network used); fictional/reserved names and documentation IP ranges only  
- **Cache:** 0 hit(s), 0 miss(es)  
- **Links CSV:** `example-demo.test_20260930T000000Z_links.csv`

> **SYNTHETIC DEMO.** Every name, IP address and registration record in this report comes from committed offline fixtures. The names use reserved or fictional domains and the IPs sit in documentation ranges (RFC 5737 / RFC 3849). Nothing here describes real infrastructure.

> **Analyst note.** Every link below is a lead, not a conclusion. Confidence reflects how well a single observation supports an infrastructure relationship; it is not an attribution. This tool does not name actors.

## Summary

| Metric | Value |
|---|---|
| Entities observed | 32 |
| Links | 38 |
| High confidence | 15 |
| Medium confidence | 17 |
| Low confidence (shared infrastructure) | 6 |
| Sources failed | 0 |
| Queries with no data | 14 |

## Certificate transparency

- Certificates matched: 5 (0 look like bulk/CDN-managed certificates)
- Unique names on those certificates: 8
- Names under the seed domain (subdomains): 3
- Other domains sharing a certificate with the seed: 4
- Top issuers: DEMO-R1 (5)
- Manual check: https://crt.sh/?q=example-demo.test

## IP pivot

- Discovered names resolved: 9 (skipped 0)
- Seed IPs: 3
- Other domains sharing an IP with the seed: 1
- **Seed-owned hosts on IPs outside the seed's own records** (possible origin infrastructure behind a CDN): api.example-demo.test -> 198.51.100.50; mx1.example-demo.test -> 192.0.2.25; ns1.example-demo.test -> 192.0.2.53

## Registration data (RDAP)

- Registrar: Demo Registrar (fictional) (IANA ID 9999)
- Registered: 2026-08-20 | Last changed: 2026-09-01 | Expires: 2027-08-20
- Domain age: 41 days  **(registered within the last 90 days)**
- Status: client transfer prohibited
- DNSSEC signed: False
- Registry nameservers: ns1.example-demo.test, ns2.dns-host-demo.test
- Registrant contact: fn=REDACTED FOR PRIVACY, org=Example Demo Ltd
- Technical contact: fn=Hostmaster, org==HYPERLINK("http://attacker.invalid/","click me"), email=hostmaster@msp-demo.test
- Manual check: https://rdap.org/domain/example-demo.test or https://lookup.icann.org/lookup?name=example-demo.test

## IP ownership (RDAP)

- `192.0.2.10` is in `192.0.2.0/26` (EXAMPLE-DEMO-NET), holder: Example Demo Ltd, country ZZ, type ASSIGNMENT
- `2001:db8:c10d::5` is in `2001:db8:c10d::/48` (DEMOCLOUD-V6), holder: Demo Cloud Hosting Inc (fictional), country ZZ, type ASSIGNMENT
- `203.0.113.140` is in `203.0.113.128/25` (DEMOCDN-EDGE), holder: DemoCDN Edge Hosting (fictional), country ZZ, type ASSIGNMENT
- `198.51.100.200` (IP of a related host) is in `198.51.100.128/25` (DEMOCLOUD-V4), holder: Demo Cloud Hosting Inc (fictional), country ZZ, type ASSIGNMENT

## Raw records observed

| Query | Answer |
|---|---|
| `example-demo.test A` | `192.0.2.10` |
| `example-demo.test A` | `203.0.113.140` |
| `example-demo.test AAAA` | `2001:db8:c10d::5` |
| `example-demo.test MX` | `10 mx1.example-demo.test.` |
| `example-demo.test MX` | `20 aspmx.l.google.com.mail-spoof.test.` |
| `example-demo.test NS` | `ns1.example-demo.test.` |
| `example-demo.test NS` | `ns2.dns-host-demo.test.` |
| `example-demo.test TXT` | `"demo-site-verification=synthetic-token-0001"` |
| `example-demo.test TXT` | `"v=spf1 mx include:_spf.salesforce.com.attacker.invalid include:mail.msp-demo.test -all"` |
| `_dmarc.example-demo.test TXT` | `"v=DMARC1; p=reject; rua=mailto:dmarc@reports.msp-demo.test"` |
| `192.0.2.10 PTR` | `web1.example-demo.test.` |
| `203.0.113.140 PTR` | `edge-140.democdn.test.` |
| `2001:db8:c10d::5 PTR` | *(no data)* |
| `crt.sh names under example-demo.test` | `api.example-demo.test` |
| `crt.sh names under example-demo.test` | `old.example-demo.test` |
| `crt.sh names under example-demo.test` | `www.example-demo.test` |
| `198.51.100.50 PTR` | *(no data)* |
| `192.0.2.25 PTR` | `mx1.example-demo.test.` |
| `192.0.2.53 PTR` | `ns1.example-demo.test.` |
| `rdap domain example-demo.test nameservers` | `ns1.example-demo.test` |
| `rdap domain example-demo.test nameservers` | `ns2.dns-host-demo.test` |

## Links (sorted by confidence)

| # | Source | Related entity | Link type | Confidence | Reason | Evidence | Data source |
|---|---|---|---|---|---|---|---|
| 1 | `example-demo.test` | `partner-demo.test` | ct_shared_certificate | **High** | Both names sit on the same certificate; the requester proved control of both at issuance (CA domain validation). | `crt.sh cert 9000003 (issuer 'DEMO-R1', valid 2026-07-15 to 2026-10-13, 2 names) lists both example-demo.test and partner-demo.test; seen on 1 certificate(s); https://crt.sh/?id=9000003` | Certificate Transparency (crt.sh) |
| 2 | `example-demo.test` | `api.example-demo.test` | ct_subdomain | **High** | A CA issued a certificate for this name under the seed domain; the requester proved control of it. | `crt.sh cert 9000002 (issuer 'DEMO-R1', valid 2026-08-05 to 2026-11-03) lists api.example-demo.test; seen on 1 certificate(s); https://crt.sh/?id=9000002` | Certificate Transparency (crt.sh) |
| 3 | `example-demo.test` | `old.example-demo.test` | ct_subdomain | **High** | A CA issued a certificate for this name under the seed domain; the requester proved control of it. Certificate has expired, so the name may no longer be in use. | `crt.sh cert 9000004 (issuer 'DEMO-R1', valid 2024-01-10 to 2024-04-09) lists old.example-demo.test; seen on 1 certificate(s); https://crt.sh/?id=9000004` | Certificate Transparency (crt.sh) |
| 4 | `example-demo.test` | `www.example-demo.test` | ct_subdomain | **High** | A CA issued a certificate for this name under the seed domain; the requester proved control of it. | `crt.sh cert 9000001 (issuer 'DEMO-R1', valid 2026-08-01 to 2026-10-30) lists www.example-demo.test; seen on 1 certificate(s); https://crt.sh/?id=9000001` | Certificate Transparency (crt.sh) |
| 5 | `example-demo.test` | `192.0.2.10` | dns_a | **High** | DNS answer (recursive resolver) ties the domain directly to this IP. Check the RDAP netblock for bulk hosting before pivoting. | `example-demo.test A -> 192.0.2.10` | DNS (system resolver via dnspython) |
| 6 | `mx1.example-demo.test` | `192.0.2.25` | dns_a | **High** | A host under the seed's own domain resolves to a non-CDN IP the seed itself does not use, and PTR/RDAP ties that IP to the seed; likely the real origin server behind a CDN. | `mx1.example-demo.test A -> 192.0.2.25` | DNS (system resolver via dnspython) |
| 7 | `ns1.example-demo.test` | `192.0.2.53` | dns_a | **High** | A host under the seed's own domain resolves to a non-CDN IP the seed itself does not use, and PTR/RDAP ties that IP to the seed; likely the real origin server behind a CDN. | `ns1.example-demo.test A -> 192.0.2.53` | DNS (system resolver via dnspython) |
| 8 | `example-demo.test` | `mx1.example-demo.test` | dns_mx | **High** | Mail is handled by a host under the seed's own domain (self-hosted mail). | `example-demo.test MX 10 mx1.example-demo.test` | DNS (system resolver via dnspython) |
| 9 | `example-demo.test` | `ns1.example-demo.test` | dns_ns | **High** | Nameserver is under the seed's own domain (self-hosted DNS); strong ownership indicator. | `example-demo.test NS ns1.example-demo.test` | DNS (system resolver via dnspython) |
| 10 | `192.0.2.25` | `mx1.example-demo.test` | dns_ptr | **High** | Reverse DNS returns a hostname under the seed's own domain; consistent forward/reverse ownership. | `192.0.2.25 PTR -> mx1.example-demo.test  (25.2.0.192.in-addr.arpa.)` | DNS (system resolver via dnspython) |
| 11 | `192.0.2.53` | `ns1.example-demo.test` | dns_ptr | **High** | Reverse DNS returns a hostname under the seed's own domain; consistent forward/reverse ownership. | `192.0.2.53 PTR -> ns1.example-demo.test  (53.2.0.192.in-addr.arpa.)` | DNS (system resolver via dnspython) |
| 12 | `192.0.2.10` | `web1.example-demo.test` | dns_ptr | **High** | Reverse DNS returns a hostname under the seed's own domain; consistent forward/reverse ownership. | `192.0.2.10 PTR -> web1.example-demo.test  (10.2.0.192.in-addr.arpa.)` | DNS (system resolver via dnspython) |
| 13 | `example-demo.test` | `ns1.example-demo.test` | rdap_nameserver | **High** | Registry lists a nameserver under the seed's own domain (self-hosted DNS). | `RDAP domain record for example-demo.test lists nameserver ns1.example-demo.test; https://rdap.org/domain/example-demo.test` | RDAP (registry/RIR via rdap.org) |
| 14 | `192.0.2.10` | `192.0.2.0/26` | rdap_netblock | **High** | Netblock holder name matches the seed's registrant/name; the IP space appears dedicated to the same organisation. | `RDAP ip record for 192.0.2.10: network 192.0.2.0/26 name='EXAMPLE-DEMO-NET' holder='Example Demo Ltd' country=ZZ; https://rdap.org/ip/192.0.2.10` | RDAP (registry/RIR via rdap.org) |
| 15 | `example-demo.test` | `partner-demo.test` | shared_ip | **High** | Both domains resolve to the same IP right now, and PTR/RDAP ties that IP to the seed organisation; the other domain is likely hosted on the seed's own infrastructure. | `example-demo.test A/AAAA -> 192.0.2.10; partner-demo.test A/AAAA -> 192.0.2.10 (both observed 2026-09-30T00:00:00+00:00)` | DNS (system resolver via dnspython) |
| 16 | `old.example-demo.test` | `legacy-partner.test` | ct_shared_certificate | **Medium** | Both names sit on the same certificate; the requester proved control of both at issuance (CA domain validation). Certificate has expired, so the relationship may be historical; confirm it still holds. | `crt.sh cert 9000004 (issuer 'DEMO-R1', valid 2024-01-10 to 2024-04-09, 2 names) lists both old.example-demo.test and legacy-partner.test; seen on 1 certificate(s); https://crt.sh/?id=9000004` | Certificate Transparency (crt.sh) |
| 17 | `example-demo.test` | `portal.fictional-partner.co.uk` | ct_shared_certificate | **Medium** | Both names sit on the same certificate; the requester proved control of both at issuance (CA domain validation). Certificate has expired, so the relationship may be historical; confirm it still holds. | `crt.sh cert 9000005 (issuer 'DEMO-R1', valid 2026-06-01 to 2026-08-30, 3 names) lists both example-demo.test and portal.fictional-partner.co.uk; seen on 1 certificate(s); https://crt.sh/?id=9000005` | Certificate Transparency (crt.sh) |
| 18 | `example-demo.test` | `www.fictional-supplier.co.uk` | ct_shared_certificate | **Medium** | Both names sit on the same certificate; the requester proved control of both at issuance (CA domain validation). Certificate has expired, so the relationship may be historical; confirm it still holds. | `crt.sh cert 9000005 (issuer 'DEMO-R1', valid 2026-06-01 to 2026-08-30, 3 names) lists both example-demo.test and www.fictional-supplier.co.uk; seen on 1 certificate(s); https://crt.sh/?id=9000005` | Certificate Transparency (crt.sh) |
| 19 | `example-demo.test` | `reports.msp-demo.test` | dmarc_report_recipient | **Medium** | DMARC reports go to a third-party domain; often an MSSP, parent company or consultant. Verify. | `_dmarc.example-demo.test TXT "v=DMARC1; p=reject; rua=mailto:dmarc@reports.msp-demo.test"` | DNS (system resolver via dnspython) |
| 20 | `partner-demo.test` | `192.0.2.10` | dns_a | **Medium** | DNS answer (recursive resolver) for a related third-party domain. The IP has not been checked against PTR/RDAP here, so shared or cloud hosting is not ruled out. Verify. | `partner-demo.test A -> 192.0.2.10` | DNS (system resolver via dnspython) |
| 21 | `legacy-partner.test` | `198.51.100.200` | dns_a | **Medium** | DNS answer (recursive resolver), but RDAP shows the IP belongs to a hosting/cloud provider's netblock; shared or reassignable space. Verify before pivoting. | `legacy-partner.test A -> 198.51.100.200` | DNS (system resolver via dnspython) |
| 22 | `api.example-demo.test` | `198.51.100.50` | dns_a | **Medium** | A host under the seed's own domain resolves to a non-CDN IP the seed itself does not use; this may be the real origin server behind a CDN. Not yet confirmed by PTR or RDAP. Verify. | `api.example-demo.test A -> 198.51.100.50` | DNS (system resolver via dnspython) |
| 23 | `example-demo.test` | `2001:db8:c10d::5` | dns_aaaa | **Medium** | DNS answer (recursive resolver), but RDAP shows the IP belongs to a hosting/cloud provider's netblock; shared or reassignable space. Verify before pivoting. | `example-demo.test AAAA -> 2001:db8:c10d::5` | DNS (system resolver via dnspython) |
| 24 | `example-demo.test` | `aspmx.l.google.com.mail-spoof.test` | dns_mx | **Medium** | Mail is handled by a third-party host not in the known-provider list; could be a smaller shared provider or a related organisation. | `example-demo.test MX 20 aspmx.l.google.com.mail-spoof.test` | DNS (system resolver via dnspython) |
| 25 | `example-demo.test` | `ns2.dns-host-demo.test` | dns_ns | **Medium** | Nameserver is operated by a third party not in the known-provider list; vanity or reseller DNS is common. Verify. | `example-demo.test NS ns2.dns-host-demo.test` | DNS (system resolver via dnspython) |
| 26 | `203.0.113.140` | `edge-140.democdn.test` | dns_ptr | **Medium** | Reverse DNS names a different organisation's hostname; could be shared hosting or a genuine related asset. Verify. | `203.0.113.140 PTR -> edge-140.democdn.test  (140.113.0.203.in-addr.arpa.)` | DNS (system resolver via dnspython) |
| 27 | `example-demo.test` | `ns2.dns-host-demo.test` | rdap_nameserver | **Medium** | Registry lists a third-party nameserver not in the known-provider list. Verify the operator. | `RDAP domain record for example-demo.test lists nameserver ns2.dns-host-demo.test; https://rdap.org/domain/example-demo.test` | RDAP (registry/RIR via rdap.org) |
| 28 | `example-demo.test` | `Example Demo Ltd` | rdap_registrant_org | **Medium** | Unredacted organisation name. Pivot by searching other registrations for it, but names are self-declared and easy to fake. | `RDAP domain record for example-demo.test: registrant contact org=Example Demo Ltd; https://rdap.org/domain/example-demo.test` | RDAP (registry/RIR via rdap.org) |
| 29 | `example-demo.test` | `hostmaster@msp-demo.test` | rdap_technical_email | **Medium** | Unredacted contact email at a different domain. Searching other registrations for this address is a classic pivot, but it is often a registrar, MSP or hosting-company mailbox. Verify. | `RDAP domain record for example-demo.test: technical contact email=hostmaster@msp-demo.test; https://rdap.org/domain/example-demo.test` | RDAP (registry/RIR via rdap.org) |
| 30 | `example-demo.test` | `=HYPERLINK("http://attacker.invalid/","click me")` | rdap_technical_org | **Medium** | Unredacted organisation name. Pivot by searching other registrations for it, but names are self-declared and easy to fake. | `RDAP domain record for example-demo.test: technical contact org==HYPERLINK("http://attacker.invalid/","click me"); https://rdap.org/domain/example-demo.test` | RDAP (registry/RIR via rdap.org) |
| 31 | `example-demo.test` | `_spf.salesforce.com.attacker.invalid` | spf_include | **Medium** | SPF authorises an unlisted third party to send mail as this domain; indicates a business relationship. Verify who operates it. | `example-demo.test TXT "v=spf1 mx include:_spf.salesforce.com.attacker.invalid include:mail.msp-demo.test -all"` | DNS (system resolver via dnspython) |
| 32 | `example-demo.test` | `mail.msp-demo.test` | spf_include | **Medium** | SPF authorises an unlisted third party to send mail as this domain; indicates a business relationship. Verify who operates it. | `example-demo.test TXT "v=spf1 mx include:_spf.salesforce.com.attacker.invalid include:mail.msp-demo.test -all"` | DNS (system resolver via dnspython) |
| 33 | `example-demo.test` | `203.0.113.140` | dns_a | **Low** | IP is in a published DemoCDN (fictional) anycast/CDN range shared by many unrelated tenants. | `example-demo.test A -> 203.0.113.140` | DNS (system resolver via dnspython) |
| 34 | `www.example-demo.test` | `203.0.113.140` | dns_a | **Low** | IP is in a published DemoCDN (fictional) anycast/CDN range shared by many unrelated tenants. | `www.example-demo.test A -> 203.0.113.140` | DNS (system resolver via dnspython) |
| 35 | `198.51.100.200` | `198.51.100.128/25` | rdap_netblock | **Low** | Netblock holder 'Demo Cloud Hosting Inc (fictional)' is a hosting/cloud provider; many unrelated tenants share this space. | `RDAP ip record for 198.51.100.200: network 198.51.100.128/25 name='DEMOCLOUD-V4' holder='Demo Cloud Hosting Inc (fictional)' country=ZZ; https://rdap.org/ip/198.51.100.200` | RDAP (registry/RIR via rdap.org) |
| 36 | `2001:db8:c10d::5` | `2001:db8:c10d::/48` | rdap_netblock | **Low** | Netblock holder 'Demo Cloud Hosting Inc (fictional)' is a hosting/cloud provider; many unrelated tenants share this space. | `RDAP ip record for 2001:db8:c10d::5: network 2001:db8:c10d::/48 name='DEMOCLOUD-V6' holder='Demo Cloud Hosting Inc (fictional)' country=ZZ; https://rdap.org/ip/2001:db8:c10d::5` | RDAP (registry/RIR via rdap.org) |
| 37 | `203.0.113.140` | `203.0.113.128/25` | rdap_netblock | **Low** | Netblock holder 'DemoCDN Edge Hosting (fictional)' is a hosting/cloud provider; many unrelated tenants share this space. | `RDAP ip record for 203.0.113.140: network 203.0.113.128/25 name='DEMOCDN-EDGE' holder='DemoCDN Edge Hosting (fictional)' country=ZZ; https://rdap.org/ip/203.0.113.140` | RDAP (registry/RIR via rdap.org) |
| 38 | `example-demo.test` | `Demo Registrar (fictional)` | rdap_registrar | **Low** | Registrar is shared by millions of unrelated domains; useful only in combination with other overlaps. | `RDAP domain record for example-demo.test: registrar 'Demo Registrar (fictional)', IANA ID 9999; https://rdap.org/domain/example-demo.test` | RDAP (registry/RIR via rdap.org) |

## Shared-infrastructure flags

These links were downgraded because the related entity is shared by many unrelated organisations. Pivoting on them will mostly return noise.

| Related entity | Flag | Reason |
|---|---|---|
| `old.example-demo.test` | expired_certificate | A CA issued a certificate for this name under the seed domain; the requester proved control of it. Certificate has expired, so the name may no longer be in use. |
| `192.0.2.25` | possible_origin_ip, origin_confirmed | A host under the seed's own domain resolves to a non-CDN IP the seed itself does not use, and PTR/RDAP ties that IP to the seed; likely the real origin server behind a CDN. |
| `192.0.2.53` | possible_origin_ip, origin_confirmed | A host under the seed's own domain resolves to a non-CDN IP the seed itself does not use, and PTR/RDAP ties that IP to the seed; likely the real origin server behind a CDN. |
| `192.0.2.0/26` | dedicated_netblock | Netblock holder name matches the seed's registrant/name; the IP space appears dedicated to the same organisation. |
| `legacy-partner.test` | expired_certificate | Both names sit on the same certificate; the requester proved control of both at issuance (CA domain validation). Certificate has expired, so the relationship may be historical; confirm it still holds. |
| `portal.fictional-partner.co.uk` | expired_certificate | Both names sit on the same certificate; the requester proved control of both at issuance (CA domain validation). Certificate has expired, so the relationship may be historical; confirm it still holds. |
| `www.fictional-supplier.co.uk` | expired_certificate | Both names sit on the same certificate; the requester proved control of both at issuance (CA domain validation). Certificate has expired, so the relationship may be historical; confirm it still holds. |
| `192.0.2.10` | unverified_third_party_ip | DNS answer (recursive resolver) for a related third-party domain. The IP has not been checked against PTR/RDAP here, so shared or cloud hosting is not ruled out. Verify. |
| `198.51.100.200` | unverified_third_party_ip, cloud_hosted_ip | DNS answer (recursive resolver), but RDAP shows the IP belongs to a hosting/cloud provider's netblock; shared or reassignable space. Verify before pivoting. |
| `198.51.100.50` | possible_origin_ip | A host under the seed's own domain resolves to a non-CDN IP the seed itself does not use; this may be the real origin server behind a CDN. Not yet confirmed by PTR or RDAP. Verify. |
| `2001:db8:c10d::5` | cloud_hosted_ip | DNS answer (recursive resolver), but RDAP shows the IP belongs to a hosting/cloud provider's netblock; shared or reassignable space. Verify before pivoting. |
| `203.0.113.140` | shared_cdn | IP is in a published DemoCDN (fictional) anycast/CDN range shared by many unrelated tenants. |
| `203.0.113.140` | shared_cdn | IP is in a published DemoCDN (fictional) anycast/CDN range shared by many unrelated tenants. |
| `198.51.100.128/25` | bulk_hosting_netblock | Netblock holder 'Demo Cloud Hosting Inc (fictional)' is a hosting/cloud provider; many unrelated tenants share this space. |
| `2001:db8:c10d::/48` | bulk_hosting_netblock | Netblock holder 'Demo Cloud Hosting Inc (fictional)' is a hosting/cloud provider; many unrelated tenants share this space. |
| `203.0.113.128/25` | bulk_hosting_netblock | Netblock holder 'DemoCDN Edge Hosting (fictional)' is a hosting/cloud provider; many unrelated tenants share this space. |
| `Demo Registrar (fictional)` | shared_registrar | Registrar is shared by millions of unrelated domains; useful only in combination with other overlaps. |

## Collection log

Every query made, including the ones that failed or returned nothing, so gaps are visible.

| Source | Query | Status | Detail | Timestamp |
|---|---|---|---|---|
| DNS | `example-demo.test A` | ok | 2 record(s) | 2026-09-30T00:00:00+00:00 |
| DNS | `example-demo.test AAAA` | ok | 1 record(s) | 2026-09-30T00:00:00+00:00 |
| DNS | `example-demo.test MX` | ok | 2 record(s) | 2026-09-30T00:00:00+00:00 |
| DNS | `example-demo.test NS` | ok | 2 record(s) | 2026-09-30T00:00:00+00:00 |
| DNS | `example-demo.test TXT` | ok | 2 record(s) | 2026-09-30T00:00:00+00:00 |
| DNS | `_dmarc.example-demo.test TXT` | ok | 1 record(s) | 2026-09-30T00:00:00+00:00 |
| DNS | `192.0.2.10 PTR` | ok | 1 record(s) | 2026-09-30T00:00:00+00:00 |
| DNS | `203.0.113.140 PTR` | ok | 1 record(s) | 2026-09-30T00:00:00+00:00 |
| DNS | `2001:db8:c10d::5 PTR` | nxdomain · | name does not exist | 2026-09-30T00:00:00+00:00 |
| crt.sh | `file:crtsh.json` | ok | 6 entries loaded from file (no network) | 2026-09-30T00:00:00+00:00 |
| DNS | `api.example-demo.test A` | ok | 1 record(s) | 2026-09-30T00:00:00+00:00 |
| DNS | `198.51.100.50 PTR` | nxdomain · | name does not exist | 2026-09-30T00:00:00+00:00 |
| DNS | `api.example-demo.test AAAA` | empty · | name exists but has no records of this type | 2026-09-30T00:00:00+00:00 |
| DNS | `legacy-partner.test A` | ok | 1 record(s) | 2026-09-30T00:00:00+00:00 |
| DNS | `legacy-partner.test AAAA` | empty · | name exists but has no records of this type | 2026-09-30T00:00:00+00:00 |
| DNS | `mx1.example-demo.test A` | ok | 1 record(s) | 2026-09-30T00:00:00+00:00 |
| DNS | `192.0.2.25 PTR` | ok | 1 record(s) | 2026-09-30T00:00:00+00:00 |
| DNS | `mx1.example-demo.test AAAA` | empty · | name exists but has no records of this type | 2026-09-30T00:00:00+00:00 |
| DNS | `ns1.example-demo.test A` | ok | 1 record(s) | 2026-09-30T00:00:00+00:00 |
| DNS | `192.0.2.53 PTR` | ok | 1 record(s) | 2026-09-30T00:00:00+00:00 |
| DNS | `ns1.example-demo.test AAAA` | empty · | name exists but has no records of this type | 2026-09-30T00:00:00+00:00 |
| DNS | `old.example-demo.test A` | nxdomain · | name does not exist | 2026-09-30T00:00:00+00:00 |
| DNS | `old.example-demo.test AAAA` | nxdomain · | name does not exist | 2026-09-30T00:00:00+00:00 |
| DNS | `partner-demo.test A` | ok | 1 record(s) | 2026-09-30T00:00:00+00:00 |
| DNS | `partner-demo.test AAAA` | empty · | name exists but has no records of this type | 2026-09-30T00:00:00+00:00 |
| DNS | `portal.fictional-partner.co.uk A` | nxdomain · | name does not exist | 2026-09-30T00:00:00+00:00 |
| DNS | `portal.fictional-partner.co.uk AAAA` | nxdomain · | name does not exist | 2026-09-30T00:00:00+00:00 |
| DNS | `www.example-demo.test A` | ok | 1 record(s) | 2026-09-30T00:00:00+00:00 |
| DNS | `www.example-demo.test AAAA` | empty · | name exists but has no records of this type | 2026-09-30T00:00:00+00:00 |
| DNS | `www.fictional-supplier.co.uk A` | nxdomain · | name does not exist | 2026-09-30T00:00:00+00:00 |
| DNS | `www.fictional-supplier.co.uk AAAA` | nxdomain · | name does not exist | 2026-09-30T00:00:00+00:00 |
| RDAP | `rdap domain example-demo.test` | ok | loaded from domain_example-demo.test.json (no network) | 2026-09-30T00:00:00+00:00 |
| RDAP | `rdap ip 192.0.2.10` | ok | loaded from ip_192.0.2.10.json (no network) | 2026-09-30T00:00:00+00:00 |
| RDAP | `rdap ip 2001:db8:c10d::5` | ok | loaded from ip_2001-db8-c10d--5.json (no network) | 2026-09-30T00:00:00+00:00 |
| RDAP | `rdap ip 203.0.113.140` | ok | loaded from ip_203.0.113.140.json (no network) | 2026-09-30T00:00:00+00:00 |
| RDAP | `rdap ip 198.51.100.200 (related host)` | ok | loaded from ip_198.51.100.200.json (no network) | 2026-09-30T00:00:00+00:00 |

## Link types in this report

- `ct_shared_certificate`: 4
- `ct_subdomain`: 3
- `dmarc_report_recipient`: 1
- `dns_a`: 8
- `dns_aaaa`: 1
- `dns_mx`: 2
- `dns_ns`: 2
- `dns_ptr`: 4
- `rdap_nameserver`: 2
- `rdap_netblock`: 4
- `rdap_registrant_org`: 1
- `rdap_registrar`: 1
- `rdap_technical_email`: 1
- `rdap_technical_org`: 1
- `shared_ip`: 1
- `spf_include`: 2
