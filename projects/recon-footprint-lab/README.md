# Passive OSINT Footprint Lab — Information Asymmetry on a University Domain

**Coursework:** WQE7011 Advanced Computer Penetration and Defence, Week-4 lab
("Reconnaissance &amp; Information Asymmetry — Self-Footprint Lab"), Universiti Malaya.
**Date:** 13 November 2026. **Live page:** [site version](./index.html).

## Objective

Measure what an attacker can learn about an organisation **without ever sending a
packet to it** (passive reconnaissance only), and turn every finding into a
defensive action. The lab uses a public university domain chosen by the lab
brief; all sources are public by design (certificate logs, DNS, registry
records) or operate on my own data (breach check, sample file metadata).

## Environment and tools

| Tool | Used for |
|---|---|
| [crt.sh](https://crt.sh) (web + JSON API, `curl` + `jq`) | Certificate Transparency subdomain search |
| MXToolbox | MX and DNS record lookups |
| ICANN Lookup → MYNIC RDAP/WHOIS | Registry and registrant records |
| Have I Been Pwned | Breach check of my own email address only |
| Metadata2Go | EXIF metadata of the lab sample photo |
| `curl`, `jq`, Python | Automation and JSON processing of public APIs |

No scanner, no probing tool and no packets directed at the target were used at
any point — every source above is public or self-referential.

## Method, step by step

1. **Certificate Transparency search.** Queried crt.sh for `%.upm.edu.my` via
   the JSON API and collected the hostnames from every logged certificate.
   Result: 232 unique hostnames. Classified names that suggest internal,
   test or administrative infrastructure.
2. **DNS and mail records.** Ran `mx:` and `dns:` lookups. Recorded the mail
   exchanger priority chain and the name servers.
3. **Registry records.** Resolved the domain through ICANN Lookup, which passes
   `.my` queries to MYNIC. Recorded registrar, creation and expiry dates, and
   which registrant fields are redacted.
4. **Breach exposure.** Checked my own email address in Have I Been Pwned (the
   lab rules allow only your own address). Noted the privacy design of the
   password checker: only the first five characters of a SHA-1 hash leave the
   device. The API's unauthenticated breach search returned an error response
   (the v3 API requires a key), so the check was completed through the website
   interface. My personal results are **deliberately excluded** from this
   public repository.
5. **File metadata.** Analysed the course sample photo with Metadata2Go and
   recorded every EXIF field that travels invisibly with the file.

## Results

| Finding | Attacker's view | Defensive action |
|---|---|---|
| 232 CT hostnames, including `eduvpn`, `jktmktest`, `admin.imputra`, `my-gitlab`, `idec-gitlab`, `ezadmin`, `ezproxy-admin`, `phpnew` — none advertised on the public website | A free map of hidden services, generated from certificates alone | Treat every certificate as public; choose hostnames that do not describe the service; retire old subdomains and certificates (attack surface management) |
| MX: own gateways `mailgw1`/`mailgw2` (priorities 1–2) in front of Google Workspace (`aspmx.l.google.com`) | Reveals who handles the organisation's email — phishing is easier to plan | Publish only necessary DNS records; enforce MFA; deploy SPF, DKIM and DMARC |
| NS: self-hosted `ns1`/`ns2`; WHOIS: registered 1996-12-18, expires 2032-12-18, registrar MYNIC; personal registrant fields REDACTED | A nearly 30-year-old domain with a huge historical attack surface | Registry privacy (redaction) is already in place; keep it on renewals |
| Breach data on staff accounts (checked on my own address only) | Credential-stuffing material | Watch breach lists for the organisation's domains; unique passwords + MFA |
| EXIF: GPS 3.1201 N, 101.6544 E (University of Malaya campus), Apple iPhone 14, taken 2026-03-02 09:14, artist "a.wahab" — the sample file itself labels this metadata as planted for teaching | One file quietly leaks location, device, time and author | Strip metadata before publishing any file |

## Evidence

| File | What it is |
|---|---|
| [`evidence/crt-subdomains-sample.txt`](evidence/crt-subdomains-sample.txt) | Sanitised sample of the crt.sh result set (email-like entries filtered out) |
| [`evidence/whois-upm-excerpt.txt`](evidence/whois-upm-excerpt.txt) | MYNIC registry record for the target domain (public data, fields redacted by the registry) |
| [`evidence/README.md`](evidence/README.md) | Provenance and sanitisation notes for every file |

## What I would do differently

- **Automate everything from the start.** The final approach (crt.sh JSON API
  via `curl` + `jq`) already replaces manual browsing; the same should be done
  for DNS history and for diffing two CT snapshots over time, where new
  certificates act as a change detector.
- **Add passive DNS history and SPF/DKIM/DMARC checks.** The defender-side
  controls were derived by hand here; they can be measured directly.
- **Resolve the HIBP API limitation earlier.** The unauthenticated breach API
  returned an error (key required), which cost a round trip before falling back
  to the website interface.

## Scope and ethics note

Passive-only: no packets were sent to the target; every source is public by
design or self-referential; the breach check used my own address; personal
results are excluded from this public repository. The lab target is a public
university domain named in the course brief.
