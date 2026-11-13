# Evidence — provenance and sanitisation notes

| File | Origin | Notes |
|---|---|---|
| `crt-subdomains-sample.txt` | crt.sh JSON API, query `%.upm.edu.my` (13 Nov 2026) | 232 unique hostnames returned; the published file is a sample. Email-like certificate entries were filtered out; the full set is kept private. |
| `whois-upm-excerpt.txt` | MYNIC registry record via ICANN Lookup (13 Nov 2026) | Public registry data; personal registrant fields are REDACTED by the registry itself. |

## What is deliberately excluded

- **Have I Been Pwned results for my own address** — personal breach data has
  no place in a public repository, even though the lab required the check.
- **The sample photo itself** — it carries GPS metadata, so it is described in
  the write-up but not published.
- **The complete 232-name CT list** — the write-up needs the evidence, not the
  whole enumeration; the sample is sufficient to verify the finding.

## Sanitisation

- All sources are public by design (certificate transparency logs, registry
  records) or self-referential (own email, teaching sample file).
- No scanning or probing of the target took place; nothing here could be used
  to attack the named organisation that a public certificate log does not
  already reveal.
