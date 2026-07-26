# Result quality and identity attribution

DeepVault treats collector output as observations, not automatically as facts
about a person. The evidence-quality gate runs after connector normalization and
before correlation, graph construction, and report generation.

## Presentation categories

| Category | Meaning | Default presentation |
| --- | --- | --- |
| Corroborated facts | Evidence already carries a confirmed or defensibly corroborated status | Prominent |
| Probable profiles | Multiple observed public attributes match supplied case context | Prominent, still requires analyst review |
| Possible profiles | Limited observed context matches the target | Prominent with limitations |
| Defensive exposure | Public breach or exposure metadata | Prominent |
| Service signals | An authorized email produced an ambiguous provider-presence signal | Collapsed |
| Unverified profiles | Username-existence result without observed profile-content matches | Collapsed |
| Quarantined candidates | Sensitive profile candidate without strong corroboration | Collapsed and never attributed |
| Rejected observations | Invalid URL, non-profile endpoint, soft-404, generic redirect, negative disambiguation, or similar failure | Audit ledger only |

## Confidence rules

- Observation confidence and identity confidence are stored separately.
- An unvalidated username-only candidate is capped at `0.25`.
- An ambiguous service-presence signal is capped at `0.30`.
- A sensitive username-only candidate is capped at `0.15` and quarantined.
- Sherlock, Maigret, Blackbird, and WhatsMyName belong to the same
  `username-catalogue` provenance family. Agreement between them does not count
  as independent identity corroboration.
- Name, employer, location, and explicitly observed profile usernames may
  increase identity confidence when they match analyst-supplied case context.
- A query echo from a collector is not an observed profile attribute.
- A single source cannot automatically confirm profile ownership.

## URL normalization

Profile URLs are normalized before deduplication:

- scheme and hostname casing are normalized;
- common `www` and mobile host aliases are merged;
- tracking parameters are removed;
- identity-bearing query parameters are retained;
- YouTube `/@handle` and `/@handle/about` variants are merged.

The original observations remain inside the correlated provenance metadata.

## Coverage-aware conclusions

If selected sources are unavailable, failed, or not queried, DeepVault reports
coverage as `partial` or `insufficient`. In the absence of concrete exposure
evidence, incomplete coverage produces an `unknown` exposure assessment rather
than `low`.

`no_results` means that a source completed without normalized evidence. It does
not prove absence.

## Input quality

- Additional known usernames can be supplied as separate seeds.
- Reserved demonstration domains such as `example.com` are rejected.
- Shodan and Censys accept only literal public IP addresses.
- Domains and IPs must be omitted unless they are explicitly authorized.

## Remaining follow-up work

The quality gate is intentionally deterministic and offline. Higher-confidence
automation should be added in separate changes:

1. A bounded public-page validator that detects soft-404 pages, generic
   redirects, canonical profile URLs, JSON-LD, and OpenGraph profile fields.
2. Per-site validation fixtures to prevent regressions when publishers change
   their layouts.
3. Analyst accept/reject decisions that persist as signed case-local
   disambiguation evidence.
4. Redis caching for validated public pages with source-specific TTLs.
5. Source-health and coverage dashboards with connector version metadata.
6. Non-root, least-privilege collector containers.

Public-page validation must remain rate-limited, robots-aware, passive by
default, and constrained to the case authorization.
