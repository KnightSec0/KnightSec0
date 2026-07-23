# Person-focused OSINT intelligence layer

This phase adds a normalized evidence pipeline for authorized investigations of
specific people. DeepVault treats every automated result as an observation, not
as proof that a person controls an account.

## Sources

- Sherlock: public username presence
- Maigret: independent username corroboration
- Holehe: public service-registration signals
- GitHub: public profile metadata only
- HIBP: breach metadata and data classes only
- Hunter: email validity and deliverability metadata
- Brave: candidate person results which always require identity disambiguation
- SpiderFoot: passive scans submitted to an explicitly configured instance
- Shodan and Censys: infrastructure metadata only when the IP is in the written
  authorization scope

Every connector emits the same evidence model: stable evidence ID, source,
source URL where available, collection time, reliability, confidence,
identity status, notes and minimized metadata.

## Confidence rules

A single username match begins as **possible**. Confidence rises only when
independent sources return the same canonical profile URL. Analysts must still
compare public profile attributes such as display name, employer, location and
cross-linked accounts.

## Structured reports

Set one provider:

```env
LLM_PROVIDER=none
# or: openai
# or: anthropic, gemini, ollama, openai-compatible
```

OpenAI uses the Responses API with structured JSON output and `store=False`.
Ollama uses the local `/api/chat` endpoint with the same report schema. By
default, identifiers are pseudonymized before any LLM call:

```env
LLM_INCLUDE_IDENTIFIERS=false
```

Every finding must contain at least one valid evidence ID. If the provider
returns unsupported references or fails, DeepVault falls back to a deterministic
evidence-only report.

For consensus reporting, configure a comma-separated provider list:

```env
LLM_CONSENSUS_PROVIDERS=openai,anthropic,gemini
```

Only identical claims with the same evidence citations that receive a majority
vote are retained. Provider-only claims are discarded. The baseline report
also includes an evidence-linked timeline, detected contradictions, source
coverage, limitations and analyst recommendations.

## Safe defaults

Sensitive pivots such as geolocation, dark-web and financial modules are
disabled unless explicitly enabled:

```env
ALLOW_SENSITIVE_PIVOTS=false
```

DeepVault does not retain passwords, authentication tokens, cookies, private
messages or session material.

## Authorization and privacy

Collection must be governed by a `CollectionPolicy` with a case authorization
reference, expiry, lawful purpose and explicit source allowlist. Infrastructure
enrichment additionally requires:

```env
ALLOW_INFRASTRUCTURE_ENRICHMENT=true
AUTHORIZATION_REFERENCE=CASE-2025-001
```

The target IP must be a literal authorized IP. DeepVault does not perform broad
Shodan or Censys discovery from a person's name or email.

Do not put API keys in targets, evidence, logs or reports. Store them only in
environment variables or a secrets manager. Raw breach records, passwords,
hashes, tokens, cookies, private communications and leaked credentials are
redacted before persistence or model processing.

## Connector configuration

```env
GITHUB_TOKEN=                 # optional for higher public API limits
HIBP_API_KEY=
HUNTER_API_KEY=
BRAVE_API_KEY=
SPIDERFOOT_URL=http://spiderfoot:5001
SHODAN_API_KEY=
CENSYS_API_ID=
CENSYS_API_SECRET=

ANTHROPIC_API_KEY=
ANTHROPIC_MODEL=claude-sonnet-4-20250514
GEMINI_API_KEY=
GEMINI_MODEL=gemini-2.5-pro
OPENAI_COMPATIBLE_API_KEY=
OPENAI_COMPATIBLE_BASE_URL=
OPENAI_COMPATIBLE_MODEL=
```

## Enabling the operational person pipeline

The expanded connector stage runs only when the investigation's
`case_metadata` contains explicit authorization. This keeps existing cases
safe and prevents a name alone from triggering global collection.

```json
{
  "authorization_confirmed": true,
  "authorization_reference": "CASE-2026-001",
  "authorization_expires_at": "2026-12-31T23:59:59Z",
  "lawful_purpose": "Consent-based defensive exposure assessment",
  "permitted_sources": [
    "github",
    "hibp",
    "hunter",
    "brave",
    "sherlock",
    "maigret",
    "holehe"
  ],
  "employer": "Example Corp",
  "location": "Paris"
}
```

Configure the deployment-wide ceiling separately:

```env
PERSON_OSINT_SOURCES=github,hibp,hunter,brave,sherlock,maigret,holehe
```

The case allowlist can only narrow that ceiling. SpiderFoot, Shodan and Censys
must be deliberately added to both lists. Shodan and Censys additionally
require `allow_infrastructure_enrichment: true`, the environment-level opt-in,
and literal IPs in `authorized_ips`.

The pipeline routes identifiers by source: usernames to GitHub/Sherlock/Maigret,
emails to HIBP/Hunter/Holehe, a name-plus-context query to Brave, approved
domains or usernames to passive SpiderFoot, and only approved IPs to
Shodan/Censys. Duplicate legacy calls are suppressed when the normalized stage
already queried the same source.

## Validation

From the repository root:

```bash
PYTHONPATH=orchestrator python3 -m unittest discover -s tests -v
python3 -m compileall orchestrator
```
