# Person-focused OSINT intelligence layer

This phase adds a normalized evidence pipeline for authorized investigations of
specific people. DeepVault treats every automated result as an observation, not
as proof that a person controls an account.

## Sources in phase 1

- Sherlock: public username presence
- Maigret: independent username corroboration
- Holehe: public service-registration signals
- Existing HIBP, Hunter, Brave, DeHashed and IntelX modules, with credential
  values removed before persistence

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
# or: ollama
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

## Safe defaults

Sensitive pivots such as geolocation, dark-web and financial modules are
disabled unless explicitly enabled:

```env
ALLOW_SENSITIVE_PIVOTS=false
```

DeepVault does not retain passwords, authentication tokens, cookies, private
messages or session material.

## Validation

From the repository root:

```bash
PYTHONPATH=orchestrator python3 -m unittest discover -s tests -v
python3 -m compileall orchestrator
```
