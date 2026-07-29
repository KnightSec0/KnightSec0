# Evidence-first identity analysis

WorldAtlas incorporates the defensible parts of the supplied Chimera/NEXUS
prototype as a local analysis layer over evidence that its authorized
connectors have already collected. It does not run a second, hidden collection
pipeline.

## What is integrated

- A deterministic identity graph whose nodes, edges and provenance steps
  reference WorldAtlas evidence IDs.
- Conservative identity hypotheses that distinguish an observed public account
  from attribution of that account to the investigated person.
- Cross-source links for the same normalized public observation. A single
  source cannot establish a probable identity on its own.
- Ranked analyst pivots that explain the expected information gain, required
  authorization and supporting evidence. Pivots are recommendations and are
  never executed automatically.
- Snapshot comparison between comparable completed cases, including added,
  not-observed, persisting and changed observations.

The analysis is serialized into the structured report, shown on the local live
dashboard and included in JSON and HTML downloads. The optional LLM providers
may summarize evidence-linked findings, but the deterministic graph and
temporal comparison remain the source of truth.

## Evidence contract

Every node derived from collection has an evidence ID. Every edge, hypothesis,
provenance step and analyst pivot carries one or more IDs that resolve to the
current evidence ledger. A temporal item carries the current ID, the previous
case ID and/or the previous evidence ID as applicable.

Scores represent the strength of a specific link or hypothesis. They are not a
probability that the investigated person owns every account in the graph.
Single-source username matches remain possible candidates until independent
public attributes corroborate them.

## Temporal semantics

Temporal comparison is off by default and requires explicit case-level opt-in.
WorldAtlas then selects the latest completed case having the same normalized
name, matching operator-supplied email, the same unexpired authorization
reference, lawful purpose and source scope. If no email was supplied, it can
fall back to the username and adds an explicit ambiguity warning. Volatile
collection fields such as evidence IDs, observation timestamps and correlation
wrappers do not create a change.

A not-observed item means only that the observation was not present in the
latest successfully covered source. It may reflect changed page behavior or
connector coverage. It is never evidence that an account or person no longer
exists. WorldAtlas suppresses not-observed entries for unavailable, timed-out,
rate-limited or unqueried sources.

## Deliberately excluded

The supplied prototype also contained techniques that do not meet WorldAtlas's
authorization, privacy or evidentiary requirements. WorldAtlas does not:

- invent email addresses, phone numbers or usernames and present them as facts;
- collect passwords, password hashes, session cookies, tokens, private messages
  or raw leaked credentials;
- perform password spraying, login attempts or account-recovery probing;
- scrape commit history to discover non-public email addresses;
- infer identity from breach-row credential co-occurrence;
- recursively crawl hidden services or bypass anti-bot controls;
- execute analyst pivots without a new, explicit source authorization.

These restrictions are design guarantees rather than optional operator
settings.
