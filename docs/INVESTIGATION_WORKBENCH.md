# Investigation workbench

WorldAtlas's localhost dashboard provides a Maltego-style visual workbench over
the deterministic, evidence-first identity graph. It is a review surface for
already-collected public evidence, not a license to attribute every returned
account to the investigated person.

## Result views

Open a completed case at `http://127.0.0.1:8080`. The default **Overview**
answers what was found, how reliable it is, and what to review next without
requiring graph-analysis or cybersecurity knowledge. Five result tabs remain
available:

- **Overview** gives a cited plain-language verdict, separates supported,
  review-first, low-signal, and hidden-noise results, provides a ranked manual
  review queue, explains coverage gaps, and states what must not be concluded.
- **Graph** combines normalized observations from every permitted connector.
  It opens in simplified mode with the target and the strongest review leads;
  the full technical provenance graph remains one click away.
  Click or press Enter on a node to open its inspector, drag nodes to arrange
  them, drag the background to pan, use the wheel to zoom, use **Show
  neighborhood** in the inspector to isolate connections, or Shift-click
  several nodes to compare them.
  The visible-entity directory provides the same selection action independently
  of the SVG target, and the entity search accepts labels, URLs, sources, types,
  and evidence IDs.
- **Evidence** shows the redacted evidence ledger, immutable evidence IDs,
  source, observation time, confidence, identity status, and safe public links.
  Search and filter it by source or analyst decision. Clicking an evidence ID
  anywhere in Overview, Graph, Timeline, or Report opens the matching row.
- **Timeline** includes only event dates stated by a source. Collection time is
  intentionally not presented as person-history.
- **Report** keeps the executive summary, evidence-linked findings,
  contradictions, source coverage, recommendations, and approved transforms.

The node inspector explains why an entity exists, displays the evidence IDs
behind it, expands up to ten cited evidence records with their source, type,
confidence, identity state, analyst decision, observation time, and exact public
link, lists clickable adjacent relationships and their reasons, and shows
evidence-backed manual review pivots. Its ownership conclusion remains explicit:
a collected page is not verified ownership unless the cited identity analysis
reaches the required status. A relationship is a source observation or an
explicitly uncertain hypothesis; it is not automatically an ownership,
employment, or identity claim.

## Graph controls

The simplified graph hides publisher-only nodes, generic search/home endpoints,
missing or inaccessible pages, catalogue-only username URLs, person-search
results without enough identity context, rejected endpoints, and quarantined
sensitive username matches. These observations remain in the audit ledger with
their evidence IDs, but broken and unvalidated links are clearly labelled and
disabled. An analyst can switch to the full technical graph and explicitly
reveal suppressed results.

Both graph modes can be filtered by source, entity type, and minimum confidence.
After selecting a node, **Connection view** can show all neighbors, only
outgoing relationships, or only incoming relationships. Relationship peers in
the inspector are buttons, so an analyst can navigate the graph inside-out
without visually locating the next node.
Entity clusters can be collapsed for large cases without changing the
underlying evidence. Edge labels can be hidden, the viewport can be reset, and
reviewed node positions can be saved to the case.

Confidence is a review aid:

- the ring around a node shows its graph confidence;
- solid edges are stronger cited relationships;
- dashed edges remain possible or insufficiently supported;
- confidence from multiple username enumeration tools is not treated as
  independent identity corroboration.

The Overview replaces raw scores with four review labels:

- **Supported** means the identity hypothesis reached probable or stronger;
- **Check first** means a manual review is worthwhile, not that ownership is
  verified;
- **Unverified lead** means a single low-signal observation;
- **Hidden by default** means a generic, rejected, or sensitive observation
  retained only for authorized audit.

Every Overview statement and review lead displays its evidence IDs. Operational
coverage messages are labeled separately because tool availability is not a
claim about the investigated person.

The red and dark-blue palette uses red for selection, breach metadata, and
important controls. It does not convert a low-confidence observation into a
critical finding.

## API model

`GET /api/investigations/{id}/graph` retains the original deterministic graph
and also returns a UI-friendly normalized model:

- `entities`: entity ID, type, label, canonical value, aliases, sources,
  confidence, identity status, timestamps, safe metadata, and evidence IDs;
- `relationships`: edge ID, endpoints, relationship type, confidence, source
  tools, reason, provenance chain, and evidence IDs;
- `clusters`: counts by entity type;
- `stats`: entity, relationship, evidence, and source counts.
- `review_summary`: a cited verdict, conservative counters, ranked review leads,
  plain-language key points and cautions, and grouped source coverage;
- review fields on every entity: `review_priority`, `confidence_label`,
  `plain_language_explanation`, `quality_status`, `publisher_count`,
  `sensitive`, and `generic_endpoint`;
- `plain_language_type` on every normalized relationship.

The API rejects malformed graph exports when a relationship has no evidence ID,
cites unknown evidence, or references a node outside the case graph.

## Exports

Each completed case supports:

| Format | Endpoint | Intended use |
|---|---|---|
| JSON | `/api/investigations/{id}/graph.json` | Full WorldAtlas graph and provenance |
| GraphML | `/api/investigations/{id}/graph.graphml` | Gephi and compatible graph tools |
| GEXF | `/api/investigations/{id}/graph.gexf` | Graph analysis and visualization |
| CSV | `/api/investigations/{id}/graph.csv` | Plain-language review fields plus technical entity/relationship audit |
| Mapping schema v2 | `/api/investigations/{id}/mapping.osint.json` | OSINT Mapping Tool import |

CSV starts with the cited verdict and gives each entity a review priority,
plain-language label, publisher list, hidden-by-default flag, and explanation.
Spreadsheet formula-like values are escaped on export. GraphML and CSV retain
relationship evidence IDs and explanations. GEXF retains node labels, edge
types, and confidence weights. The WorldAtlas JSON or GraphML export should
remain the audit source when another visualization tool does not display every
provenance field.

The downloadable HTML report now starts with the same plain-language assessment
and review queue as the dashboard. It contains a self-contained interactive
graph with text, type, confidence, incoming/outgoing, zoom, pan, node-inspector,
public-page, relationship-peer, and evidence-link controls. Evidence IDs,
coverage citations, findings, timeline entries, contradictions, and technical
relationships link directly to the evidence appendix. Full publisher provenance
remains available inside a collapsed technical section, and the evidence
appendix remains complete for controlled audit and printing.

## Analyst adjudication and false positives

The Evidence view lets an analyst mark one or more evidence records as:

- **Analyst accepted** after checking the cited public attributes;
- **Needs review** when more corroboration is required;
- **False positive** when the observation belongs to another person, is stale,
  generic, duplicated, or is a source error.

A false-positive decision requires a written note. WorldAtlas immediately removes
that evidence from the simplified and technical graphs, findings, timelines,
contradictions, reports, and customer exports. It does not delete the collected
record: the evidence ID, decision, reason, reviewer, prior decision, and timestamp
remain in the case audit history. Selecting **Restore to review** makes the
observation available again and appends another audit event.

Analyst acceptance does not rewrite the source confidence. The interface shows
the manual decision alongside the original technical score.

## Responsible decision support

WorldAtlas reports cited public evidence for qualified human review. It must not
diagnose mental health, infer protected traits, derive intimate preferences or
personality, or automatically rank, reject, or recommend a person for employment.
Employment-related reviews should be limited to relevant, consented, verifiable
facts and the legal safeguards applicable to the organization and jurisdiction.

## Pivot safety

Analyst-triggered transforms appear only when:

1. the investigation is complete;
2. written authorization has not expired;
3. the transform is in the case's permitted source scope;
4. the selected node has a supported entity type and cited evidence;
5. configured result, time, concurrency, and pivot-depth budgets allow it.

WorldAtlas never accepts passwords, session cookies, leaked credentials, private
communications, or account-recovery actions as pivots.
