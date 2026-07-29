# Investigation workbench

DeepVault's localhost dashboard provides a Maltego-style visual workbench over
the deterministic, evidence-first identity graph. It is a review surface for
already-collected public evidence, not a license to attribute every returned
account to the investigated person.

## Result views

Open a completed case at `http://127.0.0.1:8080` and use the four result tabs:

- **Graph** combines normalized observations from every permitted connector.
  Drag nodes to arrange them, drag the background to pan, use the wheel to zoom,
  double-click a node to isolate its neighborhood, or Shift-click several nodes
  to compare them.
- **Evidence** shows the redacted evidence ledger, immutable evidence IDs,
  source, observation time, confidence, identity status, and safe public links.
- **Timeline** includes only event dates stated by a source. Collection time is
  intentionally not presented as person-history.
- **Report** keeps the executive summary, evidence-linked findings,
  contradictions, source coverage, recommendations, and approved transforms.

The node inspector explains why an entity exists, displays the evidence IDs
behind it, lists adjacent relationships and their reasons, and shows
evidence-backed manual review pivots. A relationship is a source observation or
an explicitly uncertain hypothesis; it is not automatically an ownership,
employment, or identity claim.

## Graph controls

The graph can be filtered by source, entity type, and minimum confidence. Entity
clusters can be collapsed for large cases without changing the underlying
evidence. Edge labels can be hidden, the viewport can be reset, and reviewed
node positions can be saved to the case.

Confidence is a review aid:

- the ring around a node shows its graph confidence;
- solid edges are stronger cited relationships;
- dashed edges remain possible or insufficiently supported;
- confidence from multiple username enumeration tools is not treated as
  independent identity corroboration.

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

The API rejects malformed graph exports when a relationship has no evidence ID,
cites unknown evidence, or references a node outside the case graph.

## Exports

Each completed case supports:

| Format | Endpoint | Intended use |
|---|---|---|
| JSON | `/api/investigations/{id}/graph.json` | Full DeepVault graph and provenance |
| GraphML | `/api/investigations/{id}/graph.graphml` | Gephi and compatible graph tools |
| GEXF | `/api/investigations/{id}/graph.gexf` | Graph analysis and visualization |
| CSV | `/api/investigations/{id}/graph.csv` | Tabular entity/relationship review |
| Mapping schema v2 | `/api/investigations/{id}/mapping.osint.json` | OSINT Mapping Tool import |

GraphML and CSV retain relationship evidence IDs and explanations. GEXF retains
node labels, edge types, and confidence weights. The DeepVault JSON or GraphML
export should remain the audit source when another visualization tool does not
display every provenance field.

## Pivot safety

Analyst-triggered transforms appear only when:

1. the investigation is complete;
2. written authorization has not expired;
3. the transform is in the case's permitted source scope;
4. the selected node has a supported entity type and cited evidence;
5. configured result, time, concurrency, and pivot-depth budgets allow it.

DeepVault never accepts passwords, session cookies, leaked credentials, private
communications, or account-recovery actions as pivots.
