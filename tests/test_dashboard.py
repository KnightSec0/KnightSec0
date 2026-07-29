import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from xml.etree import ElementTree as ET

from fastapi import HTTPException
from pydantic import ValidationError

ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, ROOT)

from dashboard.app import (  # noqa: E402
    Investigation,
    InvestigationCreate,
    TransformRequest,
    _active_transform_run_count,
    _gexf_document,
    _graph_csv_document,
    _graph_document,
    _graphml_document,
    _mapping_document,
    render_report_html,
)


def valid_request(**overrides):
    payload = {
        "target_name": "Alice Example",
        "target_username": "alice_example",
        "target_email": None,
        "lawful_purpose": "Consent-based defensive exposure assessment",
        "authorization_reference": "SELF-TEST-001",
        "authorization_expires_at": datetime.now(timezone.utc) + timedelta(hours=1),
        "authorization_confirmed": True,
        "permitted_sources": ["github", "sherlock"],
    }
    payload.update(overrides)
    return payload


class DashboardRequestValidationTests(unittest.TestCase):
    def test_temporal_comparison_is_explicit_opt_in(self):
        self.assertFalse(
            InvestigationCreate(**valid_request()).compare_previous_cases
        )
        self.assertTrue(
            InvestigationCreate(
                **valid_request(compare_previous_cases=True)
            ).compare_previous_cases
        )

    def test_rejects_unconfirmed_authorization(self):
        with self.assertRaisesRegex(
            ValidationError, "Written authorization must be confirmed"
        ):
            InvestigationCreate(**valid_request(authorization_confirmed=False))

    def test_rejects_expired_authorization(self):
        with self.assertRaisesRegex(
            ValidationError, "Authorization expiry must be in the future"
        ):
            InvestigationCreate(
                **valid_request(
                    authorization_expires_at=datetime.now(timezone.utc)
                    - timedelta(seconds=1)
                )
            )

    def test_requires_username_or_email(self):
        with self.assertRaisesRegex(
            ValidationError, "Provide at least one username or email"
        ):
            InvestigationCreate(
                **valid_request(target_username=None, target_email=None)
            )

    def test_rejects_unsupported_source(self):
        with self.assertRaisesRegex(ValidationError, "Unsupported sources"):
            InvestigationCreate(
                **valid_request(permitted_sources=["github", "unknown-source"])
            )

    def test_rejects_whitespace_only_required_text(self):
        with self.assertRaisesRegex(ValidationError, "Value cannot be empty"):
            InvestigationCreate(**valid_request(target_name="   "))

    def test_infrastructure_source_requires_scoped_ip_and_consent(self):
        with self.assertRaisesRegex(ValidationError, "require infrastructure consent"):
            InvestigationCreate(**valid_request(permitted_sources=["github", "shodan"]))

        request = InvestigationCreate(
            **valid_request(
                permitted_sources=["github", "shodan"],
                authorized_ips=["8.8.8.8"],
                allow_infrastructure_enrichment=True,
            )
        )
        self.assertEqual(request.authorized_ips, ["8.8.8.8"])

        with self.assertRaisesRegex(ValidationError, "only literal public IP"):
            InvestigationCreate(
                **valid_request(
                    permitted_sources=["github", "shodan"],
                    authorized_ips=["172.20.10.11"],
                    allow_infrastructure_enrichment=True,
                )
            )

    def test_active_and_authenticated_transforms_require_separate_scope(self):
        with self.assertRaisesRegex(ValidationError, "authorized domain"):
            InvestigationCreate(
                **valid_request(permitted_sources=["github", "httpx"])
            )
        with self.assertRaisesRegex(
            ValidationError,
            "authenticated-transform consent",
        ):
            InvestigationCreate(
                **valid_request(permitted_sources=["github", "ghunt"])
            )
        request = InvestigationCreate(
            **valid_request(
                permitted_sources=["github", "httpx", "ghunt"],
                authorized_domains=["authorized-domain.com"],
                allow_infrastructure_enrichment=True,
                allow_authenticated_transforms=True,
            )
        )
        self.assertTrue(request.allow_authenticated_transforms)

        with self.assertRaisesRegex(ValidationError, "Reserved demonstration domain"):
            InvestigationCreate(
                **valid_request(
                    permitted_sources=["github", "httpx"],
                    authorized_domains=["example.com"],
                    allow_infrastructure_enrichment=True,
                )
            )

    def test_accepts_and_deduplicates_additional_usernames(self):
        request = InvestigationCreate(
            **valid_request(
                target_username="alice",
                additional_usernames=["Alice", "KnightSec0", "KnightSec0"],
            )
        )

        self.assertEqual(request.additional_usernames, ["KnightSec0"])

    def test_transform_request_validates_input_contract(self):
        request = TransformRequest(
            transform="blackbird",
            entity_type="username",
            value="alice",
            evidence_ids=["EVID-1", "EVID-1"],
        )
        self.assertEqual(request.evidence_ids, ["EVID-1"])
        with self.assertRaisesRegex(ValidationError, "does not accept"):
            TransformRequest(
                transform="subfinder",
                entity_type="email",
                value="alice@example.com",
            )

    def test_parallel_transform_count_ignores_terminal_runs(self):
        self.assertEqual(
            _active_transform_run_count(
                {
                    "transform_runs": [
                        {"status": "queued"},
                        {"status": "running"},
                        {"status": "completed"},
                        {"status": "failed"},
                    ]
                }
            ),
            2,
        )


class DashboardGraphExportTests(unittest.TestCase):
    def investigation(self):
        return Investigation(
            target_name="Alice Example",
            target_username="alice",
            status="COMPLETED",
            case_metadata={
                "authorization_reference": "SELF-TEST-001",
                "permitted_sources": ["github", "blackbird"],
                "structured_report": {
                    "evidence_ledger": [
                        {
                            "id": "EVID-1",
                            "source": "github",
                            "type": "github_profile",
                            "value": "https://github.com/alice",
                            "observed_at": "2026-07-26T10:00:00Z",
                            "confidence": 0.62,
                            "identity_status": "possible",
                            "independence_group": "publisher:github.com",
                        }
                    ],
                    "identity_graph": {
                        "nodes": [
                            {
                                "id": "NODE-TARGET",
                                "kind": "authorized_target",
                                "label": "Alice Example",
                                "attributes": {},
                                "evidence_ids": [],
                            },
                            {
                                "id": "NODE-PROFILE",
                                "kind": "public_profile",
                                "label": "https://github.com/alice",
                                "attributes": {"login": "alice"},
                                "evidence_ids": ["EVID-1"],
                            },
                        ],
                        "edges": [
                            {
                                "id": "EDGE-1",
                                "source_node_id": "NODE-TARGET",
                                "target_node_id": "NODE-PROFILE",
                                "relationship": "candidate_profile",
                                "confidence": 0.62,
                                "identity_status": "possible",
                                "evidence_ids": ["EVID-1"],
                                "independent_source_count": 1,
                                "provenance_chain": [
                                    {
                                        "evidence_id": "EVID-1",
                                        "source": "github",
                                        "role": "direct_observation",
                                        "independence_key": "publisher:github.com",
                                        "explanation": "Public observation.",
                                    }
                                ],
                            }
                        ],
                    },
                },
            },
        )

    def test_graph_api_and_mapping_export_keep_evidence_provenance(self):
        investigation = self.investigation()
        graph = _graph_document(investigation)
        mapping = _mapping_document(investigation)

        self.assertEqual(graph["schemaVersion"], 2)
        self.assertEqual(
            [item["name"] for item in graph["transforms"]],
            ["blackbird"],
        )
        self.assertEqual(mapping["schemaVersion"], 2)
        profile = next(
            item
            for item in mapping["identifiers"]
            if item["id"] == "NODE-PROFILE"
        )
        self.assertEqual(profile["evidenceIds"], ["EVID-1"])
        self.assertEqual(profile["confidence"], 0.62)
        self.assertEqual(profile["identityStatus"], "possible")
        self.assertEqual(profile["independentSourceCount"], 1)
        self.assertEqual(mapping["connections"][0]["confidence"], 0.62)
        self.assertEqual(
            mapping["connections"][0]["provenanceChain"][0]["source"],
            "github",
        )
        self.assertEqual(graph["stats"]["entity_count"], 2)
        self.assertEqual(graph["stats"]["relationship_count"], 1)
        self.assertEqual(graph["stats"]["evidence_count"], 1)
        profile_entity = next(
            item
            for item in graph["entities"]
            if item["entity_id"] == "NODE-PROFILE"
        )
        self.assertEqual(profile_entity["source_tools"], ["github"])
        self.assertEqual(profile_entity["confidence"], 0.62)
        self.assertEqual(profile_entity["evidence_ids"], ["EVID-1"])
        self.assertEqual(
            graph["relationships"][0]["reason"],
            "Public observation.",
        )

    def test_interoperable_exports_keep_relationship_evidence_ids(self):
        investigation = self.investigation()

        graphml = _graphml_document(investigation)
        gexf = _gexf_document(investigation)
        csv_export = _graph_csv_document(investigation)

        graphml_root = ET.fromstring(graphml)
        gexf_root = ET.fromstring(gexf)
        self.assertTrue(graphml_root.tag.endswith("graphml"))
        self.assertTrue(gexf_root.tag.endswith("gexf"))
        self.assertIn("EVID-1", graphml.decode())
        self.assertIn("candidate_profile", graphml.decode())
        self.assertIn("candidate_profile", gexf.decode())
        self.assertIn("relationship,EDGE-1", csv_export)
        self.assertIn("EVID-1", csv_export)

    def test_exports_escape_markup_and_reject_unknown_evidence(self):
        investigation = self.investigation()
        graph = investigation.case_metadata["structured_report"]["identity_graph"]
        graph["nodes"][1]["label"] = "<script>alert('graph')</script>"
        graphml = _graphml_document(investigation).decode()
        self.assertNotIn("<script>", graphml)
        self.assertIn("&lt;script&gt;", graphml)

        graph["edges"][0]["evidence_ids"] = ["EVID-UNKNOWN"]
        with self.assertRaisesRegex(
            HTTPException,
            "relationship failed evidence validation",
        ):
            _graph_document(investigation)

    def test_workbench_assets_define_requested_views_and_theme(self):
        with open(
            os.path.join(ROOT, "dashboard", "static", "index.html"),
            encoding="utf-8",
        ) as file:
            index = file.read()
        with open(
            os.path.join(ROOT, "dashboard", "static", "workbench.js"),
            encoding="utf-8",
        ) as file:
            workbench = file.read()

        self.assertIn("--bg: #071326", index)
        self.assertIn("--accent: #c1121f", index)
        self.assertIn('src="/static/workbench.js"', index)
        for result_view in ("graph", "evidence", "timeline", "report"):
            self.assertIn(f'["{result_view}"', workbench)
        self.assertIn("Why this match?", workbench)
        self.assertIn("Shift-click to compare", workbench)
        self.assertIn("graph.graphml", workbench)
        self.assertIn("graph.gexf", workbench)
        self.assertIn("graph.csv", workbench)


class DashboardReportRenderingTests(unittest.TestCase):
    def test_html_escapes_untrusted_values_and_keeps_evidence_citations(self):
        report = {
            "report_id": "REPORT-1",
            "generated_at": "2026-07-23T12:00:00Z",
            "executive_summary": "<script>alert('summary')</script>",
            "identity_confidence": "possible",
            "overall_risk": "low",
            "evidence_count": 1,
            "executive_summary_evidence_ids": ["EVID-ABC123"],
            "findings": [
                {
                    "title": "<img src=x onerror=alert(1)>",
                    "statement": "A public profile was observed.",
                    "confidence": 0.62,
                    "evidence_ids": ["EVID-ABC123"],
                }
            ],
            "source_coverage": [
                {
                    "source": "github",
                    "evidence_count": 1,
                    "status": "covered",
                }
            ],
            "evidence_ledger": [
                {
                    "id": "EVID-ABC123",
                    "source": "github",
                    "type": "github_profile",
                    "value": "https://github.com/alice",
                    "confidence": 0.62,
                    "identity_status": "possible",
                    "metadata": {
                        "public_profile": {"login": "alice"},
                        "password": "must-not-survive",
                        "error_url": (
                            "https://provider.test/query?"
                            "access_token=must-not-survive-either"
                        ),
                    },
                }
            ],
            "identity_graph": {
                "nodes": [
                    {
                        "id": "NODE-TARGET",
                        "label": "Alice Example",
                    },
                    {
                        "id": "NODE-PROFILE",
                        "label": "<svg onload=alert('graph')>",
                    },
                ],
                "edges": [
                    {
                        "relationship": "candidate_identity_association",
                        "source_node_id": "NODE-TARGET",
                        "target_node_id": "NODE-PROFILE",
                        "confidence": 0.62,
                        "identity_status": "possible",
                        "evidence_ids": ["EVID-ABC123"],
                    }
                ],
                "hypotheses": [
                    {
                        "identity_status": "possible",
                        "confidence": 0.62,
                        "claim": "A cited profile is a candidate.",
                        "evidence_ids": ["EVID-ABC123"],
                        "limitations": ["Manual verification is required."],
                    }
                ],
                "pivots": [
                    {
                        "rank": 1,
                        "title": "Review public profile",
                        "rationale": "The profile is a cited candidate.",
                        "action": "Review the public page without authenticating.",
                        "priority": "medium",
                        "evidence_ids": ["EVID-ABC123"],
                    }
                ],
            },
            "temporal_comparison": {
                "scope": {"previous_case_id": "CASE-OLD"},
                "counts": {
                    "added": 0,
                    "changed": 1,
                    "persisting": 0,
                    "not_observed": 0,
                },
                "changed": [
                    {
                        "type": "github_profile",
                        "value": "<iframe src=bad>",
                        "previous_evidence_id": "EVID-OLD",
                        "current_evidence_id": "EVID-ABC123",
                        "changed_fields": ["metadata"],
                    }
                ],
                "added": [],
                "persisting": [],
                "not_observed": [],
                "scope_note": "Snapshot changes do not prove identity.",
            },
            "recommendations": ["Review <b>manually</b>."],
        }

        rendered = render_report_html(report, "Alice <script>alert('target')</script>")

        self.assertNotIn("<script>", rendered)
        self.assertNotIn("<img src=x", rendered)
        self.assertNotIn("<b>manually</b>", rendered)
        self.assertNotIn("<svg onload", rendered)
        self.assertNotIn("<iframe src", rendered)
        self.assertIn("&lt;script&gt;", rendered)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", rendered)
        self.assertIn("Review &lt;b&gt;manually&lt;/b&gt;.", rendered)
        self.assertNotIn("must-not-survive", rendered)
        self.assertNotIn("must-not-survive-either", rendered)
        self.assertIn("&lt;redacted&gt;", rendered)
        self.assertIn("Evidence appendix", rendered)
        self.assertIn("Evidence-first identity analysis", rendered)
        self.assertIn("Changes since the previous comparable case", rendered)
        self.assertIn("&lt;svg onload=alert(&#x27;graph&#x27;)&gt;", rendered)
        self.assertIn("&lt;iframe src=bad&gt;", rendered)
        self.assertGreaterEqual(rendered.count("EVID-ABC123"), 3)


if __name__ == "__main__":
    unittest.main()
