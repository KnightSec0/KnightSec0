import asyncio
import json
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(ROOT, "orchestrator"))

from intelligence.correlation import correlate_evidence
from intelligence.models import Evidence, SourceReliability
from intelligence.models import InvestigationTarget
from intelligence.policy import CollectionPolicy
from intelligence.redaction import redact_sensitive
from investigators.person_intelligence import PersonIntelligenceInvestigator
from main import _running_task_is_stale
from reporting.person_report import (
    PersonReportGenerator,
    _baseline_report,
    _consensus,
    _llm_payload,
)
from reporting.schemas import Finding, InvestigationReport, RiskLevel


class FakeArtifact:
    def __init__(self, source, source_type, value, context=None, confidence="medium"):
        self.source = source
        self.source_type = source_type
        self.identifier_value = value
        self.context = context or {}
        self.confidence = confidence


class IntelligenceTests(unittest.TestCase):
    def test_redaction_removes_credentials(self):
        result = redact_sensitive(
            {
                "username": "alice",
                "password": "secret-value",
                "nested": {"api_token": "abcdef"},
                "raw_leak": {"hash": "deadbeef", "message_body": "private"},
                "error": (
                    "request failed at "
                    "https://provider.test/query?api_key=must-not-survive"
                ),
            }
        )
        self.assertEqual(result["username"], "alice")
        self.assertEqual(result["password"], "<redacted>")
        self.assertEqual(result["nested"]["api_token"], "<redacted>")
        self.assertEqual(result["raw_leak"], "<redacted>")
        self.assertNotIn("must-not-survive", result["error"])
        self.assertIn("api_key=<redacted>", result["error"])

    def test_independent_sources_raise_confidence(self):
        items = [
            Evidence(
                type="social_profile",
                value="https://example.test/alice",
                source="sherlock",
                confidence=0.55,
                reliability=SourceReliability.MEDIUM,
            ),
            Evidence(
                type="social_profile",
                value="https://example.test/alice/",
                source="maigret",
                confidence=0.58,
                reliability=SourceReliability.MEDIUM,
            ),
        ]
        correlated = correlate_evidence(items)
        self.assertEqual(len(correlated), 1)
        self.assertGreater(correlated[0].confidence, 0.70)
        self.assertEqual(set(correlated[0].corroborated_by), {"sherlock", "maigret"})

    def test_report_findings_reference_real_evidence(self):
        artifacts = [
            FakeArtifact(
                "hibp",
                "breach",
                "alice@example.test",
                {"breach_name": "Example", "password": "must-not-survive"},
                "high",
            )
        ]
        report = asyncio.run(
            PersonReportGenerator().generate(
                target={"name": "Alice Example"},
                artifacts=artifacts,
            )
        )
        self.assertEqual(report.evidence_count, 1)
        self.assertTrue(report.findings)
        self.assertTrue(report.findings[0].evidence_ids)
        serialized = report.model_dump_json()
        self.assertNotIn("must-not-survive", serialized)
        self.assertEqual(len(report.evidence_ledger), 1)
        self.assertEqual(
            report.evidence_ledger[0]["id"],
            report.findings[0].evidence_ids[0],
        )
        valid_ids = {finding.evidence_ids[0] for finding in report.findings}
        self.assertTrue(valid_ids)
        for event in report.timeline:
            self.assertTrue(set(event.evidence_ids).issubset(valid_ids))

    def test_report_includes_selected_sources_without_evidence(self):
        report = asyncio.run(
            PersonReportGenerator().generate(
                target={
                    "name": "Alice Example",
                    "_source_status": [
                        {
                            "source": "github",
                            "status": "no_results",
                            "evidence_count": 0,
                        }
                    ],
                },
                artifacts=[],
            )
        )
        self.assertEqual(len(report.source_coverage), 1)
        self.assertEqual(report.source_coverage[0].source, "github")
        self.assertEqual(report.source_coverage[0].status, "no_results")
        self.assertEqual(report.source_coverage[0].evidence_count, 0)

    def test_external_llm_payload_pseudonymizes_evidence_identifiers(self):
        evidence = Evidence(
            id="EVID-ABC123",
            type="breach",
            value="alice@example.test",
            source="hibp",
            source_url="https://haveibeenpwned.com/account/alice",
            metadata={
                "email": "alice@example.test",
                "breach_name": "Example Breach",
            },
        )
        baseline = _baseline_report([evidence])
        payload = _llm_payload(
            {
                "name": "Alice Example",
                "email": "alice@example.test",
                "username": "alice",
            },
            [evidence],
            baseline,
        )
        serialized = json.dumps(payload)
        self.assertNotIn("Alice Example", serialized)
        self.assertNotIn("alice@example.test", serialized)
        self.assertNotIn("haveibeenpwned.com/account/alice", serialized)
        self.assertIn("Example Breach", serialized)
        self.assertNotIn("evidence_ledger", payload["baseline_report"])
        self.assertEqual(payload["evidence"][0]["id"], "EVID-ABC123")

    def test_running_task_staleness_uses_progress_heartbeat(self):
        recent = SimpleNamespace(
            case_metadata={
                "progress": {"updated_at": datetime.now(timezone.utc).isoformat()}
            },
            updated_at=None,
            created_at=None,
        )
        stale = SimpleNamespace(
            case_metadata={
                "progress": {
                    "updated_at": (
                        datetime.now(timezone.utc) - timedelta(hours=2)
                    ).isoformat()
                }
            },
            updated_at=None,
            created_at=None,
        )
        self.assertFalse(_running_task_is_stale(recent))
        self.assertTrue(_running_task_is_stale(stale))

    def test_policy_requires_scoped_source(self):
        target = InvestigationTarget(
            name="Alice Example",
            lawful_purpose="Authorized defensive review",
            authorization_confirmed=True,
        )
        policy = CollectionPolicy(
            authorization_reference="AUTH-123",
            purpose="Authorized defensive review",
            expires_at=datetime.now(timezone.utc) + timedelta(days=1),
            permitted_sources=frozenset({"github"}),
        )
        policy.authorize(target, "github")
        with self.assertRaises(PermissionError):
            policy.authorize(target, "shodan")

    def test_person_collection_plan_routes_identifiers_by_source(self):
        target = InvestigationTarget(
            name="Alice Example",
            usernames=["alice"],
            emails=["alice@example.test"],
            domains=["example.test"],
            employer="Example Corp",
            location="Paris",
            lawful_purpose="Authorized defensive review",
            authorization_confirmed=True,
        )
        policy = CollectionPolicy(
            authorization_reference="AUTH-123",
            purpose=target.lawful_purpose,
            expires_at=datetime.now(timezone.utc) + timedelta(days=1),
            permitted_sources=frozenset(
                {"github", "hibp", "brave", "spiderfoot", "shodan"}
            ),
            infrastructure_enrichment=True,
        )
        plan = PersonIntelligenceInvestigator(policy).build_plan(
            target=target,
            authorized_ips=["203.0.113.10"],
        )
        routed = {(item.source, item.identifier, item.identifier_type) for item in plan}
        self.assertIn(("github", "alice", "username"), routed)
        self.assertIn(("hibp", "alice@example.test", "email"), routed)
        self.assertIn(
            ("brave", "Alice Example Example Corp Paris", "person_query"),
            routed,
        )
        self.assertIn(("spiderfoot", "example.test", "passive_target"), routed)
        self.assertIn(("shodan", "203.0.113.10", "authorized_ip"), routed)
        self.assertFalse(any(item.source == "censys" for item in plan))

    def test_connector_exception_does_not_expose_secret_url(self):
        class BrokenConnector:
            async def search(self, identifier):
                raise RuntimeError(
                    "https://provider.test/query?api_key=must-not-survive"
                )

        target = InvestigationTarget(
            name="Alice Example",
            usernames=["alice"],
            lawful_purpose="Authorized defensive review",
            authorization_confirmed=True,
        )
        policy = CollectionPolicy(
            authorization_reference="AUTH-123",
            purpose=target.lawful_purpose,
            expires_at=datetime.now(timezone.utc) + timedelta(days=1),
            permitted_sources=frozenset({"github"}),
        )
        investigator = PersonIntelligenceInvestigator(policy)
        investigator.connectors["github"] = BrokenConnector()
        results = asyncio.run(investigator.collect_plan(target=target))
        errors = " ".join(error for _, result in results for error in result.errors)
        self.assertNotIn("must-not-survive", errors)
        self.assertIn("connector request failed", errors)

    def test_consensus_excludes_single_provider_claim(self):
        evidence_id = "EVID-ABC"
        baseline = InvestigationReport(
            executive_summary="Baseline",
            identity_confidence="possible",
            overall_risk=RiskLevel.LOW,
            evidence_count=1,
            executive_summary_evidence_ids=[evidence_id],
            findings=[
                Finding(
                    title="Baseline",
                    statement="Baseline observation.",
                    evidence_ids=[evidence_id],
                    confidence=0.5,
                )
            ],
        )
        common = Finding(
            title="Common",
            statement="A public profile was observed.",
            evidence_ids=[evidence_id],
            confidence=0.7,
        )
        unique = Finding(
            title="Unique",
            statement="Unsupported provider-only synthesis.",
            evidence_ids=[evidence_id],
            confidence=0.8,
        )
        reports = [
            baseline.model_copy(update={"findings": [common, unique]}),
            baseline.model_copy(update={"findings": [common]}),
            baseline.model_copy(update={"findings": [common]}),
        ]
        result = _consensus(reports, baseline)
        self.assertEqual(
            [item.statement for item in result.findings], [common.statement]
        )


if __name__ == "__main__":
    unittest.main()
