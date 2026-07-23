import asyncio
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(ROOT, "orchestrator"))

from intelligence.correlation import correlate_evidence
from intelligence.models import Evidence, SourceReliability
from intelligence.models import InvestigationTarget
from intelligence.policy import CollectionPolicy
from intelligence.redaction import redact_sensitive
from reporting.person_report import PersonReportGenerator, _consensus
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
            }
        )
        self.assertEqual(result["username"], "alice")
        self.assertEqual(result["password"], "<redacted>")
        self.assertEqual(result["nested"]["api_token"], "<redacted>")
        self.assertEqual(result["raw_leak"], "<redacted>")

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
        valid_ids = {finding.evidence_ids[0] for finding in report.findings}
        self.assertTrue(valid_ids)
        for event in report.timeline:
            self.assertTrue(set(event.evidence_ids).issubset(valid_ids))

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
