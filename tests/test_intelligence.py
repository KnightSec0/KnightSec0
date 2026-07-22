import asyncio
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(ROOT, "orchestrator"))

from intelligence.correlation import correlate_evidence
from intelligence.models import Evidence, SourceReliability
from intelligence.redaction import redact_sensitive
from reporting.person_report import PersonReportGenerator


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
            }
        )
        self.assertEqual(result["username"], "alice")
        self.assertEqual(result["password"], "<redacted>")
        self.assertEqual(result["nested"]["api_token"], "<redacted>")

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


if __name__ == "__main__":
    unittest.main()
