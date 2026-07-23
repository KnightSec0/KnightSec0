import os
import sys
import unittest
from datetime import datetime, timezone


ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(ROOT, "orchestrator"))
sys.path.insert(0, ROOT)

from dashboard.app import render_report_html  # noqa: E402
from intelligence.models import Evidence, IdentityStatus, SourceReliability  # noqa: E402
from reporting.person_report import _baseline_report  # noqa: E402


class TruthfulBaselineReportTests(unittest.TestCase):
    def test_groups_candidates_and_does_not_invent_a_person_timeline(self):
        observed_at = datetime(2026, 7, 23, 12, 0, tzinfo=timezone.utc)
        evidence = [
            Evidence(
                id="EVID-SOCIAL-1",
                type="social_profile",
                value="https://www.instagram.com/alice-example/",
                source="maigret",
                source_url="https://www.instagram.com/alice-example/",
                observed_at=observed_at,
                confidence=0.58,
                reliability=SourceReliability.MEDIUM,
                identity_status=IdentityStatus.POSSIBLE,
            ),
            Evidence(
                id="EVID-SOCIAL-2",
                type="social_profile",
                value="https://www.youtube.com/@alice-example",
                source="maigret",
                source_url="https://www.youtube.com/@alice-example",
                observed_at=observed_at,
                confidence=0.58,
                reliability=SourceReliability.MEDIUM,
                identity_status=IdentityStatus.POSSIBLE,
            ),
            Evidence(
                id="EVID-SERVICE-1",
                type="service_registration",
                value="gravatar.com",
                source="holehe",
                observed_at=observed_at,
                confidence=0.62,
                reliability=SourceReliability.MEDIUM,
                identity_status=IdentityStatus.POSSIBLE,
            ),
            Evidence(
                id="EVID-SERVICE-2",
                type="service_registration",
                value="spotify.com",
                source="holehe",
                observed_at=observed_at,
                confidence=0.62,
                reliability=SourceReliability.MEDIUM,
                identity_status=IdentityStatus.POSSIBLE,
            ),
        ]
        report = _baseline_report(
            evidence,
            source_status=[
                {
                    "source": "github",
                    "status": "no_results",
                    "evidence_count": 0,
                },
                {
                    "source": "hunter",
                    "status": "unavailable",
                    "evidence_count": 0,
                    "reason_code": "missing_configuration",
                    "detail": "raw provider failure?api_key=must-not-survive",
                },
            ],
        )

        self.assertEqual(len(report.findings), 2)
        social = next(
            item for item in report.findings if "Public-profile" in item.title
        )
        services = next(
            item for item in report.findings if "service-registration" in item.title
        )
        self.assertIn("instagram.com", social.statement)
        self.assertIn("https://www.youtube.com/@alice-example", social.statement)
        self.assertIn("do not prove", social.statement)
        self.assertIn("gravatar.com", services.statement)
        self.assertIn("spotify.com", services.statement)
        self.assertIn("do not verify account ownership", services.statement)

        valid_ids = {item.id for item in evidence}
        for finding in report.findings:
            self.assertTrue(set(finding.evidence_ids).issubset(valid_ids))
        self.assertEqual(report.timeline, [])
        self.assertIn(
            "do not establish independently corroborated biographical facts",
            report.executive_summary,
        )

        coverage = {item.source: item for item in report.source_coverage}
        self.assertIn("not proof", coverage["github"].detail)
        self.assertIn("requires configuration", coverage["hunter"].detail)
        self.assertNotIn("must-not-survive", report.model_dump_json())

        rendered = render_report_html(report.model_dump(mode="json"), "Alice Example")
        self.assertIn("Confidence 58%", rendered)
        self.assertIn("Coverage note", rendered)
        self.assertIn("Collection timestamps are intentionally excluded", rendered)
        self.assertNotIn(observed_at.isoformat(), rendered)

    def test_timeline_uses_source_reported_event_dates(self):
        evidence = [
            Evidence(
                id="EVID-BREACH-1",
                type="breach",
                value="ExampleBreach",
                source="hibp",
                observed_at=datetime(2026, 7, 23, tzinfo=timezone.utc),
                confidence=0.9,
                reliability=SourceReliability.HIGH,
                metadata={
                    "breach_name": "ExampleBreach",
                    "breach_date": "2022-04-03",
                    "data_classes": ["Email addresses"],
                },
            ),
            Evidence(
                id="EVID-GITHUB-1",
                type="github_profile",
                value="https://github.com/alice-example",
                source="github",
                source_url="https://github.com/alice-example",
                observed_at=datetime(2026, 7, 23, tzinfo=timezone.utc),
                confidence=0.62,
                reliability=SourceReliability.HIGH,
                metadata={
                    "public_profile": {
                        "login": "alice-example",
                        "created_at": "2020-01-02T03:04:05Z",
                        "updated_at": "2025-06-07T08:09:10Z",
                    }
                },
            ),
        ]

        report = _baseline_report(evidence)

        self.assertEqual(len(report.timeline), 3)
        self.assertEqual(report.timeline[0].occurred_at.year, 2020)
        self.assertEqual(report.timeline[1].occurred_at.date().isoformat(), "2022-04-03")
        self.assertEqual(report.timeline[2].occurred_at.year, 2025)
        valid_ids = {item.id for item in evidence}
        for event in report.timeline:
            self.assertTrue(set(event.evidence_ids).issubset(valid_ids))
        self.assertNotIn(
            datetime(2026, 7, 23, tzinfo=timezone.utc),
            [event.occurred_at for event in report.timeline],
        )

    def test_self_published_profile_fields_are_concrete_but_not_overclaimed(self):
        evidence = Evidence(
            id="EVID-GRAVATAR-1",
            type="public_profile",
            value="https://gravatar.com/alice-example",
            source="gravatar",
            source_url="https://gravatar.com/alice-example",
            confidence=0.64,
            reliability=SourceReliability.MEDIUM,
            metadata={
                "display_name": "Alice Example",
                "location": "Paris",
                "job_title": "Engineer",
                "company": "Example Co",
                "verified_accounts": [
                    {
                        "label": "GitHub",
                        "type": "github",
                        "url": "https://github.com/alice-example",
                    }
                ],
            },
        )

        report = _baseline_report([evidence])

        statement = report.findings[0].statement
        self.assertIn("display name: Alice Example", statement)
        self.assertIn("location: Paris", statement)
        self.assertIn("job title: Engineer", statement)
        self.assertIn("GitHub (https://github.com/alice-example)", statement)
        self.assertIn("one profile source does not prove", statement)
        self.assertIn("self-published biographical fields", report.executive_summary)
        self.assertIn(
            "not independently corroborated by a single profile source",
            report.executive_summary,
        )


if __name__ == "__main__":
    unittest.main()
