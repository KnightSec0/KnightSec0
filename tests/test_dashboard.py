import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

from pydantic import ValidationError

ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, ROOT)

from dashboard.app import InvestigationCreate, render_report_html  # noqa: E402


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
                authorized_ips=["203.0.113.10"],
                allow_infrastructure_enrichment=True,
            )
        )
        self.assertEqual(request.authorized_ips, ["203.0.113.10"])


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
                    },
                }
            ],
            "recommendations": ["Review <b>manually</b>."],
        }

        rendered = render_report_html(report, "Alice <script>alert('target')</script>")

        self.assertNotIn("<script>", rendered)
        self.assertNotIn("<img src=x", rendered)
        self.assertNotIn("<b>manually</b>", rendered)
        self.assertIn("&lt;script&gt;", rendered)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", rendered)
        self.assertIn("Review &lt;b&gt;manually&lt;/b&gt;.", rendered)
        self.assertNotIn("must-not-survive", rendered)
        self.assertIn("&lt;redacted&gt;", rendered)
        self.assertIn("Evidence appendix", rendered)
        self.assertGreaterEqual(rendered.count("EVID-ABC123"), 3)


if __name__ == "__main__":
    unittest.main()
