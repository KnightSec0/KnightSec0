import os
import sys
import unittest


ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(ROOT, "orchestrator"))

from intelligence.correlation import correlate_evidence  # noqa: E402
from intelligence.models import Evidence, IdentityStatus  # noqa: E402
from intelligence.quality import (  # noqa: E402
    canonical_profile_url,
    evidence_quality,
    quality_summary,
    refine_evidence_quality,
)
from reporting.person_report import _baseline_report  # noqa: E402


class ResultQualityTests(unittest.TestCase):
    def test_profile_url_variants_collapse_without_catalogue_vote_inflation(self):
        evidence = [
            Evidence(
                id="EVID-SHERLOCK",
                type="social_profile",
                value="https://www.youtube.com/@alice/about",
                source="sherlock",
                source_url="https://www.youtube.com/@alice/about",
                confidence=0.55,
                identity_status=IdentityStatus.POSSIBLE,
                metadata={"username": "alice"},
            ),
            Evidence(
                id="EVID-MAIGRET",
                type="social_profile",
                value="https://youtube.com/@alice/",
                source="maigret",
                source_url="https://youtube.com/@alice/",
                confidence=0.58,
                identity_status=IdentityStatus.POSSIBLE,
                metadata={"username": "alice"},
            ),
        ]

        refined = refine_evidence_quality(evidence, {"username": "alice"})
        correlated = correlate_evidence(refined)

        self.assertEqual(len(correlated), 1)
        self.assertEqual(correlated[0].value, "https://youtube.com/@alice")
        self.assertEqual(correlated[0].confidence, 0.15)
        self.assertEqual(
            correlated[0].identity_status,
            IdentityStatus.INSUFFICIENT_EVIDENCE,
        )
        self.assertEqual(correlated[0].metadata["source_count"], 1)
        self.assertEqual(correlated[0].metadata["collector_count"], 2)
        self.assertEqual(
            correlated[0].metadata["quality"]["verification_status"],
            "catalogue_only",
        )

    def test_sensitive_username_only_candidate_is_quarantined(self):
        evidence = Evidence(
            type="social_profile",
            value="https://chaturbate.com/alice/",
            source="maigret",
            source_url="https://chaturbate.com/alice/",
            confidence=0.58,
            identity_status=IdentityStatus.POSSIBLE,
            metadata={"username": "alice"},
        )

        refined = refine_evidence_quality([evidence], {"username": "alice"})[0]
        quality = evidence_quality(refined)

        self.assertEqual(quality["verification_status"], "quarantined")
        self.assertEqual(quality["category"], "quarantined_candidates")
        self.assertTrue(quality["sensitive"])
        self.assertLessEqual(refined.confidence, 0.15)
        self.assertEqual(
            refined.identity_status,
            IdentityStatus.INSUFFICIENT_EVIDENCE,
        )

    def test_multiple_observed_context_attributes_make_profile_probable(self):
        evidence = Evidence(
            type="public_profile",
            value="https://profiles.example-security.com/alice",
            source="gravatar",
            confidence=0.64,
            identity_status=IdentityStatus.POSSIBLE,
            metadata={
                "display_name": "Alice Example",
                "company": "Example Security",
                "location": "Paris",
            },
        )

        refined = refine_evidence_quality(
            [evidence],
            {
                "name": "Alice Example",
                "employer": "Example Security",
                "location": "Paris",
            },
        )[0]
        quality = evidence_quality(refined)

        self.assertEqual(
            quality["matched_attributes"],
            ["name", "employer", "location"],
        )
        self.assertEqual(quality["verification_status"], "probable")
        self.assertEqual(quality["category"], "probable_profiles")
        self.assertGreaterEqual(refined.confidence, 0.68)

    def test_service_presence_is_not_identity_confidence(self):
        evidence = Evidence(
            type="service_registration",
            value="spotify.com",
            source="holehe",
            confidence=0.62,
            identity_status=IdentityStatus.POSSIBLE,
        )

        refined = refine_evidence_quality([evidence], {"email": "a@example.com"})[0]

        self.assertEqual(refined.confidence, 0.30)
        self.assertEqual(
            refined.identity_status,
            IdentityStatus.INSUFFICIENT_EVIDENCE,
        )
        self.assertEqual(
            evidence_quality(refined)["category"],
            "service_signals",
        )

    def test_quality_summary_separates_actionable_and_noisy_results(self):
        items = refine_evidence_quality(
            [
                Evidence(
                    type="social_profile",
                    value="https://example-security.com/alice",
                    source="sherlock",
                    confidence=0.55,
                ),
                Evidence(
                    type="service_registration",
                    value="spotify.com",
                    source="holehe",
                    confidence=0.62,
                ),
                Evidence(
                    type="social_profile",
                    value="https://chaturbate.com/alice",
                    source="maigret",
                    confidence=0.58,
                ),
            ],
            {"username": "alice"},
        )

        summary = quality_summary(items)

        self.assertEqual(summary["unverified"], 1)
        self.assertEqual(summary["catalogue_only"], 1)
        self.assertEqual(summary["quarantined"], 1)
        self.assertEqual(summary["possible"], 0)

    def test_canonical_profile_url_preserves_identity_query_only(self):
        self.assertEqual(
            canonical_profile_url(
                "http://www.digitalpoint.com/members/?username=alice&utm_source=x"
            ),
            "https://digitalpoint.com/members?username=alice",
        )

    def test_quality_deduplication_preserves_exact_navigation_url(self):
        source_url = (
            "http://www.digitalpoint.com/members/?username=alice&utm_source=x"
        )
        evidence = Evidence(
            type="social_profile",
            value=source_url,
            source="sherlock",
            source_url=source_url,
            confidence=0.55,
        )

        refined = refine_evidence_quality([evidence], {"username": "alice"})[0]

        self.assertEqual(
            refined.value,
            "https://digitalpoint.com/members?username=alice",
        )
        self.assertEqual(refined.source_url, source_url)

    def test_username_punctuation_is_not_collapsed_for_identity_matching(self):
        evidence = Evidence(
            type="public_profile",
            value="https://profiles.example/johnsmith",
            source="public-directory",
            confidence=0.60,
            metadata={"observed_username": "johnsmith"},
        )

        refined = refine_evidence_quality(
            [evidence],
            {"username": "john.smith"},
        )[0]

        self.assertNotIn(
            "username",
            evidence_quality(refined)["matched_attributes"],
        )
        self.assertEqual(
            refined.identity_status,
            IdentityStatus.INSUFFICIENT_EVIDENCE,
        )

    def test_person_search_requires_two_identity_attributes(self):
        name_only = Evidence(
            type="person_search_result",
            value="https://example.test/article/alice-example",
            source="brave",
            source_url="https://example.test/article/alice-example",
            confidence=0.60,
            metadata={"title": "Alice Example profile"},
        )
        contextual = Evidence(
            type="person_search_result",
            value="https://example.test/team/alice-example",
            source="brave",
            source_url="https://example.test/team/alice-example",
            confidence=0.60,
            metadata={
                "title": "Alice Example — Example Security",
                "description": "Alice leads research in Paris.",
            },
        )

        refined = refine_evidence_quality(
            [name_only, contextual],
            {
                "name": "Alice Example",
                "employer": "Example Security",
                "location": "Paris",
            },
        )

        self.assertEqual(
            evidence_quality(refined[0])["verification_status"],
            "insufficient_context",
        )
        self.assertEqual(
            evidence_quality(refined[1])["verification_status"],
            "probable",
        )

    def test_unavailable_page_cannot_remain_confirmed(self):
        evidence = Evidence(
            type="social_profile",
            value="https://example.test/alice",
            source="sherlock",
            source_url="https://example.test/alice",
            confidence=0.99,
            identity_status=IdentityStatus.CONFIRMED,
            metadata={"http_status": 404, "profile_exists": False},
        )

        refined = refine_evidence_quality([evidence], {"username": "alice"})[0]

        self.assertEqual(
            evidence_quality(refined)["verification_status"],
            "rejected",
        )
        self.assertEqual(
            refined.identity_status,
            IdentityStatus.INSUFFICIENT_EVIDENCE,
        )

    def test_noisy_case_is_inconclusive_and_grouped_away_from_identity(self):
        raw = [
            Evidence(
                type="social_profile",
                value="https://youtube.com/@alice",
                source="sherlock",
                confidence=0.55,
            ),
            Evidence(
                type="social_profile",
                value="https://instagram.com/alice",
                source="maigret",
                confidence=0.58,
            ),
            Evidence(
                type="service_registration",
                value="spotify.com",
                source="holehe",
                confidence=0.62,
            ),
        ]
        refined = refine_evidence_quality(raw, {"username": "alice"})
        report = _baseline_report(
            correlate_evidence(refined),
            source_status=[
                {"source": "sherlock", "status": "evidence_collected"},
                {"source": "maigret", "status": "evidence_collected"},
                {"source": "holehe", "status": "evidence_collected"},
                {"source": "spiderfoot", "status": "unavailable"},
                {"source": "brave", "status": "unavailable"},
            ],
        )

        self.assertEqual(report.identity_confidence, "insufficient_evidence")
        self.assertEqual(report.overall_risk.value, "unknown")
        self.assertEqual(report.coverage_assessment, "insufficient")
        self.assertEqual(report.result_quality["unverified"], 1)
        self.assertEqual(report.result_quality["catalogue_only"], 2)
        self.assertEqual(
            {item.category for item in report.findings},
            {"catalogue_leads", "service_signals"},
        )
        self.assertIn("inconclusive rather than low", report.executive_summary)


if __name__ == "__main__":
    unittest.main()
