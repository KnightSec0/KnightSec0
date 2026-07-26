# ruff: noqa: E402

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(ROOT, "orchestrator"))

from intelligence.correlation import correlate_evidence, identity_confidence_summary
from intelligence.models import Evidence, IdentityStatus, SourceReliability


class CorrelationConfidenceTests(unittest.TestCase):
    def test_single_source_reliability_does_not_raise_identity_status(self):
        cases = [
            (0.62, SourceReliability.MEDIUM, IdentityStatus.POSSIBLE),
            (0.75, SourceReliability.HIGH, IdentityStatus.POSSIBLE),
            (0.90, SourceReliability.HIGH, IdentityStatus.POSSIBLE),
        ]
        for confidence, reliability, expected_status in cases:
            with self.subTest(confidence=confidence, reliability=reliability):
                correlated = correlate_evidence(
                    [
                        Evidence(
                            type="social_profile",
                            value="https://example.test/alice",
                            source="maigret",
                            confidence=confidence,
                            reliability=reliability,
                        )
                    ]
                )

                self.assertAlmostEqual(correlated[0].confidence, confidence)
                self.assertEqual(correlated[0].identity_status, expected_status)
                self.assertEqual(correlated[0].corroborated_by, [])

    def test_duplicate_observations_from_one_source_are_not_corroboration(self):
        correlated = correlate_evidence(
            [
                Evidence(
                    type="social_profile",
                    value="https://example.test/alice",
                    source="maigret",
                    confidence=0.62,
                    reliability=SourceReliability.MEDIUM,
                ),
                Evidence(
                    type="social_profile",
                    value="https://example.test/alice/",
                    source="maigret",
                    confidence=0.64,
                    reliability=SourceReliability.MEDIUM,
                ),
            ]
        )

        self.assertAlmostEqual(correlated[0].confidence, 0.63)
        self.assertEqual(correlated[0].identity_status, IdentityStatus.POSSIBLE)
        self.assertEqual(correlated[0].corroborated_by, [])
        self.assertEqual(
            identity_confidence_summary(correlated), IdentityStatus.POSSIBLE
        )

    def test_corroborated_by_contains_only_other_independent_sources(self):
        correlated = correlate_evidence(
            [
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
        )

        self.assertEqual(correlated[0].source, "sherlock")
        self.assertEqual(correlated[0].corroborated_by, ["maigret"])
        self.assertEqual(correlated[0].identity_status, IdentityStatus.PROBABLE)
        self.assertEqual(
            identity_confidence_summary(correlated), IdentityStatus.PROBABLE
        )

    def test_overlapping_catalog_adapters_are_not_independent(self):
        correlated = correlate_evidence(
            [
                Evidence(
                    type="social_profile",
                    value="https://example.test/alice",
                    source="blackbird",
                    independence_group="whatsmyname-catalog",
                    confidence=0.58,
                ),
                Evidence(
                    type="social_profile",
                    value="https://example.test/alice/",
                    source="whatsmyname",
                    independence_group="whatsmyname-catalog",
                    confidence=0.60,
                ),
            ]
        )

        self.assertEqual(correlated[0].corroborated_by, [])
        self.assertEqual(correlated[0].identity_status, IdentityStatus.POSSIBLE)
        self.assertEqual(correlated[0].metadata["source_count"], 1)
        self.assertEqual(correlated[0].metadata["collector_count"], 2)

    def test_identity_summary_caps_uncorroborated_claim_at_possible(self):
        evidence = [
            Evidence(
                type="github_profile",
                value="https://github.com/alice",
                source="github",
                confidence=0.95,
                reliability=SourceReliability.HIGH,
                identity_status=IdentityStatus.CONFIRMED,
            )
        ]

        self.assertEqual(
            identity_confidence_summary(evidence), IdentityStatus.POSSIBLE
        )

    def test_explicit_unrelated_status_survives_correlation(self):
        correlated = correlate_evidence(
            [
                Evidence(
                    type="social_profile",
                    value="https://example.test/not-alice",
                    source="brave",
                    confidence=0.91,
                    reliability=SourceReliability.HIGH,
                    identity_status=IdentityStatus.UNRELATED,
                )
            ]
        )

        self.assertEqual(
            correlated[0].identity_status,
            IdentityStatus.UNRELATED,
        )
        self.assertEqual(
            identity_confidence_summary(correlated),
            IdentityStatus.UNRELATED,
        )

    def test_identity_summary_prefers_defensible_cross_source_status(self):
        uncorroborated = Evidence(
            type="github_profile",
            value="https://github.com/alice",
            source="github",
            confidence=0.95,
            reliability=SourceReliability.HIGH,
            identity_status=IdentityStatus.CONFIRMED,
        )
        correlated = correlate_evidence(
            [
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
        )[0]

        self.assertEqual(
            identity_confidence_summary([uncorroborated, correlated]),
            IdentityStatus.PROBABLE,
        )


if __name__ == "__main__":
    unittest.main()
