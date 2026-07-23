# ruff: noqa: E402

import json
import os
import sys
import unittest
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(ROOT, "orchestrator"))

from intelligence.models import Evidence, IdentityStatus, SourceReliability
from intelligence.temporal import (
    compare_evidence_snapshots,
    stable_evidence_fingerprint,
)


def evidence(
    evidence_id,
    *,
    value="https://example.test/alice",
    source="sherlock",
    source_url="https://example.test/alice",
    observed_at=None,
    metadata=None,
    notes=None,
    confidence=0.55,
    identity_status=IdentityStatus.POSSIBLE,
):
    return Evidence(
        id=evidence_id,
        type="social_profile",
        value=value,
        source=source,
        source_url=source_url,
        observed_at=observed_at or datetime(2026, 1, 1, tzinfo=timezone.utc),
        confidence=confidence,
        reliability=SourceReliability.MEDIUM,
        identity_status=identity_status,
        notes=notes or [],
        metadata=metadata or {"platform": "Example"},
    )


class TemporalComparisonTests(unittest.TestCase):
    def test_ids_timestamps_and_correlation_wrappers_do_not_create_change(self):
        previous = evidence(
            "EVID-PREVIOUS",
            observed_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
            confidence=0.55,
            metadata={"platform": "Example"},
        )
        current = evidence(
            "EVID-CURRENT",
            observed_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            confidence=0.91,
            identity_status=IdentityStatus.PROBABLE,
            notes=[
                "Correlated from 2 observation(s) across "
                "2 independent source(s)."
            ],
            metadata={
                "platform": "Example",
                "source_count": 2,
                "observations": [
                    {
                        "id": "EVID-INNER",
                        "source": "sherlock",
                        "observed_at": "2026-01-01T00:00:00Z",
                    }
                ],
            },
        )

        result = compare_evidence_snapshots(
            [previous],
            [current],
            previous_case_id="CASE-OLD",
            current_case_id="CASE-NEW",
        )

        self.assertEqual(result.counts.persisting, 1)
        self.assertEqual(result.counts.changed, 0)
        self.assertEqual(
            result.persisting[0].previous_evidence_id, "EVID-PREVIOUS"
        )
        self.assertEqual(result.persisting[0].current_evidence_id, "EVID-CURRENT")
        self.assertEqual(result.scope.previous_case_id, "CASE-OLD")
        self.assertEqual(result.scope.current_case_id, "CASE-NEW")

    def test_added_not_observed_and_changed_have_explicit_snapshot_ids(self):
        previous = [
            evidence(
                "EVID-REMOVED",
                value="https://removed.example/alice",
                source_url="https://removed.example/alice",
            ),
            evidence("EVID-CHANGED-OLD", metadata={"platform": "Old label"}),
        ]
        current = [
            evidence(
                "EVID-ADDED",
                value="https://added.example/alice",
                source_url="https://added.example/alice",
            ),
            evidence("EVID-CHANGED-NEW", metadata={"platform": "New label"}),
        ]

        result = compare_evidence_snapshots(previous, current)

        self.assertEqual(result.counts.model_dump(), {
            "added": 1,
            "not_observed": 1,
            "persisting": 0,
            "changed": 1,
        })
        self.assertIsNone(result.added[0].previous_evidence_id)
        self.assertEqual(result.added[0].current_evidence_id, "EVID-ADDED")
        self.assertEqual(
            result.not_observed[0].previous_evidence_id, "EVID-REMOVED"
        )
        self.assertIsNone(result.not_observed[0].current_evidence_id)
        self.assertEqual(
            result.changed[0].previous_evidence_id, "EVID-CHANGED-OLD"
        )
        self.assertEqual(
            result.changed[0].current_evidence_id, "EVID-CHANGED-NEW"
        )
        self.assertEqual(result.changed[0].changed_fields, ["metadata"])
        self.assertIn("not evidence", result.scope_note)

    def test_url_fingerprint_ignores_case_slash_query_fragment_and_ids(self):
        previous = evidence(
            "EVID-ONE",
            value="HTTPS://Example.Test/Alice/?tracking=old#bio",
            source_url="HTTPS://Example.Test/Alice/?tracking=old#bio",
        )
        current = evidence(
            "EVID-TWO",
            value="https://example.test/Alice",
            source_url="https://example.test/Alice?tracking=new",
        )

        self.assertEqual(
            stable_evidence_fingerprint(previous),
            stable_evidence_fingerprint(current),
        )
        result = compare_evidence_snapshots([previous], [current])
        self.assertEqual(result.counts.persisting, 1)

    def test_identity_bearing_url_query_is_not_discarded(self):
        first = evidence(
            "EVID-ONE",
            value="https://example.test/profile?id=123",
        )
        second = evidence(
            "EVID-TWO",
            value="https://example.test/profile?id=456",
        )

        self.assertNotEqual(
            stable_evidence_fingerprint(first),
            stable_evidence_fingerprint(second),
        )
        result = compare_evidence_snapshots([first], [second])
        self.assertEqual(result.counts.not_observed, 1)
        self.assertEqual(result.counts.added, 1)

    def test_source_filter_uses_correlated_contributors_not_representative(self):
        previous = evidence(
            "EVID-OLD",
            source="sherlock",
            metadata={
                "platform": "Example",
                "observations": [
                    {"source": "maigret"},
                    {"source": "sherlock"},
                ],
                "source_count": 2,
            },
        )
        current = evidence(
            "EVID-NEW",
            source="maigret",
            metadata={
                "platform": "Example",
                "observations": [
                    {"source": "sherlock"},
                    {"source": "maigret"},
                ],
                "source_count": 2,
            },
        )

        result = compare_evidence_snapshots(
            [previous],
            [current],
            source="MAIGRET",
        )

        self.assertEqual(result.counts.persisting, 1)
        self.assertEqual(
            result.persisting[0].previous_sources, ["maigret", "sherlock"]
        )
        self.assertEqual(
            result.persisting[0].current_sources, ["maigret", "sherlock"]
        )
        self.assertEqual(result.scope.source, "MAIGRET")

    def test_output_is_deterministic_serializable_and_redaction_safe(self):
        secret = "A" * 48
        previous = [
            evidence(
                "EVID-Z",
                value="https://z.example/alice",
                source_url=(
                    f"https://user:{secret}@z.example/alice?api_key={secret}"
                ),
                metadata={"api_token": secret, "platform": "Z"},
            ),
            evidence(
                "EVID-A",
                value="https://a.example/alice",
                source_url="https://a.example/alice",
            ),
        ]

        first = compare_evidence_snapshots(previous, [])
        second = compare_evidence_snapshots(list(reversed(previous)), [])
        first_json = first.model_dump_json()

        self.assertEqual(first.model_dump(mode="json"), second.model_dump(mode="json"))
        self.assertEqual(
            [item.previous_evidence_id for item in first.not_observed],
            ["EVID-A", "EVID-Z"],
        )
        self.assertIsInstance(json.loads(first_json), dict)
        self.assertNotIn(secret, first_json)
        self.assertNotIn("api_key=", first_json)
        self.assertNotIn("user:", first_json)

    def test_redacted_long_values_are_not_treated_as_persisting_identity(self):
        previous = evidence(
            "EVID-LONG-OLD",
            value=f"https://example.test/{'A' * 48}",
            source_url=f"https://example.test/{'A' * 48}",
        )
        current = evidence(
            "EVID-LONG-NEW",
            value=f"https://example.test/{'B' * 48}",
            source_url=f"https://example.test/{'B' * 48}",
        )

        self.assertNotEqual(
            stable_evidence_fingerprint(previous),
            stable_evidence_fingerprint(current),
        )
        result = compare_evidence_snapshots([previous], [current])
        self.assertEqual(result.counts.persisting, 0)
        self.assertEqual(result.counts.changed, 0)
        self.assertEqual(result.counts.added, 1)
        self.assertEqual(result.counts.not_observed, 1)

    def test_duplicate_ids_are_rejected_within_each_snapshot(self):
        duplicate = evidence("EVID-DUPLICATE")
        with self.assertRaisesRegex(ValueError, "Duplicate evidence ID"):
            compare_evidence_snapshots([duplicate, duplicate], [])


if __name__ == "__main__":
    unittest.main()
