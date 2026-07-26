# ruff: noqa: E402

import json
import os
import sys
import unittest

from pydantic import ValidationError


ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(ROOT, "orchestrator"))

from intelligence.identity_graph import (
    AnalystPivot,
    GraphEdge,
    GraphNode,
    IdentityGraph,
    IdentityHypothesis,
    ProvenanceStep,
    build_identity_graph,
)
from intelligence.correlation import correlate_evidence
from intelligence.models import Evidence, IdentityStatus, SourceReliability


def evidence(
    evidence_id,
    *,
    source,
    evidence_type="social_profile",
    value="https://example.test/alice",
    source_url=None,
    confidence=0.9,
    metadata=None,
    identity_status=IdentityStatus.CONFIRMED,
):
    return Evidence(
        id=evidence_id,
        type=evidence_type,
        value=value,
        source=source,
        source_url=source_url,
        confidence=confidence,
        reliability=SourceReliability.HIGH,
        identity_status=identity_status,
        metadata=metadata or {},
    )


def target_edges(graph):
    return [
        edge
        for edge in graph.edges
        if edge.source_node_id == graph.target_node_id
    ]


def edge_for_label(graph, label):
    node = next(node for node in graph.nodes if node.label == label)
    return next(
        edge
        for edge in target_edges(graph)
        if edge.target_node_id == node.id
    )


class IdentityGraphTests(unittest.TestCase):
    def test_single_source_is_serializable_deterministic_and_only_possible(self):
        item = evidence("EVID-ONE", source="github")
        context = {
            "name": "Alice Example",
            "employer": "Example Corp",
            "emails": ["unobserved@example.test"],
            "usernames": ["unobserved-handle"],
            "phones": ["+33123456789"],
        }

        first = build_identity_graph([item], context)
        second = build_identity_graph([item], context)

        self.assertEqual(
            first.model_dump(mode="json"),
            second.model_dump(mode="json"),
        )
        serialized = first.model_dump_json()
        json.loads(serialized)
        self.assertNotIn("unobserved@example.test", serialized)
        self.assertNotIn("unobserved-handle", serialized)
        self.assertNotIn("+33123456789", serialized)
        association = edge_for_label(first, "https://example.test/alice")
        self.assertEqual(association.identity_status, IdentityStatus.POSSIBLE)
        self.assertLessEqual(association.confidence, 0.64)
        self.assertEqual(association.evidence_ids, ["EVID-ONE"])
        self.assertEqual(association.independent_source_count, 1)

    def test_explicit_unrelated_evidence_never_becomes_a_candidate(self):
        item = evidence(
            "EVID-UNRELATED",
            source="brave",
            value="https://example.test/different-alice",
            identity_status=IdentityStatus.UNRELATED,
        )
        correlated = correlate_evidence([item])
        self.assertEqual(
            correlated[0].identity_status,
            IdentityStatus.UNRELATED,
        )

        graph = build_identity_graph(correlated, {"name": "Alice Example"})
        association = edge_for_label(
            graph,
            "https://example.test/different-alice",
        )
        self.assertEqual(
            association.relationship,
            "disambiguated_unrelated_observation",
        )
        self.assertEqual(
            association.identity_status,
            IdentityStatus.UNRELATED,
        )
        hypothesis = next(
            item
            for item in graph.hypotheses
            if item.object_node_id == association.target_node_id
        )
        self.assertIn("must not be attributed", hypothesis.claim)

    def test_two_username_scanners_do_not_become_independent_sources(self):
        items = [
            evidence(
                "EVID-MAIGRET",
                source="maigret",
                value="https://social.example/alice/",
                source_url="https://social.example/alice/",
            ),
            evidence(
                "EVID-SHERLOCK",
                source="sherlock",
                value="https://social.example/alice",
                source_url="https://social.example/alice",
            ),
        ]

        graph = build_identity_graph(items, {"name": "Alice Example"})
        association = edge_for_label(graph, "https://social.example/alice")

        self.assertEqual(association.identity_status, IdentityStatus.POSSIBLE)
        self.assertEqual(association.independent_source_count, 1)
        self.assertLessEqual(association.confidence, 0.64)
        hypothesis = next(
            item
            for item in graph.hypotheses
            if item.object_node_id == association.target_node_id
        )
        self.assertIn("not independent", " ".join(hypothesis.limitations))

    def test_correlated_wrapper_preserves_safe_publisher_independence(self):
        native_and_directory = correlate_evidence(
            [
                evidence(
                    "EVID-NATIVE-INNER",
                    source="github",
                    value="https://github.com/alice",
                    source_url="https://github.com/alice",
                    confidence=0.66,
                ),
                evidence(
                    "EVID-DIRECTORY-INNER",
                    source="public_directory",
                    value="https://github.com/alice/",
                    source_url="https://directory.example/people/alice",
                    confidence=0.60,
                ),
            ]
        )
        self.assertEqual(len(native_and_directory), 1)
        ledger_id = native_and_directory[0].id

        graph = build_identity_graph(
            native_and_directory,
            {"name": "Alice"},
        )
        association = edge_for_label(graph, "https://github.com/alice")

        self.assertEqual(association.identity_status, IdentityStatus.PROBABLE)
        self.assertEqual(association.independent_source_count, 2)
        self.assertEqual(association.evidence_ids, [ledger_id])
        self.assertEqual(
            {step.evidence_id for step in association.provenance_chain},
            {ledger_id},
        )
        self.assertEqual(
            {step.source for step in association.provenance_chain},
            {"github", "public_directory"},
        )

        scanner_wrapper = correlate_evidence(
            [
                evidence(
                    "EVID-MAIGRET-INNER",
                    source="maigret",
                    value="https://social.example/alice",
                    source_url="https://social.example/alice",
                ),
                evidence(
                    "EVID-SHERLOCK-INNER",
                    source="sherlock",
                    value="https://social.example/alice/",
                    source_url="https://social.example/alice/",
                ),
            ]
        )
        scanner_graph = build_identity_graph(
            scanner_wrapper,
            {"name": "Alice"},
        )
        scanner_association = edge_for_label(
            scanner_graph,
            "https://social.example/alice",
        )
        self.assertEqual(
            scanner_association.identity_status,
            IdentityStatus.POSSIBLE,
        )
        self.assertEqual(scanner_association.independent_source_count, 1)

    def test_exact_url_from_independent_publishers_can_be_probable(self):
        items = [
            evidence(
                "EVID-NATIVE",
                source="github",
                value="https://github.com/alice/",
                source_url="https://github.com/alice/",
                confidence=0.66,
            ),
            evidence(
                "EVID-DIRECTORY",
                source="public_directory",
                value="https://github.com/alice",
                source_url="https://directory.example/people/alice",
                confidence=0.60,
            ),
        ]

        graph = build_identity_graph(list(reversed(items)), {"name": "Alice"})
        association = edge_for_label(graph, "https://github.com/alice")

        self.assertEqual(association.identity_status, IdentityStatus.PROBABLE)
        self.assertEqual(association.independent_source_count, 2)
        self.assertEqual(
            set(association.evidence_ids),
            {"EVID-NATIVE", "EVID-DIRECTORY"},
        )
        self.assertLess(association.confidence, 0.80)
        self.assertIn("not confirmed", association.explanation)

    def test_verified_public_link_needs_an_independent_direct_observation(self):
        gravatar = evidence(
            "EVID-GRAVATAR",
            source="gravatar",
            evidence_type="public_profile",
            value="https://gravatar.com/alice",
            source_url="https://gravatar.com/alice",
            confidence=0.64,
            metadata={
                "display_name": "Alice Example",
                "verified_accounts": [
                    {
                        "url": "https://github.com/alice/",
                        "label": "GitHub",
                        "type": "github",
                    }
                ],
            },
        )

        graph = build_identity_graph([gravatar], {"name": "Alice Example"})
        linked = edge_for_label(graph, "https://github.com/alice")
        verified_edge = next(
            edge
            for edge in graph.edges
            if edge.relationship == "verified_public_account_link"
        )

        self.assertEqual(linked.identity_status, IdentityStatus.POSSIBLE)
        self.assertEqual(linked.independent_source_count, 1)
        self.assertEqual(verified_edge.identity_status, IdentityStatus.POSSIBLE)
        self.assertEqual(verified_edge.evidence_ids, ["EVID-GRAVATAR"])
        self.assertEqual(
            verified_edge.provenance_chain[0].role,
            "verified_public_link",
        )

        github = evidence(
            "EVID-GITHUB",
            source="github",
            evidence_type="github_profile",
            value="https://github.com/alice",
            source_url="https://github.com/alice",
            confidence=0.67,
        )
        corroborated = build_identity_graph(
            [gravatar, github],
            {"name": "Alice Example"},
        )
        linked = edge_for_label(corroborated, "https://github.com/alice")
        self.assertEqual(linked.identity_status, IdentityStatus.PROBABLE)
        self.assertEqual(linked.independent_source_count, 2)
        self.assertEqual(
            set(linked.evidence_ids),
            {"EVID-GITHUB", "EVID-GRAVATAR"},
        )

    def test_no_identifiers_are_extracted_or_invented_from_profile_urls(self):
        item = evidence(
            "EVID-PROFILE",
            source="maigret",
            value="https://social.example/@alice",
        )
        graph = build_identity_graph(
            [item],
            {
                "name": "Alice Example",
                "emails": ["invent-me@example.test"],
                "usernames": ["invent-me"],
                "phones": ["+999999999"],
            },
        )
        dumped = graph.model_dump(mode="json")
        serialized = json.dumps(dumped)

        self.assertNotIn("invent-me@example.test", serialized)
        self.assertNotIn("+999999999", serialized)
        self.assertFalse(
            any(node.kind == "email_identifier" for node in graph.nodes)
        )
        self.assertFalse(
            any(node.kind == "phone_identifier" for node in graph.nodes)
        )
        self.assertFalse(
            any(
                node.kind == "username_observation" and node.label == "alice"
                for node in graph.nodes
            )
        )

    def test_dark_web_and_credential_material_is_excluded(self):
        safe = evidence(
            "EVID-SAFE",
            source="github",
            value="https://github.com/alice",
        )
        blocked = [
            evidence(
                "EVID-PASSWORD",
                source="leak_import",
                evidence_type="password",
                value="password=hunter2",
            ),
            evidence(
                "EVID-ONION",
                source="darkweb",
                evidence_type="web_profile",
                value="http://examplehiddenservice.onion/alice",
            ),
            evidence(
                "EVID-TOKEN",
                source="manual",
                evidence_type="note",
                value="access_token=must-not-survive",
            ),
        ]

        graph = build_identity_graph([safe, *blocked], {"name": "Alice"})
        serialized = graph.model_dump_json()

        self.assertEqual(
            set(graph.excluded_evidence_ids),
            {"EVID-PASSWORD", "EVID-ONION", "EVID-TOKEN"},
        )
        self.assertEqual(
            {reference.id for reference in graph.evidence_index},
            {"EVID-SAFE"},
        )
        self.assertNotIn("hunter2", serialized)
        self.assertNotIn("must-not-survive", serialized)
        self.assertNotIn(".onion", serialized)

    def test_every_asserting_object_cites_valid_evidence_and_full_chain(self):
        items = [
            evidence(
                "EVID-A",
                source="github",
                value="https://github.com/alice",
            ),
            evidence(
                "EVID-B",
                source="directory",
                value="https://github.com/alice",
                source_url="https://directory.example/alice",
            ),
            evidence(
                "EVID-C",
                source="holehe",
                evidence_type="service_registration",
                value="spotify.com",
                confidence=0.62,
                metadata={"service": "spotify.com", "registered": True},
            ),
        ]
        graph = build_identity_graph(items, {"name": "Alice"})
        valid_ids = {reference.id for reference in graph.evidence_index}

        for obj in [*graph.edges, *graph.hypotheses, *graph.pivots]:
            self.assertTrue(obj.evidence_ids)
            self.assertTrue(set(obj.evidence_ids).issubset(valid_ids))
            self.assertEqual(
                set(obj.evidence_ids),
                {step.evidence_id for step in obj.provenance_chain},
            )
        self.assertEqual(
            [pivot.rank for pivot in graph.pivots],
            list(range(1, len(graph.pivots) + 1)),
        )
        self.assertTrue(
            all(pivot.execution_mode == "manual_review_only" for pivot in graph.pivots)
        )
        self.assertTrue(all(pivot.requires_authorization for pivot in graph.pivots))

    def test_breach_graph_keeps_metadata_but_not_raw_credentials(self):
        item = evidence(
            "EVID-BREACH",
            source="hibp",
            evidence_type="breach",
            value="alice@example.test",
            source_url="https://haveibeenpwned.com/",
            confidence=0.8,
            metadata={
                "breach_name": "Example Breach",
                "breach_date": "2024-01-02",
                "data_classes": ["Email addresses", "Passwords"],
                "password": "must-not-survive",
                "raw_record": "must-not-survive",
            },
        )

        graph = build_identity_graph([item], {"name": "Alice"})
        serialized = graph.model_dump_json()
        breach_node = next(
            node for node in graph.nodes if node.kind == "breach_event"
        )

        self.assertEqual(breach_node.label, "Breach metadata: Example Breach")
        self.assertEqual(
            breach_node.attributes["data_classes"],
            ["Email addresses", "Passwords"],
        )
        self.assertNotIn("alice@example.test", serialized)
        self.assertNotIn("must-not-survive", serialized)
        self.assertIn("No passwords", graph.hypotheses[0].claim)

    def test_redacted_long_profile_values_never_merge_into_probable_identity(self):
        items = [
            evidence(
                "EVID-LONG-A",
                source="directory-a",
                value=f"https://profiles.example/{'A' * 48}",
                source_url="https://directory-a.example/alice",
            ),
            evidence(
                "EVID-LONG-B",
                source="directory-b",
                value=f"https://profiles.example/{'B' * 48}",
                source_url="https://directory-b.example/alice",
            ),
        ]

        graph = build_identity_graph(items, {"name": "Alice"})
        target_associations = target_edges(graph)
        self.assertEqual(len(target_associations), 2)
        self.assertTrue(
            all(
                edge.identity_status != IdentityStatus.PROBABLE
                for edge in target_associations
            )
        )
        self.assertNotIn("A" * 48, graph.model_dump_json())
        self.assertNotIn("B" * 48, graph.model_dump_json())

    def test_empty_evidence_produces_only_target_context(self):
        graph = build_identity_graph(
            [],
            {
                "name": "Alice",
                "location": "Paris",
                "password": "must-not-survive",
            },
        )

        self.assertEqual(len(graph.nodes), 1)
        self.assertEqual(graph.nodes[0].kind, "authorized_target")
        self.assertEqual(graph.edges, [])
        self.assertEqual(graph.hypotheses, [])
        self.assertEqual(graph.pivots, [])
        self.assertEqual(graph.evidence_index, [])
        self.assertNotIn("must-not-survive", graph.model_dump_json())

    def test_graph_validator_rejects_unknown_evidence_references(self):
        step = ProvenanceStep(
            evidence_id="EVID-MISSING",
            source="github",
            role="direct_observation",
            independence_key="publisher:github.com",
            explanation="Observed.",
        )
        target = GraphNode(id="target", kind="authorized_target", label="Alice")
        profile = GraphNode(
            id="profile",
            kind="public_profile",
            label="https://github.com/alice",
            evidence_ids=["EVID-MISSING"],
        )
        edge = GraphEdge(
            id="edge",
            source_node_id="target",
            target_node_id="profile",
            relationship="candidate_identity_association",
            confidence=0.5,
            identity_status=IdentityStatus.POSSIBLE,
            evidence_ids=["EVID-MISSING"],
            independent_source_count=1,
            explanation="Candidate.",
            provenance_chain=[step],
        )
        hypothesis = IdentityHypothesis(
            id="hypothesis",
            subject_node_id="target",
            object_node_id="profile",
            claim="Candidate.",
            confidence=0.5,
            identity_status=IdentityStatus.POSSIBLE,
            evidence_ids=["EVID-MISSING"],
            independent_source_count=1,
            provenance_chain=[step],
        )
        pivot = AnalystPivot(
            id="pivot",
            rank=1,
            node_id="profile",
            title="Review",
            rationale="Candidate.",
            action="Review manually.",
            priority="medium",
            evidence_ids=["EVID-MISSING"],
            provenance_chain=[step],
        )

        with self.assertRaises(ValidationError):
            IdentityGraph(
                target_node_id="target",
                nodes=[target, profile],
                edges=[edge],
                hypotheses=[hypothesis],
                pivots=[pivot],
                evidence_index=[],
            )


if __name__ == "__main__":
    unittest.main()
