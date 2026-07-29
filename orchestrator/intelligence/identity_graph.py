"""Policy-safe, explainable identity graph construction.

This module turns already-collected :class:`~intelligence.models.Evidence`
objects into a deterministic analyst aid.  It does not collect data, execute
queries, infer new identifiers, or treat username-search-tool agreement as
independent identity corroboration.
"""

from __future__ import annotations

from collections import defaultdict
from hashlib import sha256
import json
import re
from statistics import mean
from typing import Any, Literal
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from pydantic import BaseModel, Field, model_validator

from .models import Evidence, IdentityStatus
from .redaction import redact_sensitive


_BLOCKED_MARKERS = {
    "cookie",
    "credential",
    "dark web",
    "dark_web",
    "darkweb",
    "leaked credential",
    "leaked record",
    "password",
    "private communication",
    "private message",
    "private_communication",
    "private_message",
    "raw leak",
    "raw record",
    "raw_leak",
    "raw_record",
    "session token",
}
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(?:api[_ -]?key|access[_ -]?token|cookie|credential|password|"
    r"private[_ -]?message|secret|session[_ -]?token)\s*[:=]"
)
_SECRET_QUERY_KEYS = {
    "access_token",
    "api-key",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "key",
    "password",
    "secret",
    "session",
    "token",
}
_PROFILE_TYPES = {
    "github_profile",
    "person_search_result",
    "public_profile",
    "social_profile",
    "web_profile",
}
_SERVICE_TYPES = {"service_registration", "service_presence"}
_BREACH_TYPES = {"breach", "breach_metadata"}
_EMAIL_TYPES = {"email", "email_verification", "email_enrichment"}
_PHONE_TYPES = {"phone", "phone_number", "phone_verification"}
_USERNAME_TYPES = {"username", "username_match", "username_similarity"}
_TARGET_CONTEXT_FIELDS = ("name", "employer", "location")
_PUBLIC_PROFILE_FIELDS = {
    "bio",
    "blog",
    "company",
    "description",
    "display_name",
    "first_name",
    "job_title",
    "languages",
    "last_name",
    "location",
    "login",
    "preferred_username",
    "profile_url",
}
_BREACH_FIELDS = {
    "breach_date",
    "breach_name",
    "data_classes",
    "domain",
    "is_spam_list",
    "modified_date",
}
_EMAIL_RESULT_FIELDS = {
    "accept_all",
    "disposable",
    "result",
    "score",
    "status",
    "webmail",
}
_SERVICE_FIELDS = {"registered", "service", "status"}
_PRIORITY_ORDER = {"high": 0, "medium": 1, "low": 2}


class ProvenanceStep(BaseModel):
    """One evidence-backed step in an explainable provenance chain."""

    evidence_id: str
    source: str
    role: Literal["direct_observation", "verified_public_link"]
    independence_key: str
    explanation: str


class EvidenceReference(BaseModel):
    """Minimal evidence index without raw connector payloads."""

    id: str
    type: str
    source: str
    source_url: str | None = None


class GraphNode(BaseModel):
    """A target, publisher, profile, or other observed public entity."""

    id: str
    kind: str
    label: str
    attributes: dict[str, Any] = Field(default_factory=dict)
    evidence_ids: list[str] = Field(default_factory=list)


class GraphEdge(BaseModel):
    """A cited relationship between two graph nodes."""

    id: str
    source_node_id: str
    target_node_id: str
    relationship: str
    confidence: float = Field(ge=0.0, le=1.0)
    identity_status: IdentityStatus
    evidence_ids: list[str] = Field(min_length=1)
    independent_source_count: int = Field(ge=1)
    explanation: str
    provenance_chain: list[ProvenanceStep] = Field(min_length=1)


class IdentityHypothesis(BaseModel):
    """An explicitly uncertain, evidence-linked candidate association."""

    id: str
    subject_node_id: str
    object_node_id: str
    claim: str
    confidence: float = Field(ge=0.0, le=1.0)
    identity_status: IdentityStatus
    evidence_ids: list[str] = Field(min_length=1)
    independent_source_count: int = Field(ge=1)
    provenance_chain: list[ProvenanceStep] = Field(min_length=1)
    limitations: list[str] = Field(default_factory=list)


class AnalystPivot(BaseModel):
    """A ranked manual review recommendation, never an executable query."""

    id: str
    rank: int = Field(ge=1)
    node_id: str
    title: str
    rationale: str
    action: str
    priority: Literal["high", "medium", "low"]
    evidence_ids: list[str] = Field(min_length=1)
    provenance_chain: list[ProvenanceStep] = Field(min_length=1)
    requires_authorization: bool = True
    execution_mode: Literal["manual_review_only"] = "manual_review_only"


class IdentityGraph(BaseModel):
    """Serializable graph with strict node and evidence-reference integrity."""

    schema_version: Literal["1.0"] = "1.0"
    target_node_id: str
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    hypotheses: list[IdentityHypothesis]
    pivots: list[AnalystPivot]
    evidence_index: list[EvidenceReference]
    excluded_evidence_ids: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_graph_integrity(self) -> "IdentityGraph":
        node_ids = [node.id for node in self.nodes]
        if len(node_ids) != len(set(node_ids)):
            raise ValueError("Graph node IDs must be unique")
        if self.target_node_id not in set(node_ids):
            raise ValueError("Target node must exist in the graph")

        valid_evidence_ids = {reference.id for reference in self.evidence_index}
        if len(valid_evidence_ids) != len(self.evidence_index):
            raise ValueError("Evidence IDs must be unique")

        def check_references(
            *,
            evidence_ids: list[str],
            chain: list[ProvenanceStep],
            label: str,
        ) -> None:
            referenced = set(evidence_ids)
            chain_ids = {step.evidence_id for step in chain}
            if not referenced or not referenced.issubset(valid_evidence_ids):
                raise ValueError(f"{label} cites an unknown evidence ID")
            if chain_ids != referenced:
                raise ValueError(
                    f"{label} provenance must cover exactly its evidence IDs"
                )

        all_node_ids = set(node_ids)
        for node in self.nodes:
            if not set(node.evidence_ids).issubset(valid_evidence_ids):
                raise ValueError("Graph node cites an unknown evidence ID")
        for edge in self.edges:
            if {
                edge.source_node_id,
                edge.target_node_id,
            } - all_node_ids:
                raise ValueError("Graph edge references an unknown node")
            check_references(
                evidence_ids=edge.evidence_ids,
                chain=edge.provenance_chain,
                label=f"Edge {edge.id}",
            )
            source_count = len(
                {step.independence_key for step in edge.provenance_chain}
            )
            if edge.independent_source_count != source_count:
                raise ValueError("Edge independent-source count is inconsistent")
            if (
                edge.identity_status
                in {
                    IdentityStatus.PROBABLE,
                    IdentityStatus.HIGHLY_PROBABLE,
                    IdentityStatus.CONFIRMED,
                }
                and source_count < 2
            ):
                raise ValueError(
                    "Probable identity edges require independent provenance"
                )

        for hypothesis in self.hypotheses:
            if {
                hypothesis.subject_node_id,
                hypothesis.object_node_id,
            } - all_node_ids:
                raise ValueError("Identity hypothesis references an unknown node")
            check_references(
                evidence_ids=hypothesis.evidence_ids,
                chain=hypothesis.provenance_chain,
                label=f"Hypothesis {hypothesis.id}",
            )
            source_count = len(
                {step.independence_key for step in hypothesis.provenance_chain}
            )
            if hypothesis.independent_source_count != source_count:
                raise ValueError(
                    "Hypothesis independent-source count is inconsistent"
                )
            if (
                hypothesis.identity_status
                in {
                    IdentityStatus.PROBABLE,
                    IdentityStatus.HIGHLY_PROBABLE,
                    IdentityStatus.CONFIRMED,
                }
                and source_count < 2
            ):
                raise ValueError(
                    "Probable identity hypotheses require independent provenance"
                )

        expected_ranks = list(range(1, len(self.pivots) + 1))
        if [pivot.rank for pivot in self.pivots] != expected_ranks:
            raise ValueError("Analyst pivot ranks must be consecutive")
        for pivot in self.pivots:
            if pivot.node_id not in all_node_ids:
                raise ValueError("Analyst pivot references an unknown node")
            check_references(
                evidence_ids=pivot.evidence_ids,
                chain=pivot.provenance_chain,
                label=f"Pivot {pivot.id}",
            )
        return self


class _Observation:
    """Internal normalized observation used while assembling the graph."""

    def __init__(
        self,
        *,
        evidence: Evidence,
        entity_key: str,
        entity_kind: str,
        entity_label: str,
        entity_attributes: dict[str, Any],
        role: Literal["direct_observation", "verified_public_link"],
        independence_key: str,
        exact_url: bool,
        parent_entity_key: str | None = None,
    ) -> None:
        self.evidence = evidence
        self.entity_key = entity_key
        self.entity_kind = entity_kind
        self.entity_label = entity_label
        self.entity_attributes = entity_attributes
        self.role = role
        self.independence_key = independence_key
        self.exact_url = exact_url
        self.parent_entity_key = parent_entity_key

    def provenance_step(self) -> ProvenanceStep:
        if self.role == "verified_public_link":
            explanation = (
                "The cited public profile exposed this URL in its explicit "
                "verified-account links."
            )
        else:
            explanation = (
                "The cited source returned this exact normalized observation."
            )
        return ProvenanceStep(
            evidence_id=self.evidence.id,
            source=self.evidence.source,
            role=self.role,
            independence_key=self.independence_key,
            explanation=explanation,
        )


def _stable_id(prefix: str, *parts: str) -> str:
    material = "\x1f".join(parts).encode("utf-8")
    return f"{prefix}-{sha256(material).hexdigest()[:16].upper()}"


def _case_scope(
    evidence_items: list[Evidence],
    target_context: dict[str, Any],
) -> str:
    """Return a deterministic case-local salt without exposing target PII."""
    supplied_case_id = _clean_text(
        target_context.get("investigation_id") or target_context.get("case_id"),
        maximum=255,
    )
    if supplied_case_id is not None:
        material = f"case:{supplied_case_id}"
    elif evidence_items:
        material = "evidence:" + "|".join(
            sorted({item.id for item in evidence_items})
        )
    else:
        # With no evidence there are no observed PII-bearing entity IDs to link.
        material = "empty-graph"
    return sha256(material.encode("utf-8")).hexdigest()


def _clean_text(value: Any, *, maximum: int = 500) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = str(redact_sensitive(value, max_string_length=maximum)).strip()
    if not cleaned:
        return None
    return cleaned


def _canonical_http_url(value: Any) -> str | None:
    cleaned = _clean_text(value, maximum=2000)
    if cleaned is None:
        return None
    # Redaction placeholders intentionally destroy the original identity-bearing
    # value. They must never become a shared canonical key, because unrelated
    # long URL components could otherwise collapse into one graph entity.
    if "<redacted" in cleaned.casefold():
        return None
    try:
        parsed = urlsplit(cleaned)
        if (
            parsed.scheme.casefold() not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.hostname.casefold().endswith(".onion")
        ):
            return None
        try:
            port = parsed.port
        except ValueError:
            return None
        hostname = parsed.hostname.casefold()
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"
        default_port = (
            parsed.scheme.casefold() == "http"
            and port == 80
            or parsed.scheme.casefold() == "https"
            and port == 443
        )
        netloc = hostname if port is None or default_port else f"{hostname}:{port}"
        path = parsed.path or "/"
        if path != "/":
            path = path.rstrip("/")
        safe_query = [
            (key, "<redacted>" if key.casefold() in _SECRET_QUERY_KEYS else val)
            for key, val in parse_qsl(parsed.query, keep_blank_values=True)
        ]
        return urlunsplit(
            (
                parsed.scheme.casefold(),
                netloc,
                path,
                urlencode(safe_query),
                "",
            )
        )
    except (TypeError, ValueError):
        return None


def _safe_context(target_context: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    attributes: dict[str, Any] = {"basis": "user_supplied_authorized_context"}
    for field in _TARGET_CONTEXT_FIELDS:
        cleaned = _clean_text(target_context.get(field), maximum=255)
        if cleaned is not None:
            attributes[field] = cleaned
    aliases = target_context.get("aliases")
    if isinstance(aliases, list):
        cleaned_aliases = sorted(
            {
                cleaned
                for item in aliases
                if (cleaned := _clean_text(item, maximum=255)) is not None
            }
        )
        if cleaned_aliases:
            attributes["aliases"] = cleaned_aliases
    label = attributes.get("name", "Authorized person target")
    return str(label), attributes


def _contains_blocked_material(item: Evidence) -> bool:
    descriptor = " ".join((item.type, item.source)).casefold()
    if any(marker in descriptor for marker in _BLOCKED_MARKERS):
        return True
    if _SECRET_ASSIGNMENT.search(item.value):
        return True
    for candidate in (item.value, item.source_url):
        if not isinstance(candidate, str):
            continue
        try:
            hostname = urlsplit(candidate).hostname
        except ValueError:
            hostname = None
        if hostname and hostname.casefold().endswith(".onion"):
            return True
    return False


def _allowlisted_attributes(item: Evidence) -> dict[str, Any]:
    metadata = item.metadata if isinstance(item.metadata, dict) else {}
    nested = metadata.get("public_profile")
    public_metadata = nested if isinstance(nested, dict) else metadata
    evidence_type = item.type.casefold()
    if evidence_type in _PROFILE_TYPES:
        fields = _PUBLIC_PROFILE_FIELDS
    elif evidence_type in _BREACH_TYPES:
        fields = _BREACH_FIELDS
    elif evidence_type in _EMAIL_TYPES:
        fields = _EMAIL_RESULT_FIELDS
    elif evidence_type in _SERVICE_TYPES:
        fields = _SERVICE_FIELDS
    else:
        fields = set()

    attributes: dict[str, Any] = {
        "observation_type": item.type,
        "source": item.source,
    }
    quality = metadata.get("quality")
    if isinstance(quality, dict):
        for field in (
            "category",
            "verification_status",
            "matched_attributes",
            "flags",
            "sensitive",
        ):
            value = quality.get(field)
            if isinstance(value, (str, bool)):
                attributes[field] = value
            elif isinstance(value, list):
                attributes[field] = [
                    cleaned
                    for member in value[:25]
                    if (cleaned := _clean_text(member, maximum=255)) is not None
                ]
    for field in sorted(fields):
        value = public_metadata.get(field)
        if isinstance(value, str):
            cleaned = _clean_text(value)
            if cleaned is not None:
                attributes[field] = cleaned
        elif isinstance(value, bool):
            attributes[field] = value
        elif isinstance(value, (int, float)):
            attributes[field] = value
        elif isinstance(value, list):
            cleaned_values = [
                cleaned
                for member in value[:25]
                if (cleaned := _clean_text(member, maximum=255)) is not None
            ]
            if cleaned_values:
                attributes[field] = cleaned_values
    return attributes


def _publisher_key(url: str | None, source: str) -> str:
    if url is not None:
        hostname = urlsplit(url).hostname
        if hostname:
            return f"publisher:{hostname.casefold()}"
    normalized_source = re.sub(r"[^a-z0-9]+", "-", source.casefold()).strip("-")
    return f"source:{normalized_source or 'unknown'}"


def _entity_for_evidence(
    item: Evidence,
) -> tuple[str, str, str, dict[str, Any], bool]:
    evidence_type = item.type.casefold()
    value_url = _canonical_http_url(item.value)
    source_url = _canonical_http_url(item.source_url)
    try:
        raw_value = urlsplit(item.value)
        value_claims_url = (
            raw_value.scheme.casefold() in {"http", "https"}
            and bool(raw_value.netloc)
        )
    except ValueError:
        value_claims_url = False
    entity_url = (
        value_url
        if evidence_type in _PROFILE_TYPES and value_claims_url
        else value_url or source_url
    )
    attributes = _allowlisted_attributes(item)
    cleaned_value = _clean_text(item.value) or f"{item.type} observation"

    if evidence_type in _SERVICE_TYPES:
        key = (
            f"service:{item.id}"
            if "<redacted" in cleaned_value.casefold()
            else f"service:{cleaned_value.casefold()}"
        )
        return key, "service", cleaned_value, attributes, False
    if evidence_type in _BREACH_TYPES:
        breach_name = _clean_text(item.metadata.get("breach_name"))
        breach_date = _clean_text(item.metadata.get("breach_date"))
        label = (
            f"Breach metadata: {breach_name}"
            if breach_name
            else "Public breach metadata observation"
        )
        key_material = "|".join((breach_name or "", breach_date or "", item.id))
        return f"breach:{key_material}", "breach_event", label, attributes, False
    if evidence_type in _EMAIL_TYPES:
        return (
            f"email-observation:{item.id}",
            "email_observation",
            "Authorized email observation",
            attributes,
            False,
        )
    if evidence_type in _PHONE_TYPES:
        return (
            f"phone-observation:{item.id}",
            "phone_observation",
            "Authorized phone observation",
            attributes,
            False,
        )
    if evidence_type in _USERNAME_TYPES:
        key = (
            f"username:{item.id}"
            if "<redacted" in cleaned_value.casefold()
            else f"username:{cleaned_value.casefold()}"
        )
        return (
            key,
            "username_observation",
            cleaned_value,
            attributes,
            False,
        )
    if entity_url is not None:
        kind = (
            "public_profile"
            if evidence_type in _PROFILE_TYPES
            else "public_resource"
        )
        attributes["url"] = entity_url
        if source_url is not None:
            # Keep the exact redacted collector URL for navigation.  ``url``
            # is the canonical entity key and may intentionally differ.
            attributes["open_url"] = source_url
        return f"url:{entity_url}", kind, entity_url, attributes, True
    return (
        f"observation:{item.id}",
        "public_observation",
        cleaned_value,
        attributes,
        False,
    )


def _direct_independence_key(item: Evidence, entity_url: str | None) -> str:
    source_url = _canonical_http_url(item.source_url)
    if source_url is not None and source_url != entity_url:
        return _publisher_key(source_url, item.source)
    return _publisher_key(entity_url or source_url, item.source)


def _verified_link_observations(
    item: Evidence,
    *,
    parent_entity_key: str,
    parent_url: str | None,
) -> list[_Observation]:
    metadata = item.metadata if isinstance(item.metadata, dict) else {}
    nested = metadata.get("public_profile")
    public_metadata = nested if isinstance(nested, dict) else metadata
    accounts = public_metadata.get("verified_accounts")
    if not isinstance(accounts, list):
        return []

    results: list[_Observation] = []
    seen: set[str] = set()
    for account in accounts:
        if not isinstance(account, dict):
            continue
        url = _canonical_http_url(account.get("url"))
        if url is None or url in seen:
            continue
        seen.add(url)
        attributes: dict[str, Any] = {
            "url": url,
            "link_assertion": "verified_public_account",
        }
        for field in ("label", "type"):
            cleaned = _clean_text(account.get(field), maximum=100)
            if cleaned is not None:
                attributes[field] = cleaned
        results.append(
            _Observation(
                evidence=item,
                entity_key=f"url:{url}",
                entity_kind="public_profile",
                entity_label=url,
                entity_attributes=attributes,
                role="verified_public_link",
                independence_key=_publisher_key(parent_url, item.source),
                exact_url=True,
                parent_entity_key=parent_entity_key,
            )
        )
    return results


def _expand_correlated_observations(item: Evidence) -> list[Evidence]:
    """Recover publisher paths while retaining the report-ledger evidence ID.

    ``correlate_evidence`` stores its contributing observations in metadata but
    emits one representative Evidence object.  The nested IDs are not necessarily
    present in the final report ledger, so every virtual observation cites the
    representative ID while retaining only safe source, URL, value, and public
    metadata fields needed to assess source independence.
    """
    observations = item.metadata.get("observations")
    if not isinstance(observations, list):
        return [item]

    expanded: list[Evidence] = []
    for nested in observations:
        if not isinstance(nested, dict):
            continue
        nested_type = _clean_text(nested.get("type"), maximum=80)
        nested_value = _clean_text(nested.get("value"), maximum=2000)
        nested_source = _clean_text(nested.get("source"), maximum=100)
        if not nested_type or not nested_value or not nested_source:
            continue
        nested_source_url = _clean_text(
            nested.get("source_url"),
            maximum=2000,
        )
        nested_metadata = nested.get("metadata")
        confidence = nested.get("confidence")
        if not isinstance(confidence, (int, float)):
            confidence = item.confidence
        try:
            nested_identity_status = IdentityStatus(
                nested.get("identity_status")
            )
        except (TypeError, ValueError):
            nested_identity_status = item.identity_status
        virtual = Evidence(
            id=item.id,
            type=nested_type,
            value=nested_value,
            source=nested_source,
            source_url=nested_source_url,
            observed_at=item.observed_at,
            confidence=max(0.0, min(float(confidence), 1.0)),
            reliability=item.reliability,
            identity_status=nested_identity_status,
            notes=[],
            metadata=(
                nested_metadata if isinstance(nested_metadata, dict) else {}
            ),
        )
        if not _contains_blocked_material(virtual):
            expanded.append(virtual)
    return expanded


def _merge_attributes(observations: list[_Observation]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    sources: set[str] = set()
    observation_types: set[str] = set()
    for observation in observations:
        sources.add(observation.evidence.source)
        observation_types.add(observation.evidence.type)
        for key, value in observation.entity_attributes.items():
            if key not in merged:
                merged[key] = value
            elif merged[key] != value:
                existing = merged[key]
                values = existing if isinstance(existing, list) else [existing]
                additions = value if isinstance(value, list) else [value]
                merged[key] = sorted(
                    {
                        json.dumps(member, sort_keys=True, default=str): member
                        for member in values + additions
                    }.values(),
                    key=lambda member: json.dumps(
                        member, sort_keys=True, default=str
                    ),
                )
    merged["sources"] = sorted(sources)
    merged["observation_types"] = sorted(observation_types)
    return merged


def _deduplicated_chain(observations: list[_Observation]) -> list[ProvenanceStep]:
    steps: dict[tuple[str, str, str], ProvenanceStep] = {}
    for observation in observations:
        step = observation.provenance_step()
        key = (step.evidence_id, step.role, step.independence_key)
        steps[key] = step
    return [
        steps[key]
        for key in sorted(
            steps,
            key=lambda member: (member[0], member[1], member[2]),
        )
    ]


def _identity_assessment(
    observations: list[_Observation],
    *,
    entity_kind: str,
) -> tuple[float, IdentityStatus]:
    chain = _deduplicated_chain(observations)
    independent_count = len({step.independence_key for step in chain})
    base = mean(observation.evidence.confidence for observation in observations)
    has_exact_url = all(observation.exact_url for observation in observations)
    has_verified_link = any(
        observation.role == "verified_public_link" for observation in observations
    )
    statuses = {
        observation.evidence.identity_status for observation in observations
    }

    if statuses == {IdentityStatus.UNRELATED}:
        return round(min(base, 0.99), 4), IdentityStatus.UNRELATED
    if IdentityStatus.UNRELATED in statuses:
        return round(min(base, 0.54), 4), IdentityStatus.POSSIBLE

    if (
        entity_kind == "public_profile"
        and has_exact_url
        and independent_count >= 2
    ):
        score = min(max(base + (0.10 if has_verified_link else 0.08), 0.68), 0.79)
        return round(score, 4), IdentityStatus.PROBABLE

    score = min(base + (0.05 if has_verified_link else 0.0), 0.64)
    if score < 0.40:
        return round(score, 4), IdentityStatus.INSUFFICIENT_EVIDENCE
    return round(score, 4), IdentityStatus.POSSIBLE


def _hypothesis_claim(
    *,
    node: GraphNode,
    status: IdentityStatus,
    observations: list[_Observation],
) -> tuple[str, list[str]]:
    has_verified_link = any(
        observation.role == "verified_public_link" for observation in observations
    )
    if status == IdentityStatus.UNRELATED:
        return (
            f"The cited source evidence disambiguates {node.label} from the "
            "authorized target. It must not be attributed to the person.",
            [
                "Retain the cited negative disambiguation when reviewing future "
                "matches.",
            ],
        )
    if node.kind == "public_profile" and status == IdentityStatus.PROBABLE:
        return (
            "Independent public provenance paths resolve to the exact URL "
            f"{node.label}. It is a probable candidate association, not "
            "confirmed account ownership.",
            [
                "Exact URL agreement is stronger than username similarity.",
                "An analyst must still verify current public profile attributes.",
            ],
        )
    if node.kind == "public_profile" and has_verified_link:
        return (
            f"A cited public profile explicitly links to {node.label}. Without "
            "an independent provenance path, this remains a possible candidate.",
            [
                "A single public profile controls its own outbound links.",
                "No login, recovery, or private-account action was performed.",
            ],
        )
    if node.kind == "public_profile":
        return (
            f"The exact public URL {node.label} was observed as a possible "
            "candidate; presence or username similarity does not prove ownership.",
            [
                "Username-search tools observing one publisher are not "
                "independent identity sources.",
            ],
        )
    if node.kind == "service":
        return (
            f"A public service-presence signal was observed for {node.label}; "
            "it does not establish account ownership or activity.",
            [
                "Service-registration behavior can be ambiguous or change.",
                "No login or recovery workflow should be used for verification.",
            ],
        )
    if node.kind == "breach_event":
        return (
            f"{node.label} was observed as public breach metadata. No passwords "
            "or raw leaked records were ingested.",
            [
                "Breach inclusion does not prove current account control.",
            ],
        )
    if node.kind in {"email_observation", "phone_observation"}:
        return (
            f"{node.label} is supported as an observation for the authorized "
            "identifier, but does not independently establish person ownership.",
            [
                "The graph does not generate or expose new contact identifiers.",
            ],
        )
    return (
        f"{node.label} is an evidence-backed public observation requiring "
        "manual identity review.",
        [
            "No unsupported identity attribution was inferred.",
        ],
    )


def _pivot_content(
    *,
    node: GraphNode,
    status: IdentityStatus,
    observations: list[_Observation],
) -> tuple[str, str, str, Literal["high", "medium", "low"]]:
    has_verified_link = any(
        observation.role == "verified_public_link" for observation in observations
    )
    if status == IdentityStatus.UNRELATED:
        return (
            "Retain negative disambiguation",
            "The cited evidence marks this observation as unrelated to the target.",
            "Do not attribute or pursue this observation unless new independent "
            "evidence justifies a documented re-evaluation.",
            "low",
        )
    if node.kind == "breach_event":
        return (
            "Review defensive breach metadata",
            "The cited evidence contains public breach metadata.",
            "Review only the breach name, date, and data-class metadata; "
            "recommend defensive remediation without seeking leaked credentials.",
            "high",
        )
    if node.kind == "public_profile" and status == IdentityStatus.PROBABLE:
        return (
            "Confirm independently linked public profile",
            "At least two independent provenance paths resolve to the exact URL.",
            "Open only the cited public pages and manually compare current name, "
            "employer, location, and verified links. Do not authenticate.",
            "high",
        )
    if node.kind == "public_profile" and has_verified_link:
        return (
            "Validate public verified-account link",
            "One public profile presents this exact URL as a verified account.",
            "Inspect both public endpoints manually and seek an independent "
            "corroborating source before attribution. Do not authenticate.",
            "high",
        )
    if node.kind == "public_profile":
        return (
            "Review candidate public profile",
            "A public source returned this exact URL as a candidate.",
            "Open the cited public URL manually and compare independently visible "
            "attributes with authorized target context. Do not authenticate or "
            "initiate account recovery.",
            "medium",
        )
    if node.kind == "service":
        return (
            "Validate service-presence signal with consent",
            "A service-presence tool returned the cited public signal.",
            "Treat the result as an existence signal only; confirm through the "
            "person's own records or direct consent. Do not trigger login or "
            "account-recovery workflows.",
            "medium",
        )
    return (
        "Review cited observation manually",
        "The graph contains a cited public observation that remains uncertain.",
        "Inspect only the cited public evidence and document any matching or "
        "contradictory attributes before changing identity confidence.",
        "low",
    )


def build_identity_graph(
    evidence_items: list[Evidence],
    target_context: dict[str, Any],
) -> IdentityGraph:
    """Build a deterministic, explainable graph from collected evidence only.

    The builder performs no network access and produces no new identifiers.
    Evidence involving credentials, private communications, raw leaks, dark-web
    sources, or onion services is excluded before graph construction.
    """

    target_label, target_attributes = _safe_context(target_context)
    graph_scope = _case_scope(evidence_items, target_context)
    target_node_id = _stable_id("NODE", graph_scope, "target")
    target_node = GraphNode(
        id=target_node_id,
        kind="authorized_target",
        label=target_label,
        attributes=target_attributes,
    )

    sorted_evidence = sorted(
        evidence_items,
        key=lambda item: (item.id, item.source.casefold(), item.type.casefold()),
    )
    eligible: list[Evidence] = []
    excluded_ids: list[str] = []
    for item in sorted_evidence:
        if _contains_blocked_material(item):
            excluded_ids.append(item.id)
        else:
            eligible.append(item)

    evidence_index = [
        EvidenceReference(
            id=item.id,
            type=item.type,
            source=item.source,
            source_url=_canonical_http_url(item.source_url),
        )
        for item in eligible
    ]

    direct_observations: list[_Observation] = []
    all_observations: list[_Observation] = []
    for ledger_item in eligible:
        for item in _expand_correlated_observations(ledger_item):
            entity_key, kind, label, attributes, exact_url = _entity_for_evidence(
                item
            )
            entity_url = label if exact_url else None
            direct = _Observation(
                evidence=item,
                entity_key=entity_key,
                entity_kind=kind,
                entity_label=label,
                entity_attributes=attributes,
                role="direct_observation",
                independence_key=_direct_independence_key(item, entity_url),
                exact_url=exact_url,
            )
            direct_observations.append(direct)
            all_observations.append(direct)
            all_observations.extend(
                _verified_link_observations(
                    item,
                    parent_entity_key=entity_key,
                    parent_url=entity_url,
                )
            )

    observations_by_entity: dict[str, list[_Observation]] = defaultdict(list)
    for observation in all_observations:
        observations_by_entity[observation.entity_key].append(observation)

    node_by_entity: dict[str, GraphNode] = {}
    for entity_key in sorted(observations_by_entity):
        observations = observations_by_entity[entity_key]
        first = sorted(
            observations,
            key=lambda item: (
                item.entity_kind,
                item.entity_label.casefold(),
                item.evidence.id,
            ),
        )[0]
        evidence_ids = sorted({item.evidence.id for item in observations})
        node_by_entity[entity_key] = GraphNode(
            id=_stable_id("NODE", graph_scope, entity_key),
            kind=first.entity_kind,
            label=first.entity_label,
            attributes=_merge_attributes(observations),
            evidence_ids=evidence_ids,
        )

    source_nodes: dict[str, GraphNode] = {}
    observations_by_source: dict[str, list[_Observation]] = defaultdict(list)
    for observation in direct_observations:
        observations_by_source[observation.evidence.source].append(observation)
    for source in sorted(observations_by_source, key=str.casefold):
        source_evidence_ids = sorted(
            {item.evidence.id for item in observations_by_source[source]}
        )
        source_nodes[source] = GraphNode(
            id=_stable_id(
                "NODE",
                graph_scope,
                "source",
                source.casefold(),
            ),
            kind="public_source",
            label=source,
            attributes={"role": "evidence_publisher_or_collection_adapter"},
            evidence_ids=source_evidence_ids,
        )

    edges: list[GraphEdge] = []
    direct_by_source_entity: dict[tuple[str, str], list[_Observation]] = defaultdict(
        list
    )
    for observation in direct_observations:
        direct_by_source_entity[
            (observation.evidence.source, observation.entity_key)
        ].append(observation)
    for (source, entity_key), observations in sorted(
        direct_by_source_entity.items(),
        key=lambda item: (item[0][0].casefold(), item[0][1]),
    ):
        chain = _deduplicated_chain(observations)
        evidence_ids = sorted({step.evidence_id for step in chain})
        confidence = round(
            min(mean(item.evidence.confidence for item in observations), 0.64),
            4,
        )
        observation_statuses = {
            item.evidence.identity_status for item in observations
        }
        if observation_statuses == {IdentityStatus.UNRELATED}:
            status = IdentityStatus.UNRELATED
        else:
            status = (
                IdentityStatus.POSSIBLE
                if confidence >= 0.40
                else IdentityStatus.INSUFFICIENT_EVIDENCE
            )
        edges.append(
            GraphEdge(
                id=_stable_id(
                    "EDGE",
                    graph_scope,
                    "publishes-attribute",
                    source,
                    entity_key,
                ),
                source_node_id=source_nodes[source].id,
                target_node_id=node_by_entity[entity_key].id,
                relationship="publishes_attribute",
                confidence=confidence,
                identity_status=status,
                evidence_ids=evidence_ids,
                independent_source_count=len(
                    {step.independence_key for step in chain}
                ),
                explanation=(
                    "This edge records a source observation only; it is not an "
                    "account-ownership claim."
                ),
                provenance_chain=chain,
            )
        )

    link_groups: dict[tuple[str, str], list[_Observation]] = defaultdict(list)
    for observation in all_observations:
        if (
            observation.role == "verified_public_link"
            and observation.parent_entity_key is not None
        ):
            link_groups[
                (observation.parent_entity_key, observation.entity_key)
            ].append(observation)
    for (parent_key, child_key), observations in sorted(link_groups.items()):
        chain = _deduplicated_chain(observations)
        evidence_ids = sorted({step.evidence_id for step in chain})
        confidence = round(
            min(
                mean(item.evidence.confidence for item in observations) + 0.08,
                0.79,
            ),
            4,
        )
        edges.append(
            GraphEdge(
                id=_stable_id(
                    "EDGE",
                    graph_scope,
                    "verified-public-link",
                    parent_key,
                    child_key,
                ),
                source_node_id=node_by_entity[parent_key].id,
                target_node_id=node_by_entity[child_key].id,
                relationship="verified_public_account_link",
                confidence=confidence,
                identity_status=IdentityStatus.POSSIBLE,
                evidence_ids=evidence_ids,
                independent_source_count=len(
                    {step.independence_key for step in chain}
                ),
                explanation=(
                    "A public profile explicitly presented this outbound account "
                    "link as verified. One publisher alone does not establish "
                    "person ownership."
                ),
                provenance_chain=chain,
            )
        )

    hypotheses: list[IdentityHypothesis] = []
    pivot_candidates: list[
        tuple[
            int,
            float,
            str,
            GraphNode,
            str,
            str,
            str,
            Literal["high", "medium", "low"],
            list[str],
            list[ProvenanceStep],
        ]
    ] = []
    for entity_key in sorted(observations_by_entity):
        observations = observations_by_entity[entity_key]
        node = node_by_entity[entity_key]
        confidence, status = _identity_assessment(
            observations,
            entity_kind=node.kind,
        )
        chain = _deduplicated_chain(observations)
        evidence_ids = sorted({step.evidence_id for step in chain})
        independent_count = len({step.independence_key for step in chain})
        claim, limitations = _hypothesis_claim(
            node=node,
            status=status,
            observations=observations,
        )
        if (
            status != IdentityStatus.UNRELATED
            and any(
                item.evidence.identity_status == IdentityStatus.UNRELATED
                for item in observations
            )
        ):
            limitations.append(
                "The provenance contains conflicting negative disambiguation; "
                "the association cannot be promoted beyond possible."
            )
        hypotheses.append(
            IdentityHypothesis(
                id=_stable_id("HYP", target_node_id, entity_key),
                subject_node_id=target_node_id,
                object_node_id=node.id,
                claim=claim,
                confidence=confidence,
                identity_status=status,
                evidence_ids=evidence_ids,
                independent_source_count=independent_count,
                provenance_chain=chain,
                limitations=limitations,
            )
        )
        edges.append(
            GraphEdge(
                id=_stable_id(
                    "EDGE",
                    graph_scope,
                    "candidate",
                    target_node_id,
                    entity_key,
                ),
                source_node_id=target_node_id,
                target_node_id=node.id,
                relationship=(
                    "disambiguated_unrelated_observation"
                    if status == IdentityStatus.UNRELATED
                    else "candidate_profile"
                    if node.kind == "public_profile"
                    else "candidate_observation"
                ),
                confidence=confidence,
                identity_status=status,
                evidence_ids=evidence_ids,
                independent_source_count=independent_count,
                explanation=claim,
                provenance_chain=chain,
            )
        )

        title, rationale, action, priority = _pivot_content(
            node=node,
            status=status,
            observations=observations,
        )
        pivot_candidates.append(
            (
                _PRIORITY_ORDER[priority],
                -confidence,
                node.id,
                node,
                title,
                rationale,
                action,
                priority,
                evidence_ids,
                chain,
            )
        )

    pivots: list[AnalystPivot] = []
    for rank, candidate in enumerate(sorted(pivot_candidates), start=1):
        (
            _priority_order,
            _negative_confidence,
            _node_sort_id,
            node,
            title,
            rationale,
            action,
            priority,
            evidence_ids,
            chain,
        ) = candidate
        pivots.append(
            AnalystPivot(
                id=_stable_id("PIVOT", graph_scope, node.id, title),
                rank=rank,
                node_id=node.id,
                title=title,
                rationale=rationale,
                action=action,
                priority=priority,
                evidence_ids=evidence_ids,
                provenance_chain=chain,
            )
        )

    nodes = [target_node]
    nodes.extend(
        source_nodes[source]
        for source in sorted(source_nodes, key=str.casefold)
    )
    nodes.extend(node_by_entity[key] for key in sorted(node_by_entity))
    return IdentityGraph(
        target_node_id=target_node_id,
        nodes=nodes,
        edges=sorted(edges, key=lambda edge: edge.id),
        hypotheses=sorted(hypotheses, key=lambda item: item.id),
        pivots=pivots,
        evidence_index=evidence_index,
        excluded_evidence_ids=sorted(excluded_ids),
    )


__all__ = [
    "AnalystPivot",
    "EvidenceReference",
    "GraphEdge",
    "GraphNode",
    "IdentityGraph",
    "IdentityHypothesis",
    "ProvenanceStep",
    "build_identity_graph",
]
