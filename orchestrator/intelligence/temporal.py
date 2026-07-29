"""Policy-safe temporal comparison for normalized evidence snapshots.

This module is deliberately pure: it compares evidence already collected by
WorldAtlas and never calls a source.  An item that was not observed means only
that the observation was not present in the current snapshot.  It must not be
treated as proof that an account, identifier, or person no longer exists.
"""

from __future__ import annotations

from collections import defaultdict
from hashlib import sha256
import json
import re
from typing import Any, Sequence
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from pydantic import BaseModel, Field

from .models import Evidence
from .redaction import redact_sensitive


_CORRELATION_METADATA_KEYS = frozenset(
    {
        "correlated_sources",
        "correlation",
        "correlation_score",
        "observations",
        "source_count",
    }
)
_CORRELATION_NOTE = re.compile(
    r"^Correlated from \d+ observation\(s\) across "
    r"\d+ independent source\(s\)\.$",
    re.IGNORECASE,
)
_URL_EVIDENCE_TYPES = frozenset(
    {"github_profile", "social_profile", "source_url", "web_profile"}
)
_IGNORED_QUERY_KEYS = frozenset(
    {
        "fbclid",
        "gclid",
        "mc_cid",
        "mc_eid",
        "ref",
        "ref_",
        "tracking",
    }
)
_SENSITIVE_QUERY_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "apikey",
        "authorization",
        "key",
        "password",
        "secret",
        "token",
    }
)
_SNAPSHOT_SCOPE_NOTE = (
    "Snapshot differences describe collected observations only. An item not "
    "observed in the current snapshot may reflect source or collection "
    "availability and is not evidence that an identity, account, or fact no "
    "longer exists. Values altered by privacy redaction are deliberately not "
    "correlated across snapshots."
)


class TemporalComparisonScope(BaseModel):
    """Optional caller-provided context for the two compared snapshots."""

    previous_case_id: str | None = None
    current_case_id: str | None = None
    source: str | None = None


class TemporalEvidenceSummary(BaseModel):
    """A compact, redaction-safe reference to one temporal observation."""

    fingerprint: str
    type: str
    value: str
    previous_evidence_id: str | None = None
    current_evidence_id: str | None = None
    previous_sources: list[str] = Field(default_factory=list)
    current_sources: list[str] = Field(default_factory=list)
    previous_source_url: str | None = None
    current_source_url: str | None = None
    changed_fields: list[str] = Field(default_factory=list)


class TemporalComparisonCounts(BaseModel):
    added: int
    not_observed: int
    persisting: int
    changed: int

    @property
    def removed(self) -> int:
        """Compatibility alias; serialized output uses ``not_observed``."""
        return self.not_observed


class TemporalComparison(BaseModel):
    """Serializable result of comparing two normalized evidence lists."""

    scope: TemporalComparisonScope
    counts: TemporalComparisonCounts
    added: list[TemporalEvidenceSummary] = Field(default_factory=list)
    not_observed: list[TemporalEvidenceSummary] = Field(default_factory=list)
    persisting: list[TemporalEvidenceSummary] = Field(default_factory=list)
    changed: list[TemporalEvidenceSummary] = Field(default_factory=list)
    scope_note: str = _SNAPSHOT_SCOPE_NOTE

    @property
    def removed(self) -> list[TemporalEvidenceSummary]:
        """Compatibility alias; serialized output uses ``not_observed``."""
        return self.not_observed


class _PreparedEvidence:
    """Internal deterministic representation of one evidence item."""

    def __init__(self, evidence: Evidence):
        self.evidence = evidence
        self.content = _stable_content(evidence)
        identity_key = {
            "type": self.content["type"],
            "value": self.content["value"],
        }
        if _contains_redaction_placeholder(self.content):
            # Redaction intentionally removes the original value. Using the
            # shared placeholder as an identity key could fabricate persistence
            # between unrelated observations, so fail closed for this item.
            identity_key["non_correlatable_evidence_id"] = evidence.id
        self.fingerprint = _fingerprint(identity_key)
        self.content_fingerprint = _fingerprint(self.content)


def _safe_text(value: str | None) -> str | None:
    if value is None:
        return None
    redacted = redact_sensitive(value)
    return str(redacted)


def _contains_redaction_placeholder(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_contains_redaction_placeholder(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_redaction_placeholder(item) for item in value)
    if isinstance(value, str):
        normalized = value.casefold()
        return "<redacted" in normalized or "…<truncated>" in normalized
    return False


def _canonical_url(value: str) -> str:
    """Normalize URLs while retaining non-secret identity-bearing parameters."""
    try:
        parsed = urlsplit(value.strip())
    except ValueError:
        return value.strip().casefold()
    if not parsed.scheme or not parsed.netloc:
        return value.strip().casefold()
    hostname = parsed.hostname
    if not hostname:
        return value.strip().casefold()
    normalized_host = hostname.casefold()
    if ":" in normalized_host and not normalized_host.startswith("["):
        normalized_host = f"[{normalized_host}]"
    try:
        port = parsed.port
    except ValueError:
        port = None
    netloc = f"{normalized_host}:{port}" if port is not None else normalized_host
    query_items = []
    for key, item in parse_qsl(parsed.query, keep_blank_values=True):
        normalized_key = key.casefold()
        if (
            normalized_key in _IGNORED_QUERY_KEYS
            or normalized_key in _SENSITIVE_QUERY_KEYS
            or normalized_key.startswith("utm_")
        ):
            continue
        query_items.append((key, item))
    query = urlencode(sorted(query_items))
    return urlunsplit(
        (
            parsed.scheme.casefold(),
            netloc,
            parsed.path.rstrip("/"),
            query,
            "",
        )
    )


def _canonical_value(evidence_type: str, value: str) -> str:
    safe_value = _safe_text(value) or ""
    if evidence_type.casefold() in _URL_EVIDENCE_TYPES:
        return _canonical_url(safe_value)
    return " ".join(safe_value.split()).casefold()


def _without_correlation_metadata(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _without_correlation_metadata(item)
            for key, item in value.items()
            if str(key).casefold() not in _CORRELATION_METADATA_KEYS
        }
    if isinstance(value, list):
        return [_without_correlation_metadata(item) for item in value]
    return value


def _contributing_sources(evidence: Evidence) -> list[str]:
    safe_source = _safe_text(evidence.source.strip()) or ""
    sources = {safe_source.casefold()}
    observations = evidence.metadata.get("observations")
    if isinstance(observations, list):
        for observation in observations:
            if not isinstance(observation, dict):
                continue
            source = observation.get("source")
            if isinstance(source, str) and source.strip():
                safe_observation_source = _safe_text(source.strip()) or ""
                sources.add(safe_observation_source.casefold())
    return sorted(sources)


def _stable_content(evidence: Evidence) -> dict[str, Any]:
    """Return source facts with collection and correlation noise removed."""
    safe_metadata = redact_sensitive(evidence.metadata)
    clean_metadata = _without_correlation_metadata(safe_metadata)
    notes = sorted(
        {
            str(redact_sensitive(note)).strip()
            for note in evidence.notes
            if note.strip() and not _CORRELATION_NOTE.match(note.strip())
        }
    )
    source_url = _safe_text(evidence.source_url)
    safe_type = _safe_text(evidence.type.strip()) or ""
    return {
        "type": safe_type.casefold(),
        "value": _canonical_value(evidence.type, evidence.value),
        "sources": _contributing_sources(evidence),
        "source_url": _canonical_url(source_url) if source_url else None,
        "reliability": evidence.reliability.value,
        "notes": notes,
        "metadata": clean_metadata,
    }


def _fingerprint(value: Any) -> str:
    serialized = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return sha256(serialized.encode("utf-8")).hexdigest()


def stable_evidence_fingerprint(evidence: Evidence) -> str:
    """Return a stable observation key that omits IDs and collection time."""
    content = _stable_content(evidence)
    identity_key = {"type": content["type"], "value": content["value"]}
    if _contains_redaction_placeholder(content):
        identity_key["non_correlatable_evidence_id"] = evidence.id
    return _fingerprint(identity_key)


def _changed_fields(
    previous: _PreparedEvidence,
    current: _PreparedEvidence,
) -> list[str]:
    return sorted(
        key
        for key in previous.content
        if previous.content[key] != current.content[key]
    )


def _summary(
    previous: _PreparedEvidence | None,
    current: _PreparedEvidence | None,
    *,
    changed_fields: list[str] | None = None,
) -> TemporalEvidenceSummary:
    representative = current or previous
    if representative is None:  # pragma: no cover - internal contract guard
        raise ValueError("A temporal summary requires at least one observation")

    previous_content = previous.content if previous else {}
    current_content = current.content if current else {}
    display_value = _safe_text(representative.evidence.value) or ""
    return TemporalEvidenceSummary(
        fingerprint=representative.fingerprint,
        type=representative.content["type"],
        value=display_value,
        previous_evidence_id=previous.evidence.id if previous else None,
        current_evidence_id=current.evidence.id if current else None,
        previous_sources=list(previous_content.get("sources", [])),
        current_sources=list(current_content.get("sources", [])),
        previous_source_url=previous_content.get("source_url"),
        current_source_url=current_content.get("source_url"),
        changed_fields=changed_fields or [],
    )


def _item_sort_key(item: _PreparedEvidence) -> tuple[str, str, str]:
    return (item.fingerprint, item.content_fingerprint, item.evidence.id)


def _summary_sort_key(
    item: TemporalEvidenceSummary,
) -> tuple[str, str, str]:
    return (
        item.fingerprint,
        item.previous_evidence_id or "",
        item.current_evidence_id or "",
    )


def _prepare(
    evidence_items: Sequence[Evidence],
    source: str | None,
) -> list[_PreparedEvidence]:
    seen_ids: set[str] = set()
    prepared: list[_PreparedEvidence] = []
    normalized_source = source.strip().casefold() if source else None
    for evidence in evidence_items:
        if evidence.id in seen_ids:
            raise ValueError(f"Duplicate evidence ID in snapshot: {evidence.id}")
        seen_ids.add(evidence.id)
        item = _PreparedEvidence(evidence)
        if normalized_source and normalized_source not in item.content["sources"]:
            continue
        prepared.append(item)
    return sorted(prepared, key=_item_sort_key)


def compare_evidence_snapshots(
    previous: Sequence[Evidence],
    current: Sequence[Evidence],
    *,
    previous_case_id: str | None = None,
    current_case_id: str | None = None,
    source: str | None = None,
) -> TemporalComparison:
    """Compare two evidence inventories without collecting or inferring facts.

    Exact content matches persist.  Items with the same normalized type and
    value but different source facts are changed.  Unmatched items are added or
    not observed; that label describes only this pair of snapshots.
    """
    previous_items = _prepare(previous, source)
    current_items = _prepare(current, source)

    previous_groups: dict[str, list[_PreparedEvidence]] = defaultdict(list)
    current_groups: dict[str, list[_PreparedEvidence]] = defaultdict(list)
    for item in previous_items:
        previous_groups[item.fingerprint].append(item)
    for item in current_items:
        current_groups[item.fingerprint].append(item)

    added: list[TemporalEvidenceSummary] = []
    not_observed: list[TemporalEvidenceSummary] = []
    persisting: list[TemporalEvidenceSummary] = []
    changed: list[TemporalEvidenceSummary] = []

    for fingerprint in sorted(set(previous_groups) | set(current_groups)):
        previous_group = list(previous_groups.get(fingerprint, []))
        current_group = list(current_groups.get(fingerprint, []))

        previous_by_content: dict[str, list[_PreparedEvidence]] = defaultdict(list)
        current_by_content: dict[str, list[_PreparedEvidence]] = defaultdict(list)
        for item in previous_group:
            previous_by_content[item.content_fingerprint].append(item)
        for item in current_group:
            current_by_content[item.content_fingerprint].append(item)

        unmatched_previous: list[_PreparedEvidence] = []
        unmatched_current: list[_PreparedEvidence] = []
        content_keys = sorted(set(previous_by_content) | set(current_by_content))
        for content_key in content_keys:
            previous_exact = previous_by_content.get(content_key, [])
            current_exact = current_by_content.get(content_key, [])
            exact_count = min(len(previous_exact), len(current_exact))
            for index in range(exact_count):
                persisting.append(
                    _summary(previous_exact[index], current_exact[index])
                )
            unmatched_previous.extend(previous_exact[exact_count:])
            unmatched_current.extend(current_exact[exact_count:])

        unmatched_previous.sort(key=_item_sort_key)
        unmatched_current.sort(key=_item_sort_key)
        changed_count = min(len(unmatched_previous), len(unmatched_current))
        for index in range(changed_count):
            previous_item = unmatched_previous[index]
            current_item = unmatched_current[index]
            changed.append(
                _summary(
                    previous_item,
                    current_item,
                    changed_fields=_changed_fields(previous_item, current_item),
                )
            )
        not_observed.extend(
            _summary(item, None) for item in unmatched_previous[changed_count:]
        )
        added.extend(
            _summary(None, item) for item in unmatched_current[changed_count:]
        )

    for collection in (added, not_observed, persisting, changed):
        collection.sort(key=_summary_sort_key)

    safe_previous_case_id = _safe_text(previous_case_id)
    safe_current_case_id = _safe_text(current_case_id)
    safe_source = _safe_text(source.strip()) if source and source.strip() else None
    return TemporalComparison(
        scope=TemporalComparisonScope(
            previous_case_id=safe_previous_case_id,
            current_case_id=safe_current_case_id,
            source=safe_source,
        ),
        counts=TemporalComparisonCounts(
            added=len(added),
            not_observed=len(not_observed),
            persisting=len(persisting),
            changed=len(changed),
        ),
        added=added,
        not_observed=not_observed,
        persisting=persisting,
        changed=changed,
    )
