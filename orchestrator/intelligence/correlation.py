"""Deterministic evidence deduplication and confidence scoring."""

from __future__ import annotations

from collections import defaultdict
from statistics import mean
from urllib.parse import urlsplit, urlunsplit

from .models import Evidence, IdentityStatus, SourceReliability

_RELIABILITY_BONUS = {
    SourceReliability.HIGH: 0.12,
    SourceReliability.MEDIUM: 0.06,
    SourceReliability.LOW: 0.0,
    SourceReliability.UNKNOWN: 0.0,
}


def _canonical_value(evidence_type: str, value: str) -> str:
    text = value.strip()
    if evidence_type in {"social_profile", "web_profile", "source_url"}:
        try:
            parsed = urlsplit(text)
            if parsed.scheme and parsed.netloc:
                path = parsed.path.rstrip("/")
                return urlunsplit(
                    (
                        parsed.scheme.lower(),
                        parsed.netloc.lower(),
                        path,
                        "",
                        "",
                    )
                )
        except ValueError:
            pass
    return text.casefold()


def status_from_score(score: float) -> IdentityStatus:
    if score >= 0.92:
        return IdentityStatus.CONFIRMED
    if score >= 0.80:
        return IdentityStatus.HIGHLY_PROBABLE
    if score >= 0.65:
        return IdentityStatus.PROBABLE
    if score >= 0.40:
        return IdentityStatus.POSSIBLE
    return IdentityStatus.INSUFFICIENT_EVIDENCE


def correlate_evidence(evidence_items: list[Evidence]) -> list[Evidence]:
    """Merge duplicate observations and reward independent corroboration."""
    grouped: dict[tuple[str, str], list[Evidence]] = defaultdict(list)
    for item in evidence_items:
        grouped[(item.type, _canonical_value(item.type, item.value))].append(item)

    correlated: list[Evidence] = []
    for group in grouped.values():
        representative = group[0]
        sources = sorted({item.source for item in group})
        avg_confidence = mean(item.confidence for item in group)
        # Reliability describes the quality of a source, but it is not independent
        # identity corroboration. Applying it to a lone observation can otherwise
        # promote a merely possible match to probable (or beyond).
        reliability_bonus = (
            max(_RELIABILITY_BONUS.get(item.reliability, 0.0) for item in group)
            if len(sources) > 1
            else 0.0
        )
        corroboration_bonus = min(max(len(sources) - 1, 0) * 0.10, 0.25)
        score = min(avg_confidence + reliability_bonus + corroboration_bonus, 0.99)
        independent_sources = [
            source for source in sources if source != representative.source
        ]
        identity_status = status_from_score(score)
        statuses = {item.identity_status for item in group}
        if statuses == {IdentityStatus.UNRELATED}:
            identity_status = IdentityStatus.UNRELATED
        elif IdentityStatus.UNRELATED in statuses:
            # Conflicting positive and negative disambiguation signals require
            # analyst review; they can never be promoted to probable.
            identity_status = IdentityStatus.POSSIBLE
        elif len(sources) == 1 and identity_status in {
            IdentityStatus.PROBABLE,
            IdentityStatus.HIGHLY_PROBABLE,
            IdentityStatus.CONFIRMED,
        }:
            # Observation confidence and identity attribution are different:
            # one source can be confident in what it returned, but cannot by
            # itself establish that the observation belongs to this person.
            identity_status = IdentityStatus.POSSIBLE

        merged_notes = list(
            dict.fromkeys(note for item in group for note in item.notes)
        )
        merged_notes.append(
            f"Correlated from {len(group)} observation(s) across "
            f"{len(sources)} independent source(s)."
        )
        # Preserve the representative's normalized public fields for report
        # rendering while retaining the full observation ledger for provenance.
        merged_metadata = {
            **representative.metadata,
            "observations": [item.safe_dump() for item in group],
            "source_count": len(sources),
        }

        correlated.append(
            representative.model_copy(
                update={
                    "confidence": score,
                    "identity_status": identity_status,
                    "corroborated_by": independent_sources,
                    "notes": merged_notes,
                    "metadata": merged_metadata,
                }
            )
        )

    return sorted(correlated, key=lambda item: item.confidence, reverse=True)


def identity_confidence_summary(evidence_items: list[Evidence]) -> IdentityStatus:
    """Return the strongest defensible identity status in the evidence set."""
    if not evidence_items:
        return IdentityStatus.INSUFFICIENT_EVIDENCE

    def has_independent_corroboration(item: Evidence) -> bool:
        other_sources = {
            source for source in item.corroborated_by if source != item.source
        }
        if other_sources:
            return True

        # Preserve compatibility with evidence correlated before
        # ``corroborated_by`` was limited to other sources.
        source_count = item.metadata.get("source_count")
        return isinstance(source_count, int) and source_count >= 2

    status_rank = {
        IdentityStatus.UNRELATED: 0,
        IdentityStatus.INSUFFICIENT_EVIDENCE: 1,
        IdentityStatus.POSSIBLE: 2,
        IdentityStatus.PROBABLE: 3,
        IdentityStatus.HIGHLY_PROBABLE: 4,
        IdentityStatus.CONFIRMED: 5,
    }
    independently_corroborated = [
        item for item in evidence_items if has_independent_corroboration(item)
    ]
    if independently_corroborated:
        strongest = max(
            independently_corroborated,
            key=lambda item: (status_rank[item.identity_status], item.confidence),
        )
        return strongest.identity_status

    # Without an independent source, evidence may support a candidate identity
    # for analyst review but not a probable or confirmed overall identity claim.
    if any(
        status_rank[item.identity_status] >= status_rank[IdentityStatus.POSSIBLE]
        for item in evidence_items
    ):
        return IdentityStatus.POSSIBLE
    if all(
        item.identity_status == IdentityStatus.UNRELATED for item in evidence_items
    ):
        return IdentityStatus.UNRELATED
    return IdentityStatus.INSUFFICIENT_EVIDENCE
