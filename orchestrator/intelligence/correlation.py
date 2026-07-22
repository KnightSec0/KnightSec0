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
        reliability_bonus = max(
            _RELIABILITY_BONUS.get(item.reliability, 0.0) for item in group
        )
        corroboration_bonus = min(max(len(sources) - 1, 0) * 0.10, 0.25)
        score = min(avg_confidence + reliability_bonus + corroboration_bonus, 0.99)

        merged_notes = list(
            dict.fromkeys(note for item in group for note in item.notes)
        )
        merged_notes.append(
            f"Correlated from {len(group)} observation(s) across "
            f"{len(sources)} independent source(s)."
        )
        merged_metadata = {
            "observations": [item.safe_dump() for item in group],
            "source_count": len(sources),
        }

        correlated.append(
            representative.model_copy(
                update={
                    "confidence": score,
                    "identity_status": status_from_score(score),
                    "corroborated_by": sources,
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
    strongest = max(evidence_items, key=lambda item: item.confidence)
    return strongest.identity_status
