"""Generate a defensible report whose claims are linked to evidence IDs."""

from __future__ import annotations

from collections import Counter
from datetime import date, datetime, time, timezone
import hashlib
import logging
import re
from typing import Any
from urllib.parse import urlsplit

from config import settings
from intelligence.correlation import (
    correlate_evidence,
    identity_confidence_summary,
)
from intelligence.identity_graph import IdentityGraph, build_identity_graph
from intelligence.models import Evidence, IdentityStatus, SourceReliability
from intelligence.quality import (
    evidence_quality,
    quality_summary,
    refine_evidence_quality,
)
from intelligence.redaction import redact_sensitive
from intelligence.temporal import (
    TemporalComparison,
    compare_evidence_snapshots,
)

from .providers import (
    AnthropicReportProvider,
    BaseReportProvider,
    GeminiReportProvider,
    OllamaReportProvider,
    OpenAIReportProvider,
)
from .schemas import (
    Contradiction,
    Finding,
    InvestigationReport,
    RiskLevel,
    SourceCoverage,
    TimelineEvent,
)

logger = logging.getLogger("deepvault.reporting.person_report")

_CONFIDENCE_MAP = {
    "speculative": 0.25,
    "low": 0.35,
    "medium": 0.55,
    "high": 0.75,
    "confirmed": 0.95,
}

_RELIABILITY_MAP = {
    "hibp": SourceReliability.HIGH,
    "github": SourceReliability.HIGH,
    "gravatar": SourceReliability.MEDIUM,
    "hunter": SourceReliability.MEDIUM,
    "sherlock": SourceReliability.MEDIUM,
    "maigret": SourceReliability.MEDIUM,
    "holehe": SourceReliability.MEDIUM,
}

_FINDING_CATEGORY_ORDER = {
    "corroborated_facts": 0,
    "probable_profiles": 1,
    "possible_profiles": 2,
    "defensive_exposure": 3,
    "service_signals": 4,
    "unverified_profiles": 5,
    "quarantined_candidates": 6,
    "rejected_observations": 7,
}


def _artifact_to_evidence(artifact: Any) -> Evidence:
    context = redact_sensitive(getattr(artifact, "context", {}) or {})
    source = str(getattr(artifact, "source", "unknown"))
    evidence_payload = context.get("evidence")
    if isinstance(evidence_payload, dict):
        try:
            return Evidence.model_validate(evidence_payload)
        except Exception:
            pass

    source_type = str(getattr(artifact, "source_type", "observation"))
    value = str(getattr(artifact, "identifier_value", "") or "<empty>")
    source_url = context.get("url") if isinstance(context.get("url"), str) else None
    confidence_label = str(getattr(artifact, "confidence", "medium")).lower()

    return Evidence(
        type=source_type,
        value=value,
        source=source,
        source_url=source_url,
        confidence=_CONFIDENCE_MAP.get(confidence_label, 0.5),
        reliability=_RELIABILITY_MAP.get(source, SourceReliability.UNKNOWN),
        identity_status=IdentityStatus.INSUFFICIENT_EVIDENCE,
        metadata=context,
    )


def _coverage_assessment(
    source_status: list[dict[str, Any]] | None,
) -> str:
    statuses = [
        str(item.get("status") or "").strip().casefold()
        for item in source_status or []
        if item.get("source")
    ]
    if not statuses:
        return "not_reported"
    missing = sum(
        status in {"failed", "not_queried", "unavailable"} for status in statuses
    )
    if not missing:
        return "complete"
    if missing / len(statuses) >= 0.30:
        return "insufficient"
    return "partial"


def _risk_from_counts(
    counts: Counter[str],
    source_status: list[dict[str, Any]] | None = None,
) -> RiskLevel:
    breaches = counts.get("breach", 0)
    darkweb = counts.get("darkweb", 0)
    if breaches and darkweb:
        return RiskLevel.HIGH
    if breaches:
        return RiskLevel.MODERATE
    if _coverage_assessment(source_status) in {"insufficient", "partial"}:
        return RiskLevel.UNKNOWN
    return RiskLevel.LOW


def _clean_scalar(value: Any, *, limit: int = 320) -> str | None:
    if not isinstance(value, (str, int, float, bool)):
        return None
    cleaned = " ".join(str(value).split())
    if not cleaned:
        return None
    if len(cleaned) > limit:
        return f"{cleaned[: limit - 1].rstrip()}…"
    return cleaned


def _public_url(item: Evidence) -> str | None:
    for candidate in (item.source_url, item.value):
        value = _clean_scalar(candidate, limit=500)
        if not value:
            continue
        parsed = urlsplit(value)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            return value
    return None


def _platform_label(item: Evidence) -> str:
    url = _public_url(item)
    if url:
        hostname = (urlsplit(url).hostname or "").lower()
        if hostname.startswith("www."):
            hostname = hostname[4:]
        if hostname:
            return hostname
    for key in ("platform", "site_name", "service"):
        value = _clean_scalar(item.metadata.get(key), limit=100)
        if value and not value.startswith(("{", "[")):
            return value
    return item.source


def _candidate_description(item: Evidence) -> str:
    label = _platform_label(item)
    url = _public_url(item)
    if url:
        return f"{label} ({url})"
    value = _clean_scalar(item.value, limit=240)
    return f"{label} ({value})" if value and value != label else label


def _service_label(item: Evidence) -> str:
    value = _clean_scalar(item.value, limit=160)
    if value:
        return value
    return _platform_label(item)


def _public_profile_fields(item: Evidence) -> list[str]:
    if item.type != "public_profile":
        return []
    details = []
    for key, label in (
        ("display_name", "display name"),
        ("location", "location"),
        ("job_title", "job title"),
        ("company", "company"),
        ("description", "description"),
    ):
        value = _clean_scalar(item.metadata.get(key), limit=280)
        if value:
            details.append(f"{label}: {value}")
    verified_accounts = item.metadata.get("verified_accounts")
    if isinstance(verified_accounts, list):
        account_labels = []
        for account in verified_accounts[:8]:
            if isinstance(account, dict):
                service = _clean_scalar(
                    account.get("label")
                    or account.get("type")
                    or account.get("service_label")
                    or account.get("service_type"),
                    limit=80,
                )
                url = _clean_scalar(account.get("url"), limit=280)
                if service and url:
                    account_labels.append(f"{service} ({url})")
                elif service or url:
                    account_labels.append(service or url or "")
            else:
                value = _clean_scalar(account, limit=280)
                if value:
                    account_labels.append(value)
        if account_labels:
            details.append(
                f"linked verified-account entries: {'; '.join(account_labels)}"
            )
    return details


def _chunks(items: list[Evidence], size: int = 4) -> list[list[Evidence]]:
    return [items[index : index + size] for index in range(0, len(items), size)]


def _mean_confidence(items: list[Evidence]) -> float:
    return round(sum(item.confidence for item in items) / len(items), 4)


def _grouped_candidate_findings(evidence: list[Evidence]) -> list[Finding]:
    groups: dict[tuple[str, str, str, bool], list[Evidence]] = {}
    for item in evidence:
        if item.type in {"social_profile", "service_registration"}:
            quality = evidence_quality(item)
            groups.setdefault(
                (
                    item.type,
                    str(quality.get("category") or "other_observations"),
                    str(
                        quality.get("verification_status")
                        or item.identity_status.value
                    ),
                    bool(quality.get("sensitive")),
                ),
                [],
            ).append(item)

    findings: list[Finding] = []
    for (
        evidence_type,
        category,
        verification_status,
        sensitive,
    ), items in groups.items():
        chunk_size = 12 if verification_status in {"unverified", "rejected"} else 6
        chunks = _chunks(items, size=chunk_size)
        for part_number, part in enumerate(chunks, start=1):
            part_suffix = (
                f" ({part_number}/{len(chunks)})"
                if len(items) > len(part)
                else ""
            )
            sources = ", ".join(
                sorted({item.source for item in part}, key=str.casefold)
            )
            if verification_status == "rejected":
                observations = "; ".join(
                    _candidate_description(item)
                    if evidence_type == "social_profile"
                    else _service_label(item)
                    for item in part
                )
                statement = (
                    f"{len(part)} observation(s) from {sources} failed an identity "
                    f"or profile-quality gate: {observations}. They remain in the "
                    "audit ledger but are excluded from identity conclusions."
                )
                title = f"Rejected observations{part_suffix}"
                limitations = [
                    "A rejected observation is not attributed to the person.",
                    "Re-evaluate only when new public, independently cited evidence exists.",
                ]
            elif evidence_type == "social_profile":
                candidates = "; ".join(_candidate_description(item) for item in part)
                if verification_status == "quarantined":
                    title = f"Quarantined sensitive candidates{part_suffix}"
                    statement = (
                        f"{sources} returned {len(part)} sensitive-profile candidate(s): "
                        f"{candidates}. They have no sufficient contextual match and "
                        "must not appear as attributed findings."
                    )
                elif verification_status == "probable":
                    title = f"Probable public profiles{part_suffix}"
                    statement = (
                        f"{len(part)} profile candidate(s) contain multiple matching "
                        f"public attributes: {candidates}. Analyst review is still "
                        "required before confirmation."
                    )
                elif verification_status == "possible":
                    title = f"Possible public profiles{part_suffix}"
                    statement = (
                        f"{len(part)} profile candidate(s) contain limited matching "
                        f"context: {candidates}. They remain possible associations."
                    )
                else:
                    title = f"Unverified username leads{part_suffix}"
                    statement = (
                        f"{sources} returned {len(part)} username-only candidate(s): "
                        f"{candidates}. No independently observed name, employer, "
                        "location, or profile-content match currently links them to "
                        "the investigated person."
                    )
                limitations = [
                    "Candidate ownership requires content-level corroboration.",
                    "Shared or recycled usernames can produce false positives.",
                    "Agreement between username-catalogue tools is not independent corroboration.",
                ]
            else:
                services = "; ".join(_service_label(item) for item in part)
                statement = (
                    f"{sources} returned possible registration indicators for "
                    f"{len(part)} service(s): {services}. These provider responses "
                    "are leads for the authorized email query; they do not verify "
                    "account ownership, activity, or present control."
                )
                title = f"Unverified service-registration signals{part_suffix}"
                limitations = [
                    "Registration signals can be stale or ambiguous.",
                    "Do not attempt login or account recovery to verify a signal.",
                ]
            findings.append(
                Finding(
                    title=title,
                    statement=statement,
                    evidence_ids=[item.id for item in part],
                    confidence=_mean_confidence(part),
                    severity=RiskLevel.LOW,
                    category=category,
                    verification_status=verification_status,
                    sensitive=sensitive,
                    limitations=limitations,
                )
            )
    return sorted(
        findings,
        key=lambda item: (
            _FINDING_CATEGORY_ORDER.get(item.category, 8),
            -item.confidence,
            item.title.casefold(),
        ),
    )


def _finding_statement(item: Evidence) -> str:
    if item.type == "breach":
        breach_name = _clean_scalar(item.metadata.get("breach_name")) or _clean_scalar(
            item.value
        )
        breach_date = _clean_scalar(item.metadata.get("breach_date"), limit=40)
        data_classes = item.metadata.get("data_classes")
        details = [breach_name or "an unnamed breach"]
        if breach_date:
            details.append(f"reported breach date {breach_date}")
        if isinstance(data_classes, list):
            safe_classes = [
                value
                for value in (
                    _clean_scalar(item, limit=80) for item in data_classes[:12]
                )
                if value
            ]
            if safe_classes:
                details.append(f"reported data classes: {', '.join(safe_classes)}")
        return (
            f"{item.source} reported breach metadata for {'; '.join(details)}. "
            "No password, hash, or raw credential value is retained in this report."
        )
    if item.type == "darkweb":
        return (
            f"{item.source} returned an unverified public-index mention for "
            f"{_clean_scalar(item.value) or 'the investigated identifier'}. It must "
            "not be treated as attribution without independent corroboration."
        )
    if item.type == "github_profile":
        profile = item.metadata.get("public_profile")
        profile = profile if isinstance(profile, dict) else {}
        details = []
        for key, label in (
            ("login", "login"),
            ("name", "public name"),
            ("company", "company"),
            ("location", "location"),
            ("public_repos", "public repositories"),
            ("followers", "followers"),
        ):
            value = _clean_scalar(profile.get(key), limit=180)
            if value:
                details.append(f"{label}: {value}")
        url = _public_url(item)
        profile_url = f" at {url}" if url else ""
        profile_details = f" ({'; '.join(details)})" if details else ""
        return (
            f"{item.source} returned a public profile{profile_url}{profile_details}. "
            "A matching login alone does not prove identity ownership."
        )
    if item.type == "public_profile":
        url = _public_url(item)
        details = _public_profile_fields(item)
        profile_url = f" at {url}" if url else ""
        profile_details = f" ({'; '.join(details)})" if details else ""
        return (
            f"{item.source} returned a self-published public profile"
            f"{profile_url}{profile_details}. The fields describe what that profile "
            "publishes; one profile source does not prove that they belong to the "
            "investigated person."
        )
    if item.type == "email_verification":
        status = _clean_scalar(item.metadata.get("status"), limit=80)
        result = _clean_scalar(item.metadata.get("result"), limit=80)
        score = _clean_scalar(item.metadata.get("score"), limit=20)
        details = [
            text
            for text in (
                f"status {status}" if status else None,
                f"result {result}" if result else None,
                f"provider score {score}" if score else None,
            )
            if text
        ]
        detail_suffix = f": {', '.join(details)}" if details else ""
        return (
            f"{item.source} returned email-verification metadata"
            f"{detail_suffix}. "
            "Verification metadata does not establish who controls the address."
        )
    value = _clean_scalar(item.value)
    url = _public_url(item)
    detail = f": {value}" if value else ""
    if url and url != value:
        detail += f" ({url})"
    return (
        f"{item.source} returned a source-backed "
        f"{item.type.replace('_', ' ')} observation{detail}."
    )


def _parse_source_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, date):
        parsed = datetime.combine(value, time.min)
    elif isinstance(value, str) and value.strip():
        normalized = value.strip()
        if normalized.endswith("Z"):
            normalized = f"{normalized[:-1]}+00:00"
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _evidence_timeline(evidence: list[Evidence]) -> list[TimelineEvent]:
    events: list[TimelineEvent] = []
    for item in evidence:
        if item.type == "breach":
            occurred_at = _parse_source_datetime(item.metadata.get("breach_date"))
            if occurred_at:
                name = _clean_scalar(item.metadata.get("breach_name")) or _clean_scalar(
                    item.value
                )
                events.append(
                    TimelineEvent(
                        occurred_at=occurred_at,
                        description=(
                            f"{item.source} reports the breach "
                            f"{name or 'event'} on this date."
                        ),
                        evidence_ids=[item.id],
                    )
                )
        elif item.type == "github_profile":
            profile = item.metadata.get("public_profile")
            if not isinstance(profile, dict):
                continue
            for key, description in (
                ("created_at", "GitHub reports that the public profile was created."),
                ("updated_at", "GitHub reports that the public profile was updated."),
            ):
                occurred_at = _parse_source_datetime(profile.get(key))
                if occurred_at:
                    events.append(
                        TimelineEvent(
                            occurred_at=occurred_at,
                            description=description,
                            evidence_ids=[item.id],
                        )
                    )
    return sorted(events, key=lambda event: event.occurred_at)


_COVERAGE_DETAIL_BY_STATUS = {
    "evidence_collected": "Normalized evidence was collected; see the cited evidence IDs.",
    "no_results": (
        "The source completed but returned no normalized evidence. This absence is "
        "not proof that no public information exists."
    ),
    "unavailable": (
        "The source was unavailable or not configured. No conclusion can be drawn "
        "from the missing coverage."
    ),
    "not_queried": (
        "The source was selected, but the supplied identifiers did not produce an "
        "executable query."
    ),
    "failed": (
        "The source did not complete. Review connector configuration and sanitized "
        "runtime diagnostics."
    ),
}


_COVERAGE_DETAIL_BY_REASON = {
    "missing_configuration": (
        "{source} requires configuration that is not currently present; it was not "
        "queried."
    ),
    "connector_unavailable": (
        "{source} is not available in the current runtime; it was not queried."
    ),
    "timeout": (
        "{source} timed out before completing. No conclusion can be drawn from the "
        "missing result."
    ),
    "rate_limited": (
        "{source} rejected the request because of a rate limit. Retry later before "
        "drawing a coverage conclusion."
    ),
    "authentication_rejected": (
        "{source} rejected configured authentication; review that connector's "
        "credentials outside the report."
    ),
    "invalid_request_or_response": (
        "{source} returned an unusable request or response. No evidence was accepted."
    ),
    "request_failed": (
        "{source} did not complete its request. Review sanitized runtime diagnostics."
    ),
}


def _coverage_detail(status: str, reason_code: Any = None, source: str = "") -> str:
    code = _clean_scalar(reason_code, limit=80)
    if code in _COVERAGE_DETAIL_BY_REASON:
        safe_source = _clean_scalar(source, limit=100) or "The source"
        return _COVERAGE_DETAIL_BY_REASON[code].format(source=safe_source)
    return _COVERAGE_DETAIL_BY_STATUS.get(
        status,
        "Coverage status is unknown; do not infer that the source contains no results.",
    )


def _baseline_report(
    evidence: list[Evidence],
    source_status: list[dict[str, Any]] | None = None,
) -> InvestigationReport:
    counts = Counter(item.type for item in evidence)
    candidate_counts = Counter(
        item.type
        for item in evidence
        if item.identity_status != IdentityStatus.UNRELATED
    )
    unrelated_count = sum(
        item.identity_status == IdentityStatus.UNRELATED for item in evidence
    )
    identity_status = identity_confidence_summary(evidence)
    coverage_assessment = _coverage_assessment(source_status)
    risk = _risk_from_counts(counts, source_status)
    result_quality = quality_summary(evidence)

    findings = _grouped_candidate_findings(evidence)
    findings.extend(
        Finding(
            title=f"{item.type.replace('_', ' ').title()} — {item.source}",
            statement=_finding_statement(item),
            evidence_ids=[item.id],
            confidence=round(item.confidence, 4),
            severity=(
                RiskLevel.MODERATE if item.type == "breach" else RiskLevel.LOW
            ),
            category=str(
                evidence_quality(item).get("category") or "other_observations"
            ),
            verification_status=str(
                evidence_quality(item).get("verification_status")
                or item.identity_status.value
            ),
            sensitive=bool(evidence_quality(item).get("sensitive")),
            limitations=(
                [
                    "Breach metadata identifies reported exposure, not present "
                    "account compromise.",
                    "No password, hash, or raw credential material was collected.",
                ]
                if item.type == "breach"
                else [
                    "Automated observations require analyst review.",
                    "One public-source match is not proof of identity ownership.",
                ]
            ),
        )
        for item in evidence
        if item.type not in {"social_profile", "service_registration"}
    )

    summary_parts = [
        f"DeepVault normalized {len(evidence)} source observation(s)."
    ]
    actionable_count = (
        result_quality["confirmed"]
        + result_quality["highly_probable"]
        + result_quality["probable"]
        + result_quality["possible"]
        + result_quality["observed"]
    )
    summary_parts.append(
        f"{actionable_count} observation(s) currently meet the threshold for "
        "prominent analyst review."
    )
    if result_quality["unverified"]:
        summary_parts.append(
            f"{result_quality['unverified']} observation(s) remain unverified and "
            "are separated from identity findings."
        )
    if result_quality["quarantined"]:
        summary_parts.append(
            f"{result_quality['quarantined']} sensitive candidate(s) were "
            "quarantined pending stronger corroboration."
        )
    if result_quality["rejected"]:
        summary_parts.append(
            f"{result_quality['rejected']} observation(s) failed a quality or "
            "disambiguation gate."
        )
    if candidate_counts["social_profile"]:
        summary_parts.append(
            f"The evidence includes {candidate_counts['social_profile']} automated "
            "public-profile candidate(s)."
        )
    if candidate_counts["service_registration"]:
        summary_parts.append(
            f"It also includes {candidate_counts['service_registration']} possible "
            "service-registration signal(s)."
        )
    if unrelated_count:
        summary_parts.append(
            f"{unrelated_count} observation(s) were explicitly disambiguated as "
            "unrelated and are not attributed to the person."
        )
    if counts["breach"]:
        summary_parts.append(
            f"Breach-notification sources returned {counts['breach']} metadata "
            "record(s)."
        )
    biographical_types = {
        "real_name",
        "employer",
        "employment",
        "location",
        "education",
        "biography",
    }
    self_published_profiles = [
        item
        for item in evidence
        if item.type == "public_profile" and _public_profile_fields(item)
    ]
    if self_published_profiles:
        summary_parts.append(
            f"{len(self_published_profiles)} public profile(s) supplied "
            "self-published biographical fields. Those fields are leads and are not "
            "independently corroborated by a single profile source."
        )
    elif evidence and not any(item.type in biographical_types for item in evidence):
        summary_parts.append(
            "These observations do not establish independently corroborated "
            "biographical facts about the investigated person."
        )
    unavailable_count = sum(
        1
        for item in source_status or []
        if str(item.get("status") or "").lower()
        in {"unavailable", "failed", "not_queried"}
    )
    no_results_count = sum(
        1
        for item in source_status or []
        if str(item.get("status") or "").lower() == "no_results"
    )
    if unavailable_count:
        summary_parts.append(
            f"{unavailable_count} selected source(s) did not provide usable coverage."
        )
    if no_results_count:
        summary_parts.append(
            f"{no_results_count} selected source(s) completed without normalized "
            "evidence; this is not evidence of absence."
        )
    if coverage_assessment in {"insufficient", "partial"}:
        summary_parts.append(
            f"Source coverage is {coverage_assessment}; defensive exposure is "
            "therefore inconclusive rather than low."
        )
    else:
        summary_parts.append(
            f"The correlation model labels identity confidence as "
            f"{identity_status.value.replace('_', ' ')} and defensive exposure as "
            f"{risk.value}; neither label confirms profile ownership."
        )
    summary = " ".join(summary_parts)
    timeline = _evidence_timeline(evidence)

    evidence_ids_by_source: dict[str, list[str]] = {}
    for item in evidence:
        for source in {item.source, *item.corroborated_by}:
            evidence_ids_by_source.setdefault(source, []).append(item.id)
    collected_counts = Counter(
        {
            source: len(evidence_ids)
            for source, evidence_ids in evidence_ids_by_source.items()
        }
    )
    status_by_source = {
        str(item.get("source")): item
        for item in source_status or []
        if item.get("source")
    }
    coverage_sources = sorted(set(collected_counts) | set(status_by_source))
    coverage = []
    for source in coverage_sources:
        status_item = status_by_source.get(source, {})
        status = (
            "evidence_collected"
            if collected_counts[source]
            else str(status_item.get("status") or "no_results").lower()
        )
        coverage.append(
            SourceCoverage(
                source=source,
                evidence_count=collected_counts[source],
                status=status,
                detail=_coverage_detail(
                    status,
                    status_item.get("reason_code"),
                    source,
                ),
                evidence_ids=evidence_ids_by_source.get(source, []),
            )
        )

    contradictions: list[Contradiction] = []
    by_type: dict[str, list[Evidence]] = {}
    for item in evidence:
        by_type.setdefault(item.type, []).append(item)
    for evidence_type, items in by_type.items():
        high_confidence = [item for item in items if item.confidence >= 0.65]
        values = {item.value.casefold().strip() for item in high_confidence}
        if len(values) > 1 and evidence_type in {"location", "employer", "real_name"}:
            contradictions.append(
                Contradiction(
                    description=(
                        f"Sources report conflicting {evidence_type.replace('_', ' ')} values."
                    ),
                    evidence_ids=[item.id for item in high_confidence],
                    recommendation="Resolve the conflict manually using dated primary sources.",
                )
            )
    recommendations = [
        "Document source access dates and analyst decisions in the case record.",
    ]
    if candidate_counts["social_profile"]:
        recommendations.append(
            "Review candidate pages manually and require matching public attributes "
            "such as name, avatar, employer, location, or linked domains before "
            "associating a profile with the person."
        )
    if candidate_counts["service_registration"]:
        recommendations.append(
            "Verify service-registration signals only through the subject's own "
            "account and privacy controls; do not attempt third-party login or "
            "password recovery."
        )
    if counts["breach"]:
        recommendations.append(
            "Prioritize remediation for verified breach exposure and rotate affected "
            "credentials outside DeepVault."
        )
    if unavailable_count:
        recommendations.append(
            "Restore missing connector configuration or runtime dependencies, then "
            "rerun the authorized case before drawing a coverage conclusion."
        )
    findings.sort(
        key=lambda item: (
            _FINDING_CATEGORY_ORDER.get(item.category, 8),
            -item.confidence,
            item.title.casefold(),
        )
    )

    return InvestigationReport(
        executive_summary=summary,
        executive_summary_evidence_ids=[item.id for item in evidence],
        identity_confidence=identity_status.value,
        overall_risk=risk,
        evidence_count=len(evidence),
        result_quality=result_quality,
        coverage_assessment=coverage_assessment,
        findings=findings,
        timeline=timeline,
        contradictions=contradictions,
        source_coverage=coverage,
        evidence_ledger=[item.safe_dump() for item in evidence],
        recommendations=recommendations,
        limitations=[
            "Only configured public and contractually authorized sources were queried.",
            "False positives are possible, especially for common names and usernames.",
            "Automated username and service-registration signals identify leads, not "
            "people; candidate pages require content-level corroboration.",
            "A source marked no results or unavailable is not evidence that no public "
            "information exists.",
            "The timeline includes only event dates stated by a source; collection "
            "timestamps are excluded because they are not person-history events.",
            "No authentication bypass, private-message access, or credential retrieval "
            "was performed.",
        ],
        methodology=[
            "Normalize every source result into a common evidence schema.",
            "Remove credential-like fields before persistence or LLM processing.",
            "Deduplicate observations and increase confidence only for independent "
            "corroboration.",
            "Apply a quality gate that separates observation confidence from "
            "identity attribution and quarantines sensitive unverified candidates.",
            "Require every report finding to reference one or more evidence IDs.",
        ],
    )


def _pseudonymize(value: str, category: str) -> str:
    digest = hashlib.sha256(value.strip().casefold().encode("utf-8")).hexdigest()[:10]
    label = re.sub(r"[^A-Z0-9]+", "_", category.upper()).strip("_") or "IDENTIFIER"
    return f"[{label}-{digest}]"


_EXTERNAL_IDENTIFIER_KEYS = {
    "address",
    "aliases",
    "bio",
    "blog",
    "company",
    "description",
    "discovered_emails",
    "discovered_phones",
    "discovered_usernames",
    "domain",
    "domains",
    "email",
    "emails",
    "employer",
    "hostnames",
    "identifier",
    "location",
    "login",
    "name",
    "names",
    "org",
    "phone",
    "phones",
    "profile",
    "query",
    "source_url",
    "target",
    "title",
    "url",
    "username",
    "usernames",
    "value",
}
_EMAIL_VALUE = re.compile(r"(?i)[^\s@]+@[^\s@]+\.[^\s@]+")
_URL_VALUE = re.compile(r"(?i)^https?://")


def _target_identifier_values(target: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in (
        "name",
        "email",
        "phone",
        "username",
        "employer",
        "location",
    ):
        value = target.get(key)
        if isinstance(value, str) and value.strip():
            values.append(value.strip())
    for key in (
        "aliases",
        "domains",
        "discovered_emails",
        "discovered_phones",
        "discovered_usernames",
    ):
        value = target.get(key)
        if isinstance(value, list):
            values.extend(str(item).strip() for item in value if str(item).strip())
    return sorted(set(values), key=len, reverse=True)


def _pseudonymize_external_payload(
    value: Any,
    *,
    key: str = "",
    target_identifiers: list[str],
) -> Any:
    """Remove target identifiers from payloads sent to external LLMs."""
    normalized_key = key.strip().lower()
    if isinstance(value, dict):
        return {
            str(item_key): _pseudonymize_external_payload(
                item,
                key=str(item_key),
                target_identifiers=target_identifiers,
            )
            for item_key, item in value.items()
        }
    if isinstance(value, list):
        return [
            _pseudonymize_external_payload(
                item,
                key=normalized_key,
                target_identifiers=target_identifiers,
            )
            for item in value
        ]
    if not isinstance(value, str) or not value:
        return value
    if (
        normalized_key in _EXTERNAL_IDENTIFIER_KEYS
        or _EMAIL_VALUE.search(value)
        or _URL_VALUE.match(value)
    ):
        return _pseudonymize(value, normalized_key or "identifier")

    scrubbed = value
    for identifier in target_identifiers:
        if identifier.casefold() not in scrubbed.casefold():
            continue
        scrubbed = re.sub(
            re.escape(identifier),
            _pseudonymize(identifier, normalized_key or "identifier"),
            scrubbed,
            flags=re.IGNORECASE,
        )
    return scrubbed


def _llm_payload(
    target: dict[str, Any],
    evidence: list[Evidence],
    baseline: InvestigationReport,
) -> dict[str, Any]:
    safe_target = redact_sensitive(target)
    safe_evidence = [item.safe_dump() for item in evidence]
    if not settings.llm_include_identifiers:
        target_identifiers = _target_identifier_values(safe_target)
        safe_target = _pseudonymize_external_payload(
            safe_target,
            target_identifiers=target_identifiers,
        )
        safe_evidence = _pseudonymize_external_payload(
            safe_evidence,
            target_identifiers=target_identifiers,
        )

    return {
        "target": safe_target,
        "evidence": safe_evidence,
        "baseline_report": baseline.model_dump(
            mode="json",
            exclude={
                "evidence_ledger",
                "identity_graph",
                "temporal_comparison",
            },
        ),
        "rules": {
            "evidence_only": True,
            "all_findings_require_evidence_ids": True,
            "no_sensitive_attribute_inference": True,
            "no_credentials": True,
        },
    }


def _successful_coverage_sources(
    source_status: list[dict[str, Any]] | None,
) -> set[str]:
    return {
        str(item.get("source") or "").strip().casefold()
        for item in source_status or []
        if str(item.get("status") or "").strip().casefold()
        in {"evidence_collected", "no_results"}
        and not str(item.get("reason_code") or "").strip()
    }


def _gate_not_observed_by_coverage(
    comparison: TemporalComparison,
    source_status: list[dict[str, Any]] | None,
) -> TemporalComparison:
    """Suppress absence-like deltas when current source coverage was incomplete."""
    successful_sources = _successful_coverage_sources(source_status)
    kept = [
        item
        for item in comparison.not_observed
        if successful_sources.intersection(item.previous_sources)
    ]
    suppressed = len(comparison.not_observed) - len(kept)
    if not suppressed:
        return comparison
    counts = comparison.counts.model_copy(
        update={"not_observed": len(kept)}
    )
    note = (
        f"{comparison.scope_note} DeepVault omitted {suppressed} possible "
        "not-observed difference(s) because the current run lacked successful "
        "coverage for the relevant source."
    )
    return comparison.model_copy(
        update={
            "counts": counts,
            "not_observed": kept,
            "scope_note": note,
        }
    )


def _with_deterministic_analysis(
    report: InvestigationReport,
    *,
    baseline: InvestigationReport,
) -> InvestigationReport:
    """Restore local analysis that an external model may neither add nor erase."""
    return report.model_copy(
        update={
            "evidence_ledger": baseline.evidence_ledger,
            "identity_graph": baseline.identity_graph,
            "temporal_comparison": baseline.temporal_comparison,
            "timeline": baseline.timeline,
            "source_coverage": baseline.source_coverage,
            "recommendations": baseline.recommendations,
            "limitations": list(
                dict.fromkeys([*baseline.limitations, *report.limitations])
            ),
            "methodology": baseline.methodology,
        }
    )


def _validate_references(
    report: InvestigationReport,
    evidence: list[Evidence],
    *,
    previous_evidence: list[Evidence] | None = None,
) -> None:
    valid_ids = {item.id for item in evidence}
    for finding in report.findings:
        invalid = set(finding.evidence_ids) - valid_ids
        if invalid:
            raise ValueError(
                f"Report finding contains unknown evidence IDs: {sorted(invalid)}"
            )
    sections = [*report.timeline, *report.contradictions, *report.source_coverage]
    for item in sections:
        invalid = set(item.evidence_ids) - valid_ids
        if invalid:
            raise ValueError(
                f"Report section contains unknown evidence IDs: {sorted(invalid)}"
            )
    invalid_summary = set(report.executive_summary_evidence_ids) - valid_ids
    if invalid_summary:
        raise ValueError(
            f"Executive summary contains unknown evidence IDs: {sorted(invalid_summary)}"
        )

    graph: IdentityGraph | None = report.identity_graph
    if graph is not None:
        graph_ids = {item.id for item in graph.evidence_index}
        invalid_graph_index = graph_ids - valid_ids
        if invalid_graph_index:
            raise ValueError(
                "Identity graph contains unknown evidence IDs: "
                f"{sorted(invalid_graph_index)}"
            )
        for node in graph.nodes:
            invalid = set(node.evidence_ids) - valid_ids
            if invalid:
                raise ValueError(
                    f"Identity graph node contains unknown evidence IDs: "
                    f"{sorted(invalid)}"
                )
        for item in [*graph.edges, *graph.hypotheses, *graph.pivots]:
            invalid = set(item.evidence_ids) - valid_ids
            if invalid:
                raise ValueError(
                    "Identity analysis contains unknown evidence IDs: "
                    f"{sorted(invalid)}"
                )

    comparison = report.temporal_comparison
    if comparison is not None:
        valid_previous_ids = {item.id for item in previous_evidence or []}
        for item in [
            *comparison.added,
            *comparison.not_observed,
            *comparison.persisting,
            *comparison.changed,
        ]:
            if (
                item.current_evidence_id is not None
                and item.current_evidence_id not in valid_ids
            ):
                raise ValueError(
                    "Temporal comparison contains an unknown current evidence ID: "
                    f"{item.current_evidence_id}"
                )
            if (
                item.previous_evidence_id is not None
                and item.previous_evidence_id not in valid_previous_ids
            ):
                raise ValueError(
                    "Temporal comparison contains an unknown previous evidence ID: "
                    f"{item.previous_evidence_id}"
                )


def _provider(name: str) -> BaseReportProvider:
    if name == "openai":
        if not settings.openai_api_key:
            raise RuntimeError("OPENAI_API_KEY is not configured")
        return OpenAIReportProvider(
            api_key=settings.openai_api_key, model=settings.openai_model
        )
    if name == "anthropic":
        if not settings.anthropic_api_key:
            raise RuntimeError("ANTHROPIC_API_KEY is not configured")
        return AnthropicReportProvider(
            api_key=settings.anthropic_api_key, model=settings.anthropic_model
        )
    if name == "gemini":
        if not settings.gemini_api_key:
            raise RuntimeError("GEMINI_API_KEY is not configured")
        return GeminiReportProvider(
            api_key=settings.gemini_api_key, model=settings.gemini_model
        )
    if name == "ollama":
        return OllamaReportProvider(
            base_url=settings.ollama_base_url, model=settings.ollama_model
        )
    if name == "openai-compatible":
        if (
            not settings.openai_compatible_api_key
            or not settings.openai_compatible_base_url
        ):
            raise RuntimeError("OpenAI-compatible endpoint is not configured")
        return OpenAIReportProvider(
            api_key=settings.openai_compatible_api_key,
            model=settings.openai_compatible_model,
            base_url=settings.openai_compatible_base_url,
        )
    raise RuntimeError(f"Unsupported LLM provider: {name}")


def _consensus(
    reports: list[InvestigationReport], baseline: InvestigationReport
) -> InvestigationReport:
    """Retain only claims independently repeated by a majority of providers."""
    if not reports:
        return baseline
    threshold = len(reports) // 2 + 1
    votes: dict[tuple[str, tuple[str, ...]], list[Finding]] = {}
    for report in reports:
        for finding in report.findings:
            key = (
                finding.statement.casefold().strip(),
                tuple(sorted(finding.evidence_ids)),
            )
            votes.setdefault(key, []).append(finding)
    findings = []
    for candidates in votes.values():
        if len(candidates) < threshold:
            continue
        selected = candidates[0].model_copy(
            update={
                "confidence": sum(item.confidence for item in candidates)
                / len(candidates)
            }
        )
        findings.append(selected)
    return baseline.model_copy(
        update={
            "findings": findings or baseline.findings,
            "methodology": baseline.methodology
            + [
                f"Consensus synthesized from {len(reports)} provider reports; "
                f"claims required {threshold} matching votes."
            ],
        }
    )


class PersonReportGenerator:
    async def generate(
        self,
        *,
        target: dict[str, Any],
        artifacts: list[Any],
        current_case_id: str | None = None,
        previous_case_id: str | None = None,
        previous_evidence: list[Evidence] | None = None,
    ) -> InvestigationReport:
        normalized = [_artifact_to_evidence(artifact) for artifact in artifacts]
        quality_gated = refine_evidence_quality(normalized, target)
        correlated = correlate_evidence(quality_gated)
        baseline = _baseline_report(
            correlated,
            source_status=target.get("_source_status"),
        )
        graph_context = {
            **target,
            **({"case_id": current_case_id} if current_case_id else {}),
        }
        identity_graph = build_identity_graph(correlated, graph_context)
        temporal_comparison = None
        if previous_case_id and previous_evidence is not None:
            temporal_comparison = compare_evidence_snapshots(
                previous_evidence,
                correlated,
                previous_case_id=previous_case_id,
                current_case_id=current_case_id,
            )
            temporal_comparison = _gate_not_observed_by_coverage(
                temporal_comparison,
                target.get("_source_status"),
            )
            if not target.get("email") and target.get("username"):
                temporal_comparison = temporal_comparison.model_copy(
                    update={
                        "scope_note": (
                            f"{temporal_comparison.scope_note} The baseline was "
                            "matched by normalized name and username because no "
                            "email was supplied; shared or recycled usernames can "
                            "make that comparison ambiguous."
                        )
                    }
                )
        baseline = baseline.model_copy(
            update={
                "identity_graph": identity_graph,
                "temporal_comparison": temporal_comparison,
                "methodology": baseline.methodology
                + [
                    "Build a case-local identity graph whose relationships, "
                    "hypotheses, and manual pivots cite the normalized evidence "
                    "ledger.",
                    "Do not execute graph pivots automatically or create new "
                    "identifiers from similarity heuristics.",
                ]
                + (
                    [
                        "Compare stable evidence fingerprints with the latest "
                        "comparable authorized case while keeping previous and "
                        "current evidence ID namespaces separate."
                    ]
                    if temporal_comparison is not None
                    else []
                ),
                "limitations": baseline.limitations
                + (
                    [
                        "A not-observed temporal item is a collection difference, "
                        "not proof that an account or fact disappeared."
                    ]
                    if temporal_comparison is not None
                    else []
                ),
            }
        )
        _validate_references(
            baseline,
            correlated,
            previous_evidence=previous_evidence,
        )

        provider_names = [
            item.strip().lower()
            for item in settings.llm_consensus_providers.split(",")
            if item.strip()
        ]
        if not provider_names:
            provider_names = [settings.llm_provider.strip().lower()]
        if provider_names == ["none"]:
            return baseline

        try:
            payload = _llm_payload(target, correlated, baseline)
            reports = []
            for name in provider_names:
                try:
                    report = await _provider(name).generate(payload)
                    report = _with_deterministic_analysis(
                        report,
                        baseline=baseline,
                    )
                    _validate_references(
                        report,
                        correlated,
                        previous_evidence=previous_evidence,
                    )
                    reports.append(report)
                except Exception as exc:
                    logger.warning(
                        "%s report provider failed (%s)",
                        name,
                        type(exc).__name__,
                    )
            if len(provider_names) > 1:
                return _consensus(reports, baseline)
            if not reports:
                return baseline
            return _with_deterministic_analysis(
                reports[0],
                baseline=baseline,
            )
        except Exception as exc:
            logger.warning(
                "LLM report generation failed; using baseline (%s)",
                type(exc).__name__,
            )
            return baseline
