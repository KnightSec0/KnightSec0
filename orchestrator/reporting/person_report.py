"""Generate a defensible report whose claims are linked to evidence IDs."""

from __future__ import annotations

from collections import Counter
import hashlib
import logging
from typing import Any

from config import settings
from intelligence.correlation import (
    correlate_evidence,
    identity_confidence_summary,
)
from intelligence.models import Evidence, IdentityStatus, SourceReliability
from intelligence.redaction import redact_sensitive

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
    "hunter": SourceReliability.MEDIUM,
    "sherlock": SourceReliability.MEDIUM,
    "maigret": SourceReliability.MEDIUM,
    "holehe": SourceReliability.MEDIUM,
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


def _risk_from_counts(counts: Counter[str]) -> RiskLevel:
    breaches = counts.get("breach", 0)
    darkweb = counts.get("darkweb", 0)
    if breaches and darkweb:
        return RiskLevel.HIGH
    if breaches:
        return RiskLevel.MODERATE
    return RiskLevel.LOW


def _finding_statement(item: Evidence) -> str:
    if item.type == "social_profile":
        return (
            "A public profile using an investigated username was reported by "
            f"{item.source}. Username matching alone does not confirm ownership."
        )
    if item.type == "service_registration":
        return (
            "A public service-registration signal was reported for an investigated "
            "email address. The signal requires manual verification."
        )
    if item.type == "breach":
        return (
            "A breach-notification source reported exposure associated with an "
            "investigated identifier. No credential value is retained in this report."
        )
    if item.type == "darkweb":
        return (
            "A public dark-web index returned an unverified mention. It must not be "
            "treated as attribution without independent corroboration."
        )
    return (
        f"A source-backed {item.type.replace('_', ' ')} observation was collected "
        f"from {item.source}."
    )


def _baseline_report(evidence: list[Evidence]) -> InvestigationReport:
    counts = Counter(item.type for item in evidence)
    identity_status = identity_confidence_summary(evidence)
    risk = _risk_from_counts(counts)

    findings = [
        Finding(
            title=f"{item.type.replace('_', ' ').title()} — {item.source}",
            statement=_finding_statement(item),
            evidence_ids=[item.id],
            confidence=item.confidence,
            severity=(RiskLevel.MODERATE if item.type == "breach" else RiskLevel.LOW),
            limitations=[
                "Automated matches require analyst review.",
                "A matching username or email signal is not proof of identity.",
            ],
        )
        for item in evidence[:50]
    ]

    summary = (
        f"DeepVault normalized {len(evidence)} correlated evidence item(s). "
        f"Identity confidence is {identity_status.value.replace('_', ' ')} and "
        f"the current defensive exposure level is {risk.value}. "
        "These results are observations, not a definitive identity determination."
    )
    timeline = [
        TimelineEvent(
            occurred_at=item.observed_at,
            description=_finding_statement(item),
            evidence_ids=[item.id],
        )
        for item in sorted(evidence, key=lambda entry: entry.observed_at)
    ]
    coverage = [
        SourceCoverage(
            source=source,
            evidence_count=count,
            status="evidence_collected",
            evidence_ids=[item.id for item in evidence if item.source == source],
        )
        for source, count in sorted(Counter(item.source for item in evidence).items())
    ]
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
    return InvestigationReport(
        executive_summary=summary,
        executive_summary_evidence_ids=[item.id for item in evidence],
        identity_confidence=identity_status.value,
        overall_risk=risk,
        evidence_count=len(evidence),
        findings=findings,
        timeline=timeline,
        contradictions=contradictions,
        source_coverage=coverage,
        recommendations=[
            "Manually verify possible identity matches using independent public attributes.",
            "Prioritize remediation for verified breach exposure and rotate affected credentials outside DeepVault.",
            "Document source access dates and analyst decisions in the case record.",
        ],
        limitations=[
            "Only configured public and contractually authorized sources were queried.",
            "False positives are possible, especially for common names and usernames.",
            "No authentication bypass, private-message access, or credential retrieval "
            "was performed.",
        ],
        methodology=[
            "Normalize every source result into a common evidence schema.",
            "Remove credential-like fields before persistence or LLM processing.",
            "Deduplicate observations and increase confidence only for independent "
            "corroboration.",
            "Require every report finding to reference one or more evidence IDs.",
        ],
    )


def _pseudonymize(value: str, category: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:10]
    return f"[{category.upper()}-{digest}]"


def _llm_payload(
    target: dict[str, Any],
    evidence: list[Evidence],
    baseline: InvestigationReport,
) -> dict[str, Any]:
    safe_target = redact_sensitive(target)
    if not settings.llm_include_identifiers:
        for key in ("email", "phone", "username", "name"):
            value = safe_target.get(key)
            if isinstance(value, str) and value:
                safe_target[key] = _pseudonymize(value, key)
        for key in ("aliases", "discovered_emails", "discovered_usernames"):
            values = safe_target.get(key)
            if isinstance(values, list):
                safe_target[key] = [_pseudonymize(str(value), key) for value in values]

    return {
        "target": safe_target,
        "evidence": [item.safe_dump() for item in evidence],
        "baseline_report": baseline.model_dump(mode="json"),
        "rules": {
            "evidence_only": True,
            "all_findings_require_evidence_ids": True,
            "no_sensitive_attribute_inference": True,
            "no_credentials": True,
        },
    }


def _validate_references(report: InvestigationReport, evidence: list[Evidence]) -> None:
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
        self, *, target: dict[str, Any], artifacts: list[Any]
    ) -> InvestigationReport:
        normalized = [_artifact_to_evidence(artifact) for artifact in artifacts]
        correlated = correlate_evidence(normalized)
        baseline = _baseline_report(correlated)

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
                    _validate_references(report, correlated)
                    reports.append(report)
                except Exception as exc:
                    logger.warning("%s report provider failed: %s", name, exc)
            if len(provider_names) > 1:
                return _consensus(reports, baseline)
            return reports[0] if reports else baseline
        except Exception as exc:
            logger.warning("LLM report generation failed; using baseline: %s", exc)
            return baseline
