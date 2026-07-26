"""Evidence quality gates for person-focused OSINT results.

Collectors report observations.  This module decides how prominently those
observations may be presented.  It performs no network access and never turns a
username-existence result into an identity claim without contextual evidence.
"""

from __future__ import annotations

from collections import Counter
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .models import Evidence, IdentityStatus


PROFILE_TYPES = {
    "github_profile",
    "public_profile",
    "social_profile",
    "web_profile",
}
SERVICE_SIGNAL_TYPES = {"service_presence", "service_registration"}
EXPOSURE_TYPES = {"breach", "breach_metadata", "darkweb"}

USERNAME_CATALOGUE_SOURCES = {
    "blackbird",
    "maigret",
    "sherlock",
    "whatsmyname",
}

_HOST_ALIASES = {
    "m.youtube.com": "youtube.com",
    "www.youtube.com": "youtube.com",
    "www.linkedin.com": "linkedin.com",
    "www.slideshare.net": "slideshare.net",
}
_IDENTITY_QUERY_KEYS = {"handle", "id", "profile", "user", "username"}
_SENSITIVE_PROFILE_HOSTS = {
    "chaturbate.com",
    "onlyfans.com",
    "pornhub.com",
    "stripchat.com",
    "xhamster.com",
    "xnxx.com",
    "xvideos.com",
}
_REJECTING_FLAGS = {
    "generic_redirect",
    "not_found",
    "profile_missing",
    "soft_404",
}
_VALIDATION_FLAGS = {
    "canonical_profile_match",
    "content_validated",
    "profile_content_validated",
    "username_in_page",
}

_SPACE = re.compile(r"\s+")
_NON_ALNUM = re.compile(r"[^a-z0-9]+")
_MULTIPLE_SLASHES = re.compile(r"/+")


def canonical_profile_url(value: Any) -> str | None:
    """Return a stable, human-profile URL without tracking parameters."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = urlsplit(value.strip())
    except ValueError:
        return None
    if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname:
        return None

    host = parsed.hostname.casefold()
    host = _HOST_ALIASES.get(host, host.removeprefix("www."))
    path = _MULTIPLE_SLASHES.sub("/", parsed.path or "/")
    if path != "/":
        path = path.rstrip("/")

    # YouTube exposes the same account through /@handle and /@handle/about.
    if host == "youtube.com" and re.fullmatch(r"/@[^/]+/about", path):
        path = path.rsplit("/", 1)[0]

    query = [
        (key.casefold(), member)
        for key, member in parse_qsl(parsed.query, keep_blank_values=False)
        if key.casefold() in _IDENTITY_QUERY_KEYS
    ]
    query.sort()
    return urlunsplit(("https", host, path, urlencode(query), ""))


def profile_source_family(item: Evidence) -> str:
    """Return a provenance family used to prevent catalogue vote inflation."""
    source = item.source.strip().casefold()
    if item.type.casefold() == "social_profile" and source in USERNAME_CATALOGUE_SOURCES:
        return "username-catalogue"
    return (item.independence_group or item.source).strip().casefold()


def _normalized_text(value: Any) -> str:
    if not isinstance(value, (str, int, float)):
        return ""
    return _SPACE.sub(" ", str(value)).strip().casefold()


def _token_key(value: Any) -> str:
    return _NON_ALNUM.sub("", _normalized_text(value))


def _metadata_layers(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    layers = [metadata]
    nested = metadata.get("public_profile")
    if isinstance(nested, dict):
        layers.append(nested)
    return layers


def _metadata_values(metadata: dict[str, Any], keys: set[str]) -> list[str]:
    values: list[str] = []
    for layer in _metadata_layers(metadata):
        for key in keys:
            value = layer.get(key)
            if isinstance(value, (str, int, float)) and str(value).strip():
                values.append(str(value))
    return values


def _target_value(target: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = target.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return ""


def _target_values(target: dict[str, Any], *keys: str) -> list[str]:
    values: list[str] = []
    for key in keys:
        value = target.get(key)
        if isinstance(value, str) and value.strip():
            values.append(value)
        elif isinstance(value, list):
            values.extend(
                member
                for member in value
                if isinstance(member, str) and member.strip()
            )
    return list(dict.fromkeys(values))


def _matched_attributes(item: Evidence, target: dict[str, Any]) -> list[str]:
    """Compare observed public attributes with analyst-supplied case context."""
    metadata = item.metadata if isinstance(item.metadata, dict) else {}
    matches: list[str] = []

    target_name = _token_key(_target_value(target, "name", "target_name"))
    public_names = _metadata_values(
        metadata,
        {"display_name", "full_name", "name"},
    )
    if target_name and any(_token_key(value) == target_name for value in public_names):
        matches.append("name")

    target_employer = _token_key(_target_value(target, "employer"))
    public_employers = _metadata_values(
        metadata,
        {"company", "employer", "organization"},
    )
    if target_employer and any(
        target_employer == _token_key(value) for value in public_employers
    ):
        matches.append("employer")

    target_location = _token_key(_target_value(target, "location"))
    public_locations = _metadata_values(metadata, {"location"})
    if target_location and any(
        target_location == _token_key(value) for value in public_locations
    ):
        matches.append("location")

    target_usernames = {
        _token_key(value)
        for value in _target_values(
            target,
            "username",
            "usernames",
            "target_username",
            "additional_usernames",
        )
        if _token_key(value)
    }
    # Query-echo fields emitted by catalogue collectors are deliberately not
    # accepted.  Only fields explicitly labelled as observed profile content
    # can corroborate an identity.
    observed_usernames = _metadata_values(
        metadata,
        {"login", "observed_username", "preferred_username", "profile_username"},
    )
    if target_usernames and any(
        _token_key(value) in target_usernames for value in observed_usernames
    ):
        matches.append("username")

    return list(dict.fromkeys(matches))


def _quality_flags(item: Evidence, canonical_url: str | None) -> set[str]:
    metadata = item.metadata if isinstance(item.metadata, dict) else {}
    flags: set[str] = set()
    for flag in _REJECTING_FLAGS | _VALIDATION_FLAGS:
        if metadata.get(flag) is True:
            flags.add(flag)
    if metadata.get("profile_exists") is False:
        flags.add("profile_missing")
    if canonical_url is None and item.type.casefold() in PROFILE_TYPES:
        flags.add("invalid_profile_url")
    elif canonical_url and "/api/" in urlsplit(canonical_url).path.casefold():
        flags.add("non_profile_endpoint")
    return flags


def _quality_update(
    item: Evidence,
    target: dict[str, Any],
) -> tuple[float, IdentityStatus, dict[str, Any]]:
    evidence_type = item.type.casefold()
    canonical_url = canonical_profile_url(item.source_url or item.value)
    matches = _matched_attributes(item, target)
    flags = _quality_flags(item, canonical_url)
    host = urlsplit(canonical_url).hostname if canonical_url else None
    sensitive = bool(host and host in _SENSITIVE_PROFILE_HOSTS)
    validated = bool(flags & _VALIDATION_FLAGS)
    rejected = bool(
        flags & (_REJECTING_FLAGS | {"invalid_profile_url", "non_profile_endpoint"})
    )

    confidence = item.confidence
    status = item.identity_status
    category = "other_observations"
    verification = "possible"

    if status == IdentityStatus.UNRELATED:
        category = "rejected_observations"
        verification = "rejected"
    elif evidence_type in SERVICE_SIGNAL_TYPES:
        confidence = min(item.confidence, 0.30)
        status = IdentityStatus.INSUFFICIENT_EVIDENCE
        category = "service_signals"
        verification = "unverified"
    elif evidence_type in PROFILE_TYPES:
        if status == IdentityStatus.CONFIRMED:
            category = "corroborated_facts"
            verification = "confirmed"
        elif rejected:
            confidence = min(item.confidence, 0.05)
            status = IdentityStatus.INSUFFICIENT_EVIDENCE
            category = "rejected_observations"
            verification = "rejected"
        elif sensitive and len(matches) < 2:
            confidence = min(item.confidence, 0.15)
            status = IdentityStatus.INSUFFICIENT_EVIDENCE
            category = "quarantined_candidates"
            verification = "quarantined"
        elif evidence_type == "social_profile" and not validated and not matches:
            confidence = min(item.confidence, 0.25)
            status = IdentityStatus.INSUFFICIENT_EVIDENCE
            category = "unverified_profiles"
            verification = "unverified"
        elif len(matches) >= 2:
            confidence = max(min(item.confidence, 0.79), 0.68)
            status = IdentityStatus.PROBABLE
            category = "probable_profiles"
            verification = "probable"
        elif matches:
            confidence = max(min(item.confidence, 0.64), 0.40)
            status = IdentityStatus.POSSIBLE
            category = "possible_profiles"
            verification = "possible"
        elif validated:
            confidence = min(item.confidence, 0.39)
            status = IdentityStatus.INSUFFICIENT_EVIDENCE
            category = "unverified_profiles"
            verification = "observed_not_attributed"
        else:
            confidence = min(item.confidence, 0.39)
            status = IdentityStatus.INSUFFICIENT_EVIDENCE
            category = "unverified_profiles"
            verification = "unverified"
    elif evidence_type in EXPOSURE_TYPES:
        category = "defensive_exposure"
        verification = "observed"
    elif status in {
        IdentityStatus.CONFIRMED,
        IdentityStatus.HIGHLY_PROBABLE,
        IdentityStatus.PROBABLE,
    }:
        category = "corroborated_facts"
        verification = status.value
    elif status == IdentityStatus.INSUFFICIENT_EVIDENCE:
        category = "unverified_observations"
        verification = "unverified"
    else:
        category = "possible_facts"
        verification = "possible"

    quality = {
        "category": category,
        "verification_status": verification,
        "observation_confidence": round(item.confidence, 4),
        "identity_confidence": round(confidence, 4),
        "matched_attributes": matches,
        "flags": sorted(flags),
        "sensitive": sensitive,
        "canonical_url": canonical_url,
        "source_family": profile_source_family(item),
    }
    return confidence, status, quality


def refine_evidence_quality(
    evidence_items: list[Evidence],
    target_context: dict[str, Any],
) -> list[Evidence]:
    """Annotate and conservatively rescore normalized observations."""
    refined: list[Evidence] = []
    for item in evidence_items:
        confidence, status, quality = _quality_update(item, target_context)
        metadata = {
            **item.metadata,
            "quality": quality,
        }
        notes = list(item.notes)
        if quality["verification_status"] in {
            "quarantined",
            "rejected",
            "unverified",
        }:
            notes.append(
                "Result prominence was reduced by the DeepVault evidence-quality gate."
            )
        canonical_url = quality.get("canonical_url")
        update: dict[str, Any] = {
            "confidence": round(confidence, 4),
            "identity_status": status,
            "metadata": metadata,
            "notes": list(dict.fromkeys(notes)),
        }
        if canonical_url and item.type.casefold() in PROFILE_TYPES:
            update["value"] = canonical_url
            update["source_url"] = canonical_url
        refined.append(item.model_copy(update=update))
    return refined


def evidence_quality(item: Evidence) -> dict[str, Any]:
    quality = item.metadata.get("quality")
    if isinstance(quality, dict):
        return quality
    return {
        "category": "other_observations",
        "verification_status": (
            "rejected"
            if item.identity_status == IdentityStatus.UNRELATED
            else item.identity_status.value
        ),
        "sensitive": False,
        "matched_attributes": [],
        "flags": [],
    }


def quality_summary(evidence_items: list[Evidence]) -> dict[str, int]:
    """Return stable counts used by both reports and the dashboard."""
    counts: Counter[str] = Counter()
    for item in evidence_items:
        quality = evidence_quality(item)
        counts[str(quality.get("verification_status") or "unverified")] += 1
    return {
        "confirmed": counts["confirmed"],
        "highly_probable": counts["highly_probable"],
        "probable": counts["probable"],
        "possible": counts["possible"],
        "observed": counts["observed"],
        "unverified": counts["unverified"]
        + counts["observed_not_attributed"],
        "quarantined": counts["quarantined"],
        "rejected": counts["rejected"],
    }


__all__ = [
    "USERNAME_CATALOGUE_SOURCES",
    "canonical_profile_url",
    "evidence_quality",
    "profile_source_family",
    "quality_summary",
    "refine_evidence_quality",
]
