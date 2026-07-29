"""Safe adapters for separately installed CLI tools.

Third-party code is never imported into WorldAtlas.  Each adapter executes a
fixed argv list, parses a bounded machine-readable result, and emits minimized
evidence.  Missing tools are reported as source-coverage gaps.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import time
from typing import Any, Iterable
from urllib.parse import urlsplit

from config import settings
from connectors.cli import run_cli
from intelligence.models import (
    ConnectorResult,
    Evidence,
    IdentityStatus,
    SourceReliability,
)
from intelligence.redaction import redact_sensitive

from ..base import (
    TransformAdapter,
    TransformContext,
    TransformEntity,
    TransformSpec,
)


_USERNAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_EMAIL = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)
_URL = re.compile(r"https?://[^\s<>'\"()\[\]]+", re.IGNORECASE)
_EXTRACTED_EMAIL = re.compile(
    r"(?<![\w.+-])[\w.+-]{1,64}@(?:[\w-]{1,63}\.)+[A-Za-z]{2,63}"
)
_SENSITIVE_METADATA_PARTS = {
    "cookie",
    "credential",
    "hash",
    "password",
    "private",
    "secret",
    "session",
    "token",
}


def _tool(binary: str) -> str | None:
    configured = os.getenv(f"DEEPVAULT_{binary.upper()}_COMMAND")
    if configured:
        candidate = Path(configured)
        if (
            candidate.is_absolute()
            and candidate.is_file()
            and os.access(candidate, os.X_OK)
        ):
            return str(candidate)
        return shutil.which(configured)
    return shutil.which(binary)


def _unavailable(name: str) -> ConnectorResult:
    return ConnectorResult(
        connector=name,
        errors=[f"{name} is not installed or not on PATH"],
    )


def _safe_url(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) > 2000:
        return None
    try:
        parsed = urlsplit(value.strip())
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return value.strip()


def _read_json(path: Path) -> Any:
    if not path.is_file() or path.stat().st_size > settings.max_transform_output_bytes:
        raise ValueError("Transform output is missing or too large")
    return json.loads(path.read_text(encoding="utf-8", errors="replace"))


def _json_lines(text: str) -> Iterable[dict[str, Any]]:
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            yield payload


def _indicator_evidence(
    text: str,
    *,
    source: str,
    source_file: str,
) -> list[Evidence]:
    results: list[Evidence] = []
    seen: set[tuple[str, str]] = set()
    for value in _EXTRACTED_EMAIL.findall(text):
        key = ("email_observation", value.casefold())
        if key in seen:
            continue
        seen.add(key)
        results.append(
            Evidence(
                type="email_observation",
                value=value,
                source=source,
                confidence=0.70,
                reliability=SourceReliability.HIGH,
                identity_status=IdentityStatus.INSUFFICIENT_EVIDENCE,
                notes=[
                    "The identifier was extracted from an operator-supplied file."
                ],
                metadata={"source_file": source_file, "extraction": source},
            )
        )
    for match in _URL.findall(text):
        value = match.rstrip(".,;:")
        key = ("web_observation", value.casefold())
        if key in seen:
            continue
        seen.add(key)
        results.append(
            Evidence(
                type="web_observation",
                value=value,
                source=source,
                source_url=value,
                confidence=0.65,
                reliability=SourceReliability.HIGH,
                identity_status=IdentityStatus.INSUFFICIENT_EVIDENCE,
                metadata={"source_file": source_file, "extraction": source},
            )
        )
    return results


def _authorized_file(value: str) -> Path:
    root = Path(settings.transform_upload_root).resolve()
    path = Path(value).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise PermissionError("File is outside the authorized upload directory") from exc
    if not path.is_file():
        raise ValueError("Authorized file does not exist")
    if path.stat().st_size > settings.max_transform_input_bytes:
        raise ValueError("Authorized file exceeds the transform size limit")
    return path


class BlackbirdTransform(TransformAdapter):
    spec = TransformSpec(
        name="blackbird",
        title="Blackbird account discovery",
        accepted_entity_types={"username", "email"},
        produced_entity_types={"public_profile", "service"},
        passive=True,
        priority="p1",
        independence_group="whatsmyname-catalog",
        description="Import source observations only; Blackbird AI output is disabled.",
    )

    async def execute(
        self,
        entity: TransformEntity,
        context: TransformContext,
    ) -> ConnectorResult:
        del context
        started = time.monotonic()
        binary = _tool("blackbird")
        script = os.getenv("BLACKBIRD_PATH")
        if not binary and script and Path(script).is_file():
            python = os.getenv("BLACKBIRD_PYTHON")
            if python:
                python_path = Path(python).resolve()
                if not python_path.is_file() or not os.access(python_path, os.X_OK):
                    return ConnectorResult(
                        connector=self.spec.name,
                        errors=["BLACKBIRD_PYTHON does not identify an executable"],
                    )
                interpreter = str(python_path)
            else:
                interpreter = sys.executable
            script_path = Path(script).resolve()
            command = [interpreter, str(script_path)]
            command_cwd = script_path.parent
            result_root = command_cwd / "results"
        elif binary:
            command = [binary]
            configured_root = os.getenv("BLACKBIRD_RESULTS_DIR")
            if not configured_root:
                return ConnectorResult(
                    connector=self.spec.name,
                    errors=["BLACKBIRD_RESULTS_DIR is not configured"],
                )
            result_root = Path(configured_root).resolve()
            command_cwd = Path(
                os.getenv("BLACKBIRD_WORKDIR") or result_root.parent
            ).resolve()
        else:
            return _unavailable(self.spec.name)

        if entity.type == "username":
            if not _USERNAME.fullmatch(entity.value):
                raise ValueError("Blackbird received an invalid username")
            command.extend(["--username", entity.value])
        else:
            if not _EMAIL.fullmatch(entity.value):
                raise ValueError("Blackbird received an invalid email")
            command.extend(["--email", entity.value])
        before = (
            {
                path.resolve(): (path.stat().st_mtime_ns, path.stat().st_size)
                for path in result_root.glob("**/*.json")
                if path.is_file()
            }
            if result_root.exists()
            else {}
        )
        command.extend(
            [
                "--json",
                "--no-update",
                "--no-nsfw",
                "--timeout",
                str(min(settings.connector_timeout, 30)),
                "--max-concurrent-requests",
                "10",
            ]
        )
        command_result = await run_cli(
            command,
            timeout=settings.transform_timeout,
            cwd=command_cwd,
            max_output_bytes=settings.max_transform_output_bytes,
        )
        candidates = [
            path
            for path in result_root.glob("**/*.json")
            if path.resolve() not in before
            or before[path.resolve()]
            != (path.stat().st_mtime_ns, path.stat().st_size)
        ] if result_root.exists() else []
        payload: Any = []
        if candidates:
            newest = max(candidates, key=lambda path: path.stat().st_mtime)
            try:
                payload = _read_json(newest)
            except (OSError, ValueError, json.JSONDecodeError):
                payload = []

        evidence: list[Evidence] = []
        for record in payload if isinstance(payload, list) else []:
            if not isinstance(record, dict):
                continue
            url = _safe_url(
                record.get("url")
                or record.get("url_user")
                or record.get("profile_url")
            )
            if not url:
                continue
            evidence.append(
                Evidence(
                    type="social_profile",
                    value=url,
                    source=self.spec.name,
                    source_url=url,
                    confidence=0.52,
                    reliability=SourceReliability.MEDIUM,
                    identity_status=IdentityStatus.POSSIBLE,
                    independence_group=self.spec.independence_group,
                    notes=[
                        "A catalogue result is a candidate, not proof of ownership.",
                        "Blackbird AI profiling was not executed or imported.",
                    ],
                    metadata={
                        "site": str(record.get("name") or "")[:120],
                        "username": entity.value if entity.type == "username" else None,
                    },
                )
            )
        errors = []
        if command_result.returncode != 0:
            errors.append("Blackbird could not complete this transform")
        return ConnectorResult(
            connector=self.spec.name,
            evidence=evidence,
            errors=errors,
            duration_ms=int((time.monotonic() - started) * 1000),
        )


class TheHarvesterTransform(TransformAdapter):
    spec = TransformSpec(
        name="theharvester",
        title="theHarvester passive domain collection",
        accepted_entity_types={"domain"},
        produced_entity_types={
            "email_observation",
            "domain_observation",
            "web_observation",
            "infrastructure_observation",
        },
        passive=True,
        priority="p1",
        independence_group="theharvester",
    )

    async def execute(
        self,
        entity: TransformEntity,
        context: TransformContext,
    ) -> ConnectorResult:
        del context
        binary = _tool("theharvester") or _tool("theHarvester")
        if not binary:
            return _unavailable(self.spec.name)
        domain = entity.value.casefold().rstrip(".")
        if not _DOMAIN.fullmatch(domain):
            raise ValueError("theHarvester received an invalid domain")
        with tempfile.TemporaryDirectory(prefix="deepvault-harvester-") as temp_dir:
            prefix = Path(temp_dir) / "result"
            result = await run_cli(
                [
                    binary,
                    "-d",
                    domain,
                    "-b",
                    "crtsh,waybackarchive,urlscan",
                    "-l",
                    str(min(settings.max_results_per_transform, 200)),
                    "-q",
                    "-f",
                    str(prefix),
                ],
                timeout=settings.transform_timeout,
                max_output_bytes=settings.max_transform_output_bytes,
            )
            try:
                payload = _read_json(prefix.with_suffix(".json"))
            except (OSError, ValueError, json.JSONDecodeError):
                payload = {}
        evidence: list[Evidence] = []
        if isinstance(payload, dict):
            for email in payload.get("emails", []) or []:
                if isinstance(email, str) and _EMAIL.fullmatch(email):
                    evidence.append(
                        Evidence(
                            type="email_observation",
                            value=email,
                            source=self.spec.name,
                            confidence=0.58,
                            reliability=SourceReliability.MEDIUM,
                            metadata={"authorized_domain": domain},
                        )
                    )
            for host in payload.get("hosts", []) or []:
                value = host.get("host") if isinstance(host, dict) else host
                if isinstance(value, str) and (
                    value.casefold() == domain
                    or value.casefold().endswith(f".{domain}")
                ):
                    evidence.append(
                        Evidence(
                            type="domain_observation",
                            value=value.casefold(),
                            source=self.spec.name,
                            confidence=0.68,
                            reliability=SourceReliability.MEDIUM,
                            metadata={"authorized_domain": domain},
                        )
                    )
            for url in [
                *(payload.get("interesting_urls", []) or []),
                *(payload.get("trello_urls", []) or []),
            ]:
                if safe := _safe_url(url):
                    evidence.append(
                        Evidence(
                            type="web_observation",
                            value=safe,
                            source=self.spec.name,
                            source_url=safe,
                            confidence=0.55,
                            reliability=SourceReliability.MEDIUM,
                            metadata={"authorized_domain": domain},
                        )
                    )
        errors = []
        if result.returncode != 0:
            errors.append("theHarvester could not complete this transform")
        return ConnectorResult(
            connector=self.spec.name,
            evidence=evidence,
            errors=errors,
            duration_ms=result.duration_ms,
        )


class SubfinderTransform(TransformAdapter):
    spec = TransformSpec(
        name="subfinder",
        title="Subfinder passive subdomain discovery",
        accepted_entity_types={"domain"},
        produced_entity_types={"domain_observation"},
        passive=True,
        priority="p1",
        independence_group="subfinder",
    )

    async def execute(
        self,
        entity: TransformEntity,
        context: TransformContext,
    ) -> ConnectorResult:
        del context
        binary = _tool("subfinder")
        if not binary:
            return _unavailable(self.spec.name)
        domain = entity.value.casefold().rstrip(".")
        if not _DOMAIN.fullmatch(domain):
            raise ValueError("Subfinder received an invalid domain")
        result = await run_cli(
            [
                binary,
                "-d",
                domain,
                "-oJ",
                "-silent",
                "-timeout",
                str(min(settings.connector_timeout, 30)),
                "-max-time",
                "2",
                "-rl",
                "5",
                "-mr",
                str(min(settings.max_results_per_transform, 200)),
            ],
            timeout=settings.transform_timeout,
            max_output_bytes=settings.max_transform_output_bytes,
        )
        evidence = []
        for payload in _json_lines(result.stdout):
            host = str(payload.get("host") or "").casefold().rstrip(".")
            if not host or not (
                host == domain or host.endswith(f".{domain}")
            ):
                continue
            sources = payload.get("sources")
            evidence.append(
                Evidence(
                    type="domain_observation",
                    value=host,
                    source=self.spec.name,
                    confidence=0.68,
                    reliability=SourceReliability.MEDIUM,
                    metadata={
                        "authorized_domain": domain,
                        "passive_sources": (
                            sources[:25] if isinstance(sources, list) else []
                        ),
                    },
                )
            )
        errors = []
        if result.returncode != 0:
            errors.append("Subfinder could not complete this transform")
        return ConnectorResult(
            connector=self.spec.name,
            evidence=evidence,
            errors=errors,
            duration_ms=result.duration_ms,
        )


class HttpxTransform(TransformAdapter):
    spec = TransformSpec(
        name="httpx",
        title="HTTP metadata probe",
        accepted_entity_types={"domain", "hostname", "url"},
        produced_entity_types={"web_observation", "infrastructure_observation"},
        passive=False,
        priority="p2",
        independence_group="httpx",
        description="Active HTTP metadata probing for explicitly authorized assets.",
    )

    async def execute(
        self,
        entity: TransformEntity,
        context: TransformContext,
    ) -> ConnectorResult:
        del context
        binary = _tool("httpx")
        if not binary:
            return _unavailable(self.spec.name)
        result = await run_cli(
            [
                binary,
                "-u",
                entity.value,
                "-json",
                "-silent",
                "-rl",
                "5",
                "-t",
                "5",
                "-timeout",
                str(min(settings.connector_timeout, 10)),
                "-no-color",
            ],
            timeout=settings.transform_timeout,
            max_output_bytes=settings.max_transform_output_bytes,
        )
        evidence = []
        for payload in _json_lines(result.stdout):
            url = _safe_url(payload.get("url"))
            if not url:
                continue
            evidence.append(
                Evidence(
                    type="web_observation",
                    value=url,
                    source=self.spec.name,
                    source_url=url,
                    confidence=0.80,
                    reliability=SourceReliability.HIGH,
                    identity_status=IdentityStatus.INSUFFICIENT_EVIDENCE,
                    metadata=redact_sensitive(
                        {
                            "status_code": payload.get("status_code"),
                            "title": payload.get("title"),
                            "webserver": payload.get("webserver"),
                            "tech": payload.get("tech", [])[:25]
                            if isinstance(payload.get("tech"), list)
                            else [],
                            "host": payload.get("host"),
                        }
                    ),
                )
            )
        errors = []
        if result.returncode != 0:
            errors.append("httpx could not complete this transform")
        return ConnectorResult(
            connector=self.spec.name,
            evidence=evidence,
            errors=errors,
            duration_ms=result.duration_ms,
        )


class GHuntTransform(TransformAdapter):
    spec = TransformSpec(
        name="ghunt",
        title="GHunt public Google identity",
        accepted_entity_types={"email"},
        produced_entity_types={"public_profile"},
        passive=True,
        manual_only=True,
        authenticated=True,
        priority="p2",
        independence_group="google",
        description=(
            "Requires explicit consent and a separately managed GHunt session. "
            "Cookies are never accepted or persisted by WorldAtlas."
        ),
    )

    async def execute(
        self,
        entity: TransformEntity,
        context: TransformContext,
    ) -> ConnectorResult:
        del context
        if not _EMAIL.fullmatch(entity.value):
            raise ValueError("GHunt received an invalid email")
        binary = _tool("ghunt")
        if not binary:
            return _unavailable(self.spec.name)
        with tempfile.TemporaryDirectory(prefix="deepvault-ghunt-") as temp_dir:
            output = Path(temp_dir) / "result.json"
            result = await run_cli(
                [binary, "email", entity.value, "--json", str(output)],
                timeout=settings.transform_timeout,
                max_output_bytes=settings.max_transform_output_bytes,
            )
            try:
                payload = _read_json(output)
            except (OSError, ValueError, json.JSONDecodeError):
                payload = {}
        public_urls: set[str] = set()
        queue = [payload]
        while queue:
            value = queue.pop()
            if isinstance(value, dict):
                for key, member in value.items():
                    normalized_key = str(key).casefold()
                    if any(part in normalized_key for part in _SENSITIVE_METADATA_PARTS):
                        continue
                    queue.append(member)
            elif isinstance(value, list):
                queue.extend(value[:100])
            elif safe := _safe_url(value):
                public_urls.add(safe)
        evidence = [
            Evidence(
                type="public_profile",
                value=url,
                source=self.spec.name,
                source_url=url,
                confidence=0.55,
                reliability=SourceReliability.MEDIUM,
                identity_status=IdentityStatus.POSSIBLE,
                notes=[
                    "Google public metadata requires manual identity disambiguation."
                ],
                metadata={"query_type": "explicit_consent_email"},
            )
            for url in sorted(public_urls)
        ]
        errors = []
        if result.returncode != 0:
            errors.append("GHunt could not complete this transform")
        return ConnectorResult(
            connector=self.spec.name,
            evidence=evidence,
            errors=errors,
            duration_ms=result.duration_ms,
        )


class ExifToolTransform(TransformAdapter):
    spec = TransformSpec(
        name="exiftool",
        title="ExifTool metadata extraction",
        accepted_entity_types={"file"},
        produced_entity_types={"document_metadata"},
        passive=True,
        priority="p1",
        independence_group="operator-supplied-file",
    )

    async def execute(
        self,
        entity: TransformEntity,
        context: TransformContext,
    ) -> ConnectorResult:
        binary = _tool("exiftool")
        if not binary:
            return _unavailable(self.spec.name)
        path = _authorized_file(entity.value)
        result = await run_cli(
            [binary, "-json", "-G", "-n", str(path)],
            timeout=min(settings.transform_timeout, 60),
            max_output_bytes=settings.max_transform_output_bytes,
        )
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            payload = []
        metadata: dict[str, Any] = {}
        if isinstance(payload, list) and payload and isinstance(payload[0], dict):
            for key, value in payload[0].items():
                normalized = str(key).casefold()
                if normalized.endswith("sourcefile"):
                    continue
                if any(part in normalized for part in _SENSITIVE_METADATA_PARTS):
                    continue
                if (
                    not context.allow_sensitive_pivots
                    and any(part in normalized for part in ("gps", "location"))
                ):
                    continue
                if isinstance(value, (str, int, float, bool)) and len(str(value)) <= 1000:
                    metadata[str(key)[:150]] = value
        evidence = []
        if metadata:
            evidence.append(
                Evidence(
                    type="document_metadata",
                    value=path.name,
                    source=self.spec.name,
                    confidence=0.92,
                    reliability=SourceReliability.HIGH,
                    identity_status=IdentityStatus.INSUFFICIENT_EVIDENCE,
                    metadata=metadata,
                )
            )
        errors = []
        if result.returncode != 0:
            errors.append("ExifTool could not complete this transform")
        return ConnectorResult(
            connector=self.spec.name,
            evidence=evidence,
            errors=errors,
            duration_ms=result.duration_ms,
        )


class TesseractTransform(TransformAdapter):
    spec = TransformSpec(
        name="tesseract",
        title="Tesseract OCR indicators",
        accepted_entity_types={"file"},
        produced_entity_types={"email_observation", "web_observation"},
        passive=True,
        priority="p1",
        independence_group="operator-supplied-file",
    )

    async def execute(
        self,
        entity: TransformEntity,
        context: TransformContext,
    ) -> ConnectorResult:
        del context
        binary = _tool("tesseract")
        if not binary:
            return _unavailable(self.spec.name)
        path = _authorized_file(entity.value)
        result = await run_cli(
            [binary, str(path), "stdout"],
            timeout=settings.transform_timeout,
            max_output_bytes=settings.max_transform_output_bytes,
        )
        evidence = _indicator_evidence(
            result.stdout[: settings.max_transform_output_bytes],
            source=self.spec.name,
            source_file=path.name,
        )
        errors = []
        if result.returncode != 0:
            errors.append("Tesseract could not complete this transform")
        return ConnectorResult(
            connector=self.spec.name,
            evidence=evidence,
            errors=errors,
            duration_ms=result.duration_ms,
        )


class PopplerTransform(TransformAdapter):
    spec = TransformSpec(
        name="poppler",
        title="Poppler PDF indicator extraction",
        accepted_entity_types={"file"},
        produced_entity_types={"email_observation", "web_observation"},
        passive=True,
        priority="p1",
        independence_group="operator-supplied-file",
    )

    async def execute(
        self,
        entity: TransformEntity,
        context: TransformContext,
    ) -> ConnectorResult:
        del context
        binary = _tool("pdftotext")
        if not binary:
            return _unavailable(self.spec.name)
        path = _authorized_file(entity.value)
        if path.suffix.casefold() != ".pdf":
            raise ValueError("Poppler accepts PDF files only")
        result = await run_cli(
            [binary, "-layout", str(path), "-"],
            timeout=settings.transform_timeout,
            max_output_bytes=settings.max_transform_output_bytes,
        )
        evidence = _indicator_evidence(
            result.stdout[: settings.max_transform_output_bytes],
            source=self.spec.name,
            source_file=path.name,
        )
        errors = []
        if result.returncode != 0:
            errors.append("Poppler could not complete this transform")
        return ConnectorResult(
            connector=self.spec.name,
            evidence=evidence,
            errors=errors,
            duration_ms=result.duration_ms,
        )
