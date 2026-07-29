"""Optional LLM providers. Evidence remains the sole factual source."""

from __future__ import annotations

from abc import ABC, abstractmethod
import json
from typing import Any

import httpx

from .schemas import InvestigationReport

_SYSTEM_INSTRUCTIONS = """
You are an evidence analyst for an authorized defensive OSINT investigation.
Use only the supplied evidence. Do not use outside knowledge or make unsupported
identity claims. Every finding must cite one or more supplied evidence IDs.
Never infer home address, protected attributes, criminality, relationships,
financial status, or intent. Never output passwords, tokens, cookies, session
material, or private communications. Clearly distinguish observation from
identity attribution and preserve uncertainty.
""".strip()


class BaseReportProvider(ABC):
    @abstractmethod
    async def generate(self, payload: dict[str, Any]) -> InvestigationReport:
        raise NotImplementedError


class OpenAIReportProvider(BaseReportProvider):
    def __init__(
        self, *, api_key: str, model: str, base_url: str | None = None
    ) -> None:
        self.api_key = api_key
        self.model = model
        self.base_url = base_url

    async def generate(self, payload: dict[str, Any]) -> InvestigationReport:
        try:
            from openai import AsyncOpenAI
        except ImportError as exc:
            raise RuntimeError("The openai package is not installed") from exc

        client = AsyncOpenAI(api_key=self.api_key, base_url=self.base_url)
        response = await client.responses.create(
            model=self.model,
            store=False,
            instructions=_SYSTEM_INSTRUCTIONS,
            input=json.dumps(payload, ensure_ascii=False),
            text={
                "format": {
                    "type": "json_schema",
                    "name": "worldatlas_person_report",
                    "schema": InvestigationReport.model_json_schema(),
                    "strict": True,
                }
            },
        )
        return InvestigationReport.model_validate_json(response.output_text)


class AnthropicReportProvider(BaseReportProvider):
    def __init__(self, *, api_key: str, model: str) -> None:
        self.api_key = api_key
        self.model = model

    async def generate(self, payload: dict[str, Any]) -> InvestigationReport:
        try:
            from anthropic import AsyncAnthropic
        except ImportError as exc:
            raise RuntimeError("The anthropic package is not installed") from exc
        client = AsyncAnthropic(api_key=self.api_key)
        response = await client.messages.create(
            model=self.model,
            max_tokens=8192,
            system=_SYSTEM_INSTRUCTIONS,
            messages=[{"role": "user", "content": json.dumps(payload)}],
        )
        content = "".join(
            block.text
            for block in response.content
            if getattr(block, "type", "") == "text"
        )
        return InvestigationReport.model_validate_json(content)


class GeminiReportProvider(BaseReportProvider):
    def __init__(self, *, api_key: str, model: str) -> None:
        self.api_key = api_key
        self.model = model

    async def generate(self, payload: dict[str, Any]) -> InvestigationReport:
        try:
            from google import genai
        except ImportError as exc:
            raise RuntimeError("The google-genai package is not installed") from exc
        client = genai.Client(api_key=self.api_key)
        response = await client.aio.models.generate_content(
            model=self.model,
            contents=json.dumps(payload),
            config={
                "system_instruction": _SYSTEM_INSTRUCTIONS,
                "response_mime_type": "application/json",
                "response_schema": InvestigationReport,
            },
        )
        return InvestigationReport.model_validate_json(response.text)


class OllamaReportProvider(BaseReportProvider):
    def __init__(self, *, base_url: str, model: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model

    async def generate(self, payload: dict[str, Any]) -> InvestigationReport:
        request = {
            "model": self.model,
            "stream": False,
            "format": InvestigationReport.model_json_schema(),
            "messages": [
                {"role": "system", "content": _SYSTEM_INSTRUCTIONS},
                {
                    "role": "user",
                    "content": json.dumps(payload, ensure_ascii=False),
                },
            ],
        }
        async with httpx.AsyncClient(timeout=180) as client:
            response = await client.post(f"{self.base_url}/api/chat", json=request)
            response.raise_for_status()
            data = response.json()
        content = data.get("message", {}).get("content", "")
        return InvestigationReport.model_validate_json(content)
