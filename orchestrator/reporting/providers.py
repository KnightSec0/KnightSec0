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
    def __init__(self, *, api_key: str, model: str) -> None:
        self.api_key = api_key
        self.model = model

    async def generate(self, payload: dict[str, Any]) -> InvestigationReport:
        try:
            from openai import AsyncOpenAI
        except ImportError as exc:
            raise RuntimeError("The openai package is not installed") from exc

        client = AsyncOpenAI(api_key=self.api_key)
        response = await client.responses.create(
            model=self.model,
            store=False,
            instructions=_SYSTEM_INSTRUCTIONS,
            input=json.dumps(payload, ensure_ascii=False),
            text={
                "format": {
                    "type": "json_schema",
                    "name": "deepvault_person_report",
                    "schema": InvestigationReport.model_json_schema(),
                    "strict": True,
                }
            },
        )
        return InvestigationReport.model_validate_json(response.output_text)


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
