"""Transform discovery without importing or copying third-party tool code."""

from __future__ import annotations

from .base import TransformAdapter, TransformSpec


class TransformRegistry:
    def __init__(self) -> None:
        self._adapters: dict[str, TransformAdapter] = {}

    def register(self, adapter: TransformAdapter) -> None:
        name = adapter.spec.name
        if name in self._adapters:
            raise ValueError(f"Duplicate transform: {name}")
        self._adapters[name] = adapter

    def get(self, name: str) -> TransformAdapter:
        try:
            return self._adapters[name]
        except KeyError as exc:
            raise ValueError(f"Unknown transform: {name}") from exc

    def specs(self) -> list[TransformSpec]:
        return [
            self._adapters[name].spec
            for name in sorted(self._adapters)
        ]

    def applicable(self, entity_type: str) -> list[TransformSpec]:
        return [
            spec
            for spec in self.specs()
            if entity_type in spec.accepted_entity_types
        ]


def build_default_registry() -> TransformRegistry:
    from .adapters.cli_tools import (
        BlackbirdTransform,
        ExifToolTransform,
        GHuntTransform,
        HttpxTransform,
        PopplerTransform,
        SubfinderTransform,
        TesseractTransform,
        TheHarvesterTransform,
    )
    from .adapters.connectors import (
        HoleheTransform,
        MaigretTransform,
        SherlockTransform,
        SpiderFootTransform,
    )

    registry = TransformRegistry()
    for adapter in (
        SpiderFootTransform(),
        SherlockTransform(),
        MaigretTransform(),
        HoleheTransform(),
        BlackbirdTransform(),
        TheHarvesterTransform(),
        SubfinderTransform(),
        HttpxTransform(),
        GHuntTransform(),
        ExifToolTransform(),
        TesseractTransform(),
        PopplerTransform(),
    ):
        registry.register(adapter)
    return registry
