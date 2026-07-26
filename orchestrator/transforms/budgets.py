"""Hard execution budgets which prevent uncontrolled graph expansion."""

from __future__ import annotations

from dataclasses import dataclass, field


class BudgetExceeded(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class TransformBudgets:
    max_parallel_transforms: int = 6
    max_results_per_transform: int = 200
    max_graph_nodes: int = 3000
    max_pivot_depth: int = 2
    transform_timeout: int = 120
    cache_ttl_seconds: int = 86400

    def __post_init__(self) -> None:
        for name in (
            "max_parallel_transforms",
            "max_results_per_transform",
            "max_graph_nodes",
            "transform_timeout",
            "cache_ttl_seconds",
        ):
            if getattr(self, name) < 1:
                raise ValueError(f"{name} must be positive")
        if self.max_pivot_depth < 0:
            raise ValueError("max_pivot_depth cannot be negative")


@dataclass(slots=True)
class BudgetTracker:
    budgets: TransformBudgets
    current_graph_nodes: int = 0
    emitted_evidence_ids: set[str] = field(default_factory=set)

    def authorize_depth(self, depth: int) -> None:
        if depth > self.budgets.max_pivot_depth:
            raise BudgetExceeded(
                f"Pivot depth {depth} exceeds limit {self.budgets.max_pivot_depth}"
            )

    def remaining_results(self) -> int:
        graph_capacity = max(self.budgets.max_graph_nodes - self.current_graph_nodes, 0)
        return min(self.budgets.max_results_per_transform, graph_capacity)

    def retain(self, evidence: list) -> list:
        limit = self.remaining_results()
        if limit < 1:
            raise BudgetExceeded("Graph node budget is exhausted")
        retained = []
        for item in evidence:
            if item.id in self.emitted_evidence_ids:
                continue
            self.emitted_evidence_ids.add(item.id)
            retained.append(item)
            if len(retained) >= limit:
                break
        return retained
