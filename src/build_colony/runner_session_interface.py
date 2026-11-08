from __future__ import annotations

from .runner_adapter import RunnerCapabilities, reference_capabilities
from .runner_session import SessionDispatchReceipt, SessionDispatchRequest, SessionRunnerAdapter
from .runner_session_strict import accept_reference_session_dispatch


class ReferenceSessionRunnerAdapter:
    """Deterministic reference adapter routed through the strict v0.0.5 boundary."""

    def capabilities(self) -> RunnerCapabilities:
        return reference_capabilities()

    def dispatch(self, request: SessionDispatchRequest) -> SessionDispatchReceipt:
        return accept_reference_session_dispatch(request)


__all__ = ["ReferenceSessionRunnerAdapter", "SessionRunnerAdapter"]
