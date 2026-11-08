from __future__ import annotations

from typing import Protocol, runtime_checkable

from .runner_adapter import DispatchReceipt, DispatchRequest, RunnerCapabilities, reference_capabilities
from .runner_strict import accept_reference_dispatch


@runtime_checkable
class RunnerAdapter(Protocol):
    """Minimal provider-neutral adapter surface.

    Implementations transport work. They do not gain Builder, Verifier, or
    Integrator authority merely by satisfying this protocol.
    """

    def capabilities(self) -> RunnerCapabilities:
        """Return a deterministic capability declaration for this adapter."""
        ...

    def dispatch(self, request: DispatchRequest) -> DispatchReceipt:
        """Accept a dispatch request and return a receipt bound to that request."""
        ...


class ReferenceRunnerAdapter:
    """Deterministic loopback implementation used for protocol conformance tests."""

    def capabilities(self) -> RunnerCapabilities:
        return reference_capabilities()

    def dispatch(self, request: DispatchRequest) -> DispatchReceipt:
        return accept_reference_dispatch(request)
