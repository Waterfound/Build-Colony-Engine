class BuildColonyError(Exception):
    """Base error for Build Colony."""


class ProfileError(BuildColonyError):
    """Raised when a project profile is invalid."""


class SchedulingError(BuildColonyError):
    """Raised when work cannot be scheduled deterministically."""


class VerificationError(BuildColonyError):
    """Raised when supplied evidence is malformed or inconsistent."""


class ProtocolError(BuildColonyError):
    """Raised when an execution protocol manifest is invalid or inconsistent."""


class StateError(BuildColonyError):
    """Raised when the execution state machine or ledger is invalid."""


class AdapterError(BuildColonyError):
    """Raised when a runner adapter request, receipt, capability set, or result envelope is invalid."""


class SessionError(BuildColonyError):
    """Raised when a runner session attempt, revocation, or session-bound result is invalid."""


class PoolError(BuildColonyError):
    """Raised when runner-pool planning, assignment, attempt, or atomic binding is invalid."""


class RemotePoolError(BuildColonyError):
    """Raised when remote-pool launch binding, source provenance, or evidence admission is invalid."""


class InteropError(BuildColonyError):
    """Raised when an interoperability input is invalid."""
