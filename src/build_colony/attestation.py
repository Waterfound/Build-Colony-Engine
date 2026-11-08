from __future__ import annotations

import base64
import binascii
import json
from dataclasses import asdict, dataclass, fields, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from .errors import BuildColonyError
from .ledger import ROLE_EVENTS, append_event, verify_ledger
from .protocol import RunManifest, canonical_json, sha256_digest
from .state_models import RunLedger

ATTESTATION_PROTOCOL_VERSION = "0.0.6"
ATTESTATION_SCHEMA_VERSION = 1
ALGORITHM_ED25519 = "ed25519"


class AttestationError(BuildColonyError):
    """Raised when trust policy or actor attestation validation fails."""


@dataclass(frozen=True)
class TrustedSigner:
    signer_id: str
    role: str
    algorithm: str
    public_key_b64: str
    allowed_events: tuple[str, ...]
    signer_digest: str


@dataclass(frozen=True)
class AttestationTrustPolicy:
    schema_version: int
    attestation_protocol_version: str
    run_id: str
    manifest_digest: str
    signers: tuple[TrustedSigner, ...]
    policy_digest: str


@dataclass(frozen=True)
class ActorAttestation:
    schema_version: int
    attestation_protocol_version: str
    run_id: str
    manifest_digest: str
    package_id: str
    role: str
    action: str
    payload_digest: str
    signer_id: str
    policy_digest: str
    signature_b64: str
    attestation_digest: str


def _normal(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return {field.name: _normal(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, dict):
        return {str(key): _normal(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_normal(item) for item in value]
    return value


def _without(value: Any, *names: str) -> dict[str, Any]:
    payload = _normal(value)
    for name in names:
        payload.pop(name, None)
    return payload


def _require_nonempty(value: str, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise AttestationError(f"{field} must be a non-empty string")


def _decode_b64(value: str, field: str, expected_length: int | None = None) -> bytes:
    _require_nonempty(value, field)
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise AttestationError(f"{field} must be canonical base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise AttestationError(f"{field} must use canonical base64 encoding")
    if expected_length is not None and len(decoded) != expected_length:
        raise AttestationError(f"{field} must decode to {expected_length} bytes")
    return decoded


def _signer_payload(signer: TrustedSigner | dict[str, Any]) -> dict[str, Any]:
    return _without(signer, "signer_digest")


def _policy_payload(policy: AttestationTrustPolicy | dict[str, Any]) -> dict[str, Any]:
    return _without(policy, "policy_digest")


def _attestation_payload(attestation: ActorAttestation | dict[str, Any]) -> dict[str, Any]:
    return _without(attestation, "attestation_digest")


def make_trusted_signer(
    *,
    signer_id: str,
    role: str,
    public_key_b64: str,
    allowed_events: tuple[str, ...] | None = None,
    algorithm: str = ALGORITHM_ED25519,
) -> TrustedSigner:
    _require_nonempty(signer_id, "signer_id")
    if role not in ROLE_EVENTS:
        raise AttestationError(f"unknown signer role: {role}")
    if algorithm != ALGORITHM_ED25519:
        raise AttestationError(f"unsupported signing algorithm: {algorithm}")
    _decode_b64(public_key_b64, "public_key_b64", expected_length=32)

    events = tuple(sorted(allowed_events if allowed_events is not None else ROLE_EVENTS[role]))
    if not events:
        raise AttestationError("trusted signer must be authorized for at least one event")
    if len(set(events)) != len(events):
        raise AttestationError("allowed_events must be unique")
    unauthorized = sorted(set(events) - set(ROLE_EVENTS[role]))
    if unauthorized:
        raise AttestationError(
            f"signer role {role} cannot be authorized for events: {unauthorized}"
        )

    unsigned = TrustedSigner(
        signer_id=signer_id,
        role=role,
        algorithm=algorithm,
        public_key_b64=public_key_b64,
        allowed_events=events,
        signer_digest="",
    )
    return TrustedSigner(
        signer_id=unsigned.signer_id,
        role=unsigned.role,
        algorithm=unsigned.algorithm,
        public_key_b64=unsigned.public_key_b64,
        allowed_events=unsigned.allowed_events,
        signer_digest=sha256_digest(_signer_payload(unsigned)),
    )


def verify_trusted_signer(signer: TrustedSigner) -> tuple[bool, tuple[str, ...]]:
    reasons: list[str] = []
    try:
        rebuilt = make_trusted_signer(
            signer_id=signer.signer_id,
            role=signer.role,
            public_key_b64=signer.public_key_b64,
            allowed_events=signer.allowed_events,
            algorithm=signer.algorithm,
        )
    except AttestationError as exc:
        reasons.append(str(exc))
    else:
        if rebuilt.signer_digest != signer.signer_digest:
            reasons.append("trusted signer digest mismatch")
    return not reasons, tuple(reasons)


def make_trust_policy(
    manifest: RunManifest,
    signers: tuple[TrustedSigner, ...],
) -> AttestationTrustPolicy:
    if not signers:
        raise AttestationError("trust policy must contain at least one trusted signer")
    ids = [signer.signer_id for signer in signers]
    if len(ids) != len(set(ids)):
        raise AttestationError("trust policy signer_id values must be unique")
    keys = [signer.public_key_b64 for signer in signers]
    if len(keys) != len(set(keys)):
        raise AttestationError("trust policy public keys must be unique")
    for signer in signers:
        accepted, reasons = verify_trusted_signer(signer)
        if not accepted:
            raise AttestationError(
                f"invalid trusted signer {signer.signer_id}: " + "; ".join(reasons)
            )

    ordered = tuple(sorted(signers, key=lambda item: item.signer_id))
    unsigned = AttestationTrustPolicy(
        schema_version=ATTESTATION_SCHEMA_VERSION,
        attestation_protocol_version=ATTESTATION_PROTOCOL_VERSION,
        run_id=manifest.run_id,
        manifest_digest=manifest.manifest_digest,
        signers=ordered,
        policy_digest="",
    )
    return AttestationTrustPolicy(
        schema_version=unsigned.schema_version,
        attestation_protocol_version=unsigned.attestation_protocol_version,
        run_id=unsigned.run_id,
        manifest_digest=unsigned.manifest_digest,
        signers=unsigned.signers,
        policy_digest=sha256_digest(_policy_payload(unsigned)),
    )


def verify_trust_policy(
    policy: AttestationTrustPolicy,
    manifest: RunManifest,
) -> tuple[bool, tuple[str, ...]]:
    reasons: list[str] = []
    if policy.schema_version != ATTESTATION_SCHEMA_VERSION:
        reasons.append("unsupported attestation policy schema version")
    if policy.attestation_protocol_version != ATTESTATION_PROTOCOL_VERSION:
        reasons.append("unsupported attestation protocol version")
    if policy.run_id != manifest.run_id or policy.manifest_digest != manifest.manifest_digest:
        reasons.append("trust policy is not bound to the supplied Run Manifest")
    if not policy.signers:
        reasons.append("trust policy contains no signers")
    ids: set[str] = set()
    keys: set[str] = set()
    for signer in policy.signers:
        if signer.signer_id in ids:
            reasons.append(f"duplicate signer_id: {signer.signer_id}")
        ids.add(signer.signer_id)
        if signer.public_key_b64 in keys:
            reasons.append(f"duplicate public key for signer: {signer.signer_id}")
        keys.add(signer.public_key_b64)
        accepted, signer_reasons = verify_trusted_signer(signer)
        if not accepted:
            reasons.extend(f"{signer.signer_id}: {reason}" for reason in signer_reasons)
    if policy.policy_digest != sha256_digest(_policy_payload(policy)):
        reasons.append("trust policy digest mismatch")
    return not reasons, tuple(dict.fromkeys(reasons))


def _find_signer(policy: AttestationTrustPolicy, signer_id: str) -> TrustedSigner:
    signer = next((item for item in policy.signers if item.signer_id == signer_id), None)
    if signer is None:
        raise AttestationError(f"signer is not trusted by policy: {signer_id}")
    return signer


def attestation_statement(
    manifest: RunManifest,
    policy: AttestationTrustPolicy,
    *,
    signer_id: str,
    package_id: str,
    role: str,
    action: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    accepted, reasons = verify_trust_policy(policy, manifest)
    if not accepted:
        raise AttestationError("invalid trust policy: " + "; ".join(reasons))
    if "actor_attestation" in payload:
        raise AttestationError("payload supplied for signing must not contain actor_attestation")
    package_ids = {package.package_id for package in manifest.packages}
    if package_id not in package_ids:
        raise AttestationError(f"unknown package_id: {package_id}")
    signer = _find_signer(policy, signer_id)
    if signer.role != role:
        raise AttestationError(
            f"signer role mismatch: signer={signer.role}, requested={role}"
        )
    if action not in signer.allowed_events:
        raise AttestationError(
            f"signer {signer_id} is not authorized for event: {action}"
        )
    return {
        "attestation_protocol_version": ATTESTATION_PROTOCOL_VERSION,
        "run_id": manifest.run_id,
        "manifest_digest": manifest.manifest_digest,
        "package_id": package_id,
        "role": role,
        "action": action,
        "payload_digest": sha256_digest(payload),
        "signer_id": signer_id,
        "policy_digest": policy.policy_digest,
    }


def attestation_statement_bytes(
    manifest: RunManifest,
    policy: AttestationTrustPolicy,
    *,
    signer_id: str,
    package_id: str,
    role: str,
    action: str,
    payload: dict[str, Any],
) -> bytes:
    statement = attestation_statement(
        manifest,
        policy,
        signer_id=signer_id,
        package_id=package_id,
        role=role,
        action=action,
        payload=payload,
    )
    return canonical_json(statement).encode("utf-8")


def make_attestation(
    manifest: RunManifest,
    policy: AttestationTrustPolicy,
    *,
    signer_id: str,
    package_id: str,
    role: str,
    action: str,
    payload: dict[str, Any],
    signature_b64: str,
) -> ActorAttestation:
    statement = attestation_statement(
        manifest,
        policy,
        signer_id=signer_id,
        package_id=package_id,
        role=role,
        action=action,
        payload=payload,
    )
    _decode_b64(signature_b64, "signature_b64", expected_length=64)
    unsigned = ActorAttestation(
        schema_version=ATTESTATION_SCHEMA_VERSION,
        attestation_protocol_version=ATTESTATION_PROTOCOL_VERSION,
        run_id=statement["run_id"],
        manifest_digest=statement["manifest_digest"],
        package_id=statement["package_id"],
        role=statement["role"],
        action=statement["action"],
        payload_digest=statement["payload_digest"],
        signer_id=statement["signer_id"],
        policy_digest=statement["policy_digest"],
        signature_b64=signature_b64,
        attestation_digest="",
    )
    return ActorAttestation(
        **{
            **asdict(unsigned),
            "attestation_digest": sha256_digest(_attestation_payload(unsigned)),
        }
    )


def _ed25519_verify(public_key: bytes, signature: bytes, message: bytes) -> None:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise AttestationError(
            "Ed25519 verification requires the optional 'attestation' dependency"
        ) from exc
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except InvalidSignature as exc:
        raise AttestationError("Ed25519 signature verification failed") from exc
    except ValueError as exc:
        raise AttestationError("invalid Ed25519 public key") from exc


def verify_attestation(
    attestation: ActorAttestation,
    manifest: RunManifest,
    policy: AttestationTrustPolicy,
    *,
    payload: dict[str, Any],
) -> tuple[bool, tuple[str, ...]]:
    reasons: list[str] = []
    accepted, policy_reasons = verify_trust_policy(policy, manifest)
    if not accepted:
        reasons.extend(policy_reasons)
    if attestation.schema_version != ATTESTATION_SCHEMA_VERSION:
        reasons.append("unsupported attestation schema version")
    if attestation.attestation_protocol_version != ATTESTATION_PROTOCOL_VERSION:
        reasons.append("unsupported attestation protocol version")
    if attestation.run_id != manifest.run_id or attestation.manifest_digest != manifest.manifest_digest:
        reasons.append("attestation is not bound to the supplied Run Manifest")
    if attestation.policy_digest != policy.policy_digest:
        reasons.append("attestation policy digest mismatch")
    if attestation.payload_digest != sha256_digest(payload):
        reasons.append("attestation payload digest mismatch")
    if attestation.attestation_digest != sha256_digest(_attestation_payload(attestation)):
        reasons.append("attestation digest mismatch")

    signer: TrustedSigner | None = None
    try:
        signer = _find_signer(policy, attestation.signer_id)
    except AttestationError as exc:
        reasons.append(str(exc))
    if signer is not None:
        if signer.role != attestation.role:
            reasons.append("attestation role does not match trusted signer role")
        if attestation.action not in signer.allowed_events:
            reasons.append("attestation action is not authorized for signer")
        try:
            statement = attestation_statement(
                manifest,
                policy,
                signer_id=attestation.signer_id,
                package_id=attestation.package_id,
                role=attestation.role,
                action=attestation.action,
                payload=payload,
            )
            message = canonical_json(statement).encode("utf-8")
            public_key = _decode_b64(signer.public_key_b64, "public_key_b64", expected_length=32)
            signature = _decode_b64(attestation.signature_b64, "signature_b64", expected_length=64)
            _ed25519_verify(public_key, signature, message)
        except AttestationError as exc:
            reasons.append(str(exc))
    return not reasons, tuple(dict.fromkeys(reasons))


def attested_payload(
    payload: dict[str, Any],
    attestation: ActorAttestation,
) -> dict[str, Any]:
    if "actor_attestation" in payload:
        raise AttestationError("payload already contains actor_attestation")
    return {**payload, "actor_attestation": _normal(attestation)}


def append_attested_event(
    manifest: RunManifest,
    ledger: RunLedger,
    policy: AttestationTrustPolicy,
    attestation: ActorAttestation,
    *,
    payload: dict[str, Any],
) -> RunLedger:
    accepted, reasons = verify_attestation(attestation, manifest, policy, payload=payload)
    if not accepted:
        raise AttestationError("invalid actor attestation: " + "; ".join(reasons))
    return append_event(
        manifest,
        ledger,
        package_id=attestation.package_id,
        role=attestation.role,
        event_type=attestation.action,
        payload=attested_payload(payload, attestation),
    )


def _attestation_from_dict(raw: dict[str, Any]) -> ActorAttestation:
    try:
        return ActorAttestation(**raw)
    except (TypeError, KeyError) as exc:
        raise AttestationError(f"invalid embedded actor attestation: {exc}") from exc


def verify_attested_ledger(
    manifest: RunManifest,
    ledger: RunLedger,
    policy: AttestationTrustPolicy,
) -> tuple[bool, tuple[str, ...]]:
    reasons: list[str] = []
    accepted, core_reasons = verify_ledger(manifest, ledger)
    if not accepted:
        reasons.extend(core_reasons)
    accepted, policy_reasons = verify_trust_policy(policy, manifest)
    if not accepted:
        reasons.extend(policy_reasons)
    if reasons:
        return False, tuple(dict.fromkeys(reasons))

    for event in ledger.events:
        try:
            payload = json.loads(event.payload_json)
        except json.JSONDecodeError:
            reasons.append(f"event {event.seq} payload JSON is invalid")
            continue
        raw = payload.pop("actor_attestation", None)
        if not isinstance(raw, dict):
            reasons.append(f"event {event.seq} has no actor_attestation")
            continue
        try:
            attestation = _attestation_from_dict(raw)
        except AttestationError as exc:
            reasons.append(f"event {event.seq}: {exc}")
            continue
        if attestation.package_id != event.package_id:
            reasons.append(f"event {event.seq} attestation package mismatch")
        if attestation.role != event.role:
            reasons.append(f"event {event.seq} attestation role mismatch")
        if attestation.action != event.event_type:
            reasons.append(f"event {event.seq} attestation action mismatch")
        accepted, attestation_reasons = verify_attestation(
            attestation,
            manifest,
            policy,
            payload=payload,
        )
        if not accepted:
            reasons.extend(
                f"event {event.seq}: {reason}" for reason in attestation_reasons
            )
    return not reasons, tuple(dict.fromkeys(reasons))


def trust_policy_to_dict(policy: AttestationTrustPolicy) -> dict[str, Any]:
    return _normal(policy)


def write_trust_policy(policy: AttestationTrustPolicy, path: str | Path) -> None:
    Path(path).write_text(
        json.dumps(trust_policy_to_dict(policy), indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def trust_policy_from_dict(document: dict[str, Any]) -> AttestationTrustPolicy:
    try:
        signers = tuple(
            TrustedSigner(
                signer_id=item["signer_id"],
                role=item["role"],
                algorithm=item["algorithm"],
                public_key_b64=item["public_key_b64"],
                allowed_events=tuple(item["allowed_events"]),
                signer_digest=item["signer_digest"],
            )
            for item in document["signers"]
        )
        return AttestationTrustPolicy(
            schema_version=int(document["schema_version"]),
            attestation_protocol_version=document["attestation_protocol_version"],
            run_id=document["run_id"],
            manifest_digest=document["manifest_digest"],
            signers=signers,
            policy_digest=document["policy_digest"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise AttestationError(f"invalid trust policy document: {exc}") from exc


def load_trust_policy(path: str | Path) -> AttestationTrustPolicy:
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AttestationError(f"could not load trust policy: {exc}") from exc
    if not isinstance(document, dict):
        raise AttestationError("trust policy root must be an object")
    return trust_policy_from_dict(document)
