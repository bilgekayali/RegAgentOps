from __future__ import annotations

from datetime import datetime
import base64
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .identity_models import (
    SignedWorkloadIdentity,
    TrustKeyStatus,
    WorkloadIdentityStatement,
    WorkloadIdentityTrustBundle,
)
from .models import canonical_json, digest_artifact


class WorkloadIdentityError(ValueError):
    pass


class WorkloadIdentitySigner(Protocol):
    institution_id: str
    key_id: str
    algorithm: str

    def sign(self, message: bytes) -> bytes: ...


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _decode_b64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _encode_b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def workload_signing_document(statement: WorkloadIdentityStatement, *, key_id: str, algorithm: str) -> dict[str, str]:
    return {
        "purpose": "regagentops.workload-identity.v1",
        "institution_id": statement.institution_id,
        "agent_id": statement.agent_id,
        "human_owner_id": statement.human_owner_id,
        "workload_id": statement.workload_id,
        "statement_digest": statement.artifact_digest,
        "key_id": key_id,
        "algorithm": algorithm,
    }


def sign_workload_identity(
    statement: WorkloadIdentityStatement,
    *,
    signer: WorkloadIdentitySigner,
) -> SignedWorkloadIdentity:
    if signer.institution_id != statement.institution_id:
        raise WorkloadIdentityError("workload signer institution does not match statement institution")
    if signer.algorithm != "Ed25519":
        raise WorkloadIdentityError("v0.2 workload signer must use Ed25519")
    if not isinstance(signer.key_id, str) or not signer.key_id or len(signer.key_id) > 256:
        raise WorkloadIdentityError("workload signer key id must be bounded text")
    document = workload_signing_document(statement, key_id=signer.key_id, algorithm=signer.algorithm)
    target = canonical_json(document).encode("utf-8")
    signature = signer.sign(target)
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise WorkloadIdentityError("Ed25519 signer must return a 64-byte signature")
    return SignedWorkloadIdentity(
        statement=statement,
        key_id=signer.key_id,
        algorithm=signer.algorithm,
        signature_base64url=_encode_b64url(signature),
        signing_document_digest=digest_artifact(document),
    )


def verify_workload_identity(
    signed: SignedWorkloadIdentity,
    *,
    trust_bundle: WorkloadIdentityTrustBundle,
    now: str,
) -> WorkloadIdentityStatement:
    statement = signed.statement
    if trust_bundle.institution_id != statement.institution_id:
        raise WorkloadIdentityError("workload trust bundle institution does not match statement institution")
    matches = [key for key in trust_bundle.keys if key.key_id == signed.key_id]
    if len(matches) != 1:
        raise WorkloadIdentityError("workload key id must resolve to exactly one trust key")
    key = matches[0]
    if key.status is not TrustKeyStatus.ACTIVE:
        raise WorkloadIdentityError("workload trust key is not active")
    if key.algorithm != signed.algorithm or signed.algorithm != "Ed25519":
        raise WorkloadIdentityError("workload signature algorithm does not match trust key")

    now_dt = _parse_timestamp(now)
    issued_dt = _parse_timestamp(statement.issued_at)
    expires_dt = _parse_timestamp(statement.expires_at)
    key_start = _parse_timestamp(key.not_before)
    key_end = _parse_timestamp(key.not_after)
    if issued_dt > now_dt:
        raise WorkloadIdentityError("workload identity was issued in the future")
    if expires_dt <= now_dt:
        raise WorkloadIdentityError("workload identity is expired")
    if not (key_start <= issued_dt < key_end and key_start <= now_dt < key_end):
        raise WorkloadIdentityError("workload trust key is outside its validity interval")

    document = workload_signing_document(statement, key_id=signed.key_id, algorithm=signed.algorithm)
    if signed.signing_document_digest != digest_artifact(document):
        raise WorkloadIdentityError("workload signing document digest mismatch")
    target = canonical_json(document).encode("utf-8")
    try:
        public_key = Ed25519PublicKey.from_public_bytes(_decode_b64url(key.public_key_base64url))
        public_key.verify(_decode_b64url(signed.signature_base64url), target)
    except (ValueError, InvalidSignature) as exc:
        raise WorkloadIdentityError("workload identity signature is invalid") from exc
    return statement
