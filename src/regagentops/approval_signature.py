from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .approval_models import ApprovalStatement
from .models import canonical_json, digest_artifact


class ApprovalSignatureError(ValueError):
    pass


class ApprovalKeyStatus(str, Enum):
    ACTIVE = "active"
    DISABLED = "disabled"


@dataclass(frozen=True, slots=True)
class ApprovalTrustKey:
    institution_id: str
    principal_id: str
    key_id: str
    public_key_base64url: str
    not_before: str
    not_after: str
    status: ApprovalKeyStatus = ApprovalKeyStatus.ACTIVE
    algorithm: str = "Ed25519"

    def __post_init__(self) -> None:
        for name in ("institution_id", "principal_id", "key_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip() or len(value) > 256:
                raise ValueError(f"{name} must be non-empty bounded text")
        if self.algorithm != "Ed25519":
            raise ValueError("v0.3 approval trust keys require Ed25519")
        raw = _decode(self.public_key_base64url)
        if len(raw) != 32:
            raise ValueError("Ed25519 approval public key must decode to 32 bytes")
        if _parse(self.not_before) >= _parse(self.not_after):
            raise ValueError("approval trust key validity interval must be positive")


@dataclass(frozen=True, slots=True)
class ApprovalTrustBundle:
    institution_id: str
    keys: tuple[ApprovalTrustKey, ...]
    schema_version: str = "regagentops.approval-trust-bundle.v1"

    def __post_init__(self) -> None:
        if not isinstance(self.institution_id, str) or not self.institution_id.strip():
            raise ValueError("institution_id must not be empty")
        if not self.keys:
            raise ValueError("approval trust bundle must contain at least one key")
        if any(key.institution_id != self.institution_id for key in self.keys):
            raise ValueError("approval trust keys must belong to the bundle institution")
        identities = [(key.principal_id, key.key_id) for key in self.keys]
        if len(identities) != len(set(identities)):
            raise ValueError("approval trust bundle contains duplicate principal/key ids")

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


class ApprovalSigner(Protocol):
    institution_id: str
    principal_id: str
    key_id: str
    algorithm: str

    def sign(self, message: bytes) -> bytes: ...


@dataclass(frozen=True, slots=True)
class SignedApprovalStatement:
    statement: ApprovalStatement
    key_id: str
    algorithm: str
    signature_base64url: str
    signing_document_digest: str
    schema_version: str = "regagentops.signed-approval-statement.v1"

    def __post_init__(self) -> None:
        if not isinstance(self.key_id, str) or not self.key_id.strip() or len(self.key_id) > 256:
            raise ValueError("key_id must be non-empty bounded text")
        if self.algorithm != "Ed25519":
            raise ValueError("v0.3 approval signatures require Ed25519")
        if len(_decode(self.signature_base64url)) != 64:
            raise ValueError("Ed25519 approval signature must decode to 64 bytes")
        if len(self.signing_document_digest) != 64:
            raise ValueError("signing_document_digest must be SHA-256 hex")

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    if not isinstance(value, str) or "=" in value:
        raise ValueError("base64url values must be unpadded text")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:  # pragma: no cover
        raise ValueError("invalid base64url value") from exc


def _parse(value: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("approval signature time must be RFC3339 UTC")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError("approval signature time is invalid") from exc


def approval_signing_document(statement: ApprovalStatement, *, key_id: str, algorithm: str) -> dict[str, str]:
    return {
        "purpose": "regagentops.human-approval.v1",
        "institution_id": statement.institution_id,
        "approval_id": statement.approval_id,
        "approver_id": statement.approver_id,
        "requirement_digest": statement.requirement_digest,
        "request_digest": statement.request_digest,
        "authority_grant_digest": statement.authority_grant_digest,
        "statement_digest": statement.artifact_digest,
        "key_id": key_id,
        "algorithm": algorithm,
    }


def sign_approval_statement(statement: ApprovalStatement, *, signer: ApprovalSigner) -> SignedApprovalStatement:
    if signer.institution_id != statement.institution_id:
        raise ApprovalSignatureError("approval signer institution mismatch")
    if signer.principal_id != statement.approver_id:
        raise ApprovalSignatureError("approval signer principal mismatch")
    if signer.algorithm != "Ed25519":
        raise ApprovalSignatureError("v0.3 approval signer must use Ed25519")
    document = approval_signing_document(statement, key_id=signer.key_id, algorithm=signer.algorithm)
    signature = signer.sign(canonical_json(document).encode("utf-8"))
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise ApprovalSignatureError("approval signer must return a 64-byte Ed25519 signature")
    return SignedApprovalStatement(
        statement=statement,
        key_id=signer.key_id,
        algorithm=signer.algorithm,
        signature_base64url=_encode(signature),
        signing_document_digest=digest_artifact(document),
    )


def verify_signed_approval(
    signed: SignedApprovalStatement,
    *,
    trust_bundle: ApprovalTrustBundle,
    now: str,
) -> ApprovalStatement:
    statement = signed.statement
    if trust_bundle.institution_id != statement.institution_id:
        raise ApprovalSignatureError("approval trust bundle institution mismatch")
    matches = [
        key for key in trust_bundle.keys
        if key.principal_id == statement.approver_id and key.key_id == signed.key_id
    ]
    if len(matches) != 1:
        raise ApprovalSignatureError("approval key must resolve uniquely for the approver")
    key = matches[0]
    if key.status is not ApprovalKeyStatus.ACTIVE:
        raise ApprovalSignatureError("approval trust key is not active")
    if key.algorithm != signed.algorithm or signed.algorithm != "Ed25519":
        raise ApprovalSignatureError("approval signature algorithm mismatch")
    now_dt = _parse(now)
    issued = _parse(statement.issued_at)
    expires = _parse(statement.expires_at)
    key_start = _parse(key.not_before)
    key_end = _parse(key.not_after)
    if not (issued <= now_dt < expires):
        raise ApprovalSignatureError("approval statement is expired or not yet valid")
    if not (key_start <= issued < key_end and key_start <= now_dt < key_end):
        raise ApprovalSignatureError("approval trust key is outside its validity interval")
    document = approval_signing_document(statement, key_id=signed.key_id, algorithm=signed.algorithm)
    if signed.signing_document_digest != digest_artifact(document):
        raise ApprovalSignatureError("approval signing document digest mismatch")
    try:
        public_key = Ed25519PublicKey.from_public_bytes(_decode(key.public_key_base64url))
        public_key.verify(_decode(signed.signature_base64url), canonical_json(document).encode("utf-8"))
    except (ValueError, InvalidSignature) as exc:
        raise ApprovalSignatureError("approval signature is invalid") from exc
    return statement
