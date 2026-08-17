from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import base64
import re
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .identity_models import AuthenticatedAgentIdentity, TrustKeyStatus, WorkloadIdentityTrustBundle
from .models import canonical_json, digest_artifact

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")


class AuthenticatedIdentitySignatureError(ValueError):
    pass


class AuthenticatedIdentitySigner(Protocol):
    institution_id: str
    key_id: str
    algorithm: str

    def sign(self, message: bytes) -> bytes: ...


def _encode_b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_b64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _parse(value: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise AuthenticatedIdentitySignatureError("identity verification time must be RFC3339 UTC")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise AuthenticatedIdentitySignatureError("identity verification time is invalid") from exc


@dataclass(frozen=True, slots=True)
class SignedAuthenticatedAgentIdentity:
    identity: AuthenticatedAgentIdentity
    key_id: str
    algorithm: str
    signature_base64url: str
    signing_document_digest: str
    schema_version: str = "regagentops.signed-authenticated-agent-identity.v1"

    def __post_init__(self) -> None:
        if not isinstance(self.key_id, str) or not self.key_id or len(self.key_id) > 256:
            raise ValueError("key_id must be non-empty bounded text")
        if self.algorithm != "Ed25519":
            raise ValueError("v0.2 authenticated identity signatures require Ed25519")
        if not isinstance(self.signature_base64url, str) or "=" in self.signature_base64url:
            raise ValueError("signature_base64url must be unpadded base64url")
        try:
            raw = _decode_b64url(self.signature_base64url)
        except Exception as exc:  # pragma: no cover
            raise ValueError("signature_base64url is invalid") from exc
        if len(raw) != 64:
            raise ValueError("Ed25519 signature must decode to 64 bytes")
        if not _HEX_64.fullmatch(self.signing_document_digest):
            raise ValueError("signing_document_digest must be a lowercase SHA-256 digest")

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


def authenticated_identity_signing_document(
    identity: AuthenticatedAgentIdentity,
    *,
    key_id: str,
    algorithm: str,
) -> dict[str, str]:
    return {
        "purpose": "regagentops.authenticated-agent-identity.v1",
        "institution_id": identity.institution_id,
        "agent_id": identity.agent_id,
        "human_owner_id": identity.human_owner_id,
        "provider_id": identity.provider_id,
        "workload_id": identity.workload_id,
        "identity_digest": identity.artifact_digest,
        "key_id": key_id,
        "algorithm": algorithm,
    }


def sign_authenticated_agent_identity(
    identity: AuthenticatedAgentIdentity,
    *,
    signer: AuthenticatedIdentitySigner,
) -> SignedAuthenticatedAgentIdentity:
    if signer.institution_id != identity.institution_id:
        raise AuthenticatedIdentitySignatureError("context signer institution mismatch")
    if signer.algorithm != "Ed25519":
        raise AuthenticatedIdentitySignatureError("v0.2 context signer must use Ed25519")
    document = authenticated_identity_signing_document(identity, key_id=signer.key_id, algorithm=signer.algorithm)
    target = canonical_json(document).encode("utf-8")
    signature = signer.sign(target)
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise AuthenticatedIdentitySignatureError("Ed25519 signer must return a 64-byte signature")
    return SignedAuthenticatedAgentIdentity(
        identity=identity,
        key_id=signer.key_id,
        algorithm=signer.algorithm,
        signature_base64url=_encode_b64url(signature),
        signing_document_digest=digest_artifact(document),
    )


def verify_signed_authenticated_agent_identity(
    signed: SignedAuthenticatedAgentIdentity,
    *,
    trust_bundle: WorkloadIdentityTrustBundle,
    now: str,
) -> AuthenticatedAgentIdentity:
    identity = signed.identity
    if trust_bundle.institution_id != identity.institution_id:
        raise AuthenticatedIdentitySignatureError("context trust bundle institution mismatch")
    matches = [key for key in trust_bundle.keys if key.key_id == signed.key_id]
    if len(matches) != 1:
        raise AuthenticatedIdentitySignatureError("context key id must resolve to exactly one trust key")
    key = matches[0]
    if key.status is not TrustKeyStatus.ACTIVE:
        raise AuthenticatedIdentitySignatureError("context trust key is not active")
    if key.algorithm != signed.algorithm or signed.algorithm != "Ed25519":
        raise AuthenticatedIdentitySignatureError("context signature algorithm mismatch")

    now_dt = _parse(now)
    established = _parse(identity.established_at)
    valid_until = _parse(identity.valid_until)
    key_start = _parse(key.not_before)
    key_end = _parse(key.not_after)
    if now_dt < established or now_dt >= valid_until:
        raise AuthenticatedIdentitySignatureError("authenticated context is expired or not yet valid")
    if not (key_start <= established < key_end and key_start <= now_dt < key_end):
        raise AuthenticatedIdentitySignatureError("context trust key is outside its validity interval")

    document = authenticated_identity_signing_document(identity, key_id=signed.key_id, algorithm=signed.algorithm)
    if signed.signing_document_digest != digest_artifact(document):
        raise AuthenticatedIdentitySignatureError("context signing document digest mismatch")
    try:
        public_key = Ed25519PublicKey.from_public_bytes(_decode_b64url(key.public_key_base64url))
        public_key.verify(
            _decode_b64url(signed.signature_base64url),
            canonical_json(document).encode("utf-8"),
        )
    except (ValueError, InvalidSignature) as exc:
        raise AuthenticatedIdentitySignatureError("authenticated context signature is invalid") from exc
    return identity
