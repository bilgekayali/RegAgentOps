from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import base64
import re

from .models import digest_artifact

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$")
_ALLOWED_OIDC_ALGORITHMS = frozenset({"RS256", "PS256", "ES256", "EdDSA"})


def _text(name: str, value: str, *, limit: int = 256) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(f"{name} must be non-empty text no longer than {limit} characters")


def _identifier(name: str, value: str) -> None:
    _text(name, value)
    if not _ID.fullmatch(value):
        raise ValueError(f"{name} contains unsupported characters")


def _digest(name: str, value: str) -> None:
    if not _HEX_64.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase SHA-256 hex digest")


def _timestamp(name: str, value: str) -> datetime:
    _text(name, value, limit=64)
    if not value.endswith("Z"):
        raise ValueError(f"{name} must be an RFC3339 UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{name} must be a valid RFC3339 UTC timestamp") from exc
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError(f"{name} must use UTC")
    return parsed


def _b64url(name: str, value: str, *, expected_bytes: int | None = None) -> bytes:
    _text(name, value, limit=4096)
    if "=" in value:
        raise ValueError(f"{name} must be unpadded base64url")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:  # pragma: no cover - decoder implementations vary
        raise ValueError(f"{name} must be valid base64url") from exc
    if expected_bytes is not None and len(raw) != expected_bytes:
        raise ValueError(f"{name} must decode to {expected_bytes} bytes")
    return raw


def to_rfc3339_utc(epoch_seconds: int) -> str:
    if not isinstance(epoch_seconds, int) or isinstance(epoch_seconds, bool) or epoch_seconds < 0:
        raise ValueError("epoch_seconds must be a non-negative integer")
    return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc).isoformat().replace("+00:00", "Z")


class TrustKeyStatus(str, Enum):
    ACTIVE = "active"
    RETIRED = "retired"
    DISABLED = "disabled"


@dataclass(frozen=True, slots=True)
class OidcVerifierConfig:
    institution_id: str
    provider_id: str
    issuer: str
    client_id: str
    allowed_algorithms: tuple[str, ...]
    max_token_age_seconds: int = 300
    required_acr_values: tuple[str, ...] = ()
    schema_version: str = "regagentops.oidc-verifier-config.v1"

    def __post_init__(self) -> None:
        _identifier("institution_id", self.institution_id)
        _identifier("provider_id", self.provider_id)
        _text("issuer", self.issuer, limit=512)
        _text("client_id", self.client_id)
        if not self.issuer.startswith("https://") or "?" in self.issuer or "#" in self.issuer:
            raise ValueError("issuer must be an HTTPS URL without query or fragment")
        if not self.allowed_algorithms or len(set(self.allowed_algorithms)) != len(self.allowed_algorithms):
            raise ValueError("allowed_algorithms must be non-empty and unique")
        unsupported = set(self.allowed_algorithms) - _ALLOWED_OIDC_ALGORITHMS
        if unsupported:
            raise ValueError(f"unsupported OIDC signing algorithm(s): {sorted(unsupported)}")
        if not isinstance(self.max_token_age_seconds, int) or isinstance(self.max_token_age_seconds, bool):
            raise ValueError("max_token_age_seconds must be an integer")
        if not 1 <= self.max_token_age_seconds <= 3600:
            raise ValueError("max_token_age_seconds must be between 1 and 3600")
        if len(set(self.required_acr_values)) != len(self.required_acr_values):
            raise ValueError("required_acr_values must be unique")
        for value in self.required_acr_values:
            _text("required_acr_value", value)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class HumanIdentityAssertion:
    institution_id: str
    provider_id: str
    human_owner_id: str
    issuer: str
    subject: str
    audiences: tuple[str, ...]
    client_id: str
    key_id: str
    algorithm: str
    token_digest: str
    claims_digest: str
    nonce_digest: str
    jwks_digest: str
    provider_config_digest: str
    issued_at: str
    expires_at: str
    auth_time: str | None = None
    acr: str | None = None
    schema_version: str = "regagentops.human-identity-assertion.v1"

    def __post_init__(self) -> None:
        for name in ("institution_id", "provider_id", "human_owner_id", "subject", "key_id"):
            _identifier(name, getattr(self, name))
        _text("issuer", self.issuer, limit=512)
        _text("client_id", self.client_id)
        if self.algorithm not in _ALLOWED_OIDC_ALGORITHMS:
            raise ValueError("algorithm is not an allowed asymmetric OIDC algorithm")
        if not self.audiences or len(set(self.audiences)) != len(self.audiences):
            raise ValueError("audiences must be non-empty and unique")
        for audience in self.audiences:
            _text("audience", audience)
        for name in ("token_digest", "claims_digest", "nonce_digest", "jwks_digest", "provider_config_digest"):
            _digest(name, getattr(self, name))
        issued = _timestamp("issued_at", self.issued_at)
        expires = _timestamp("expires_at", self.expires_at)
        if expires <= issued:
            raise ValueError("expires_at must be after issued_at")
        if self.auth_time is not None:
            _timestamp("auth_time", self.auth_time)
        if self.acr is not None:
            _text("acr", self.acr)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class WorkloadIdentityStatement:
    institution_id: str
    agent_id: str
    human_owner_id: str
    model_provider: str
    model_id: str
    workload_id: str
    challenge_digest: str
    issued_at: str
    expires_at: str
    schema_version: str = "regagentops.workload-identity-statement.v1"

    def __post_init__(self) -> None:
        for name in ("institution_id", "agent_id", "human_owner_id", "model_provider", "model_id", "workload_id"):
            _identifier(name, getattr(self, name))
        _digest("challenge_digest", self.challenge_digest)
        issued = _timestamp("issued_at", self.issued_at)
        expires = _timestamp("expires_at", self.expires_at)
        if expires <= issued:
            raise ValueError("expires_at must be after issued_at")
        if (expires - issued).total_seconds() > 900:
            raise ValueError("workload identity lifetime must not exceed 900 seconds")

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class SignedWorkloadIdentity:
    statement: WorkloadIdentityStatement
    key_id: str
    algorithm: str
    signature_base64url: str
    signing_document_digest: str
    schema_version: str = "regagentops.signed-workload-identity.v1"

    def __post_init__(self) -> None:
        _identifier("key_id", self.key_id)
        if self.algorithm != "Ed25519":
            raise ValueError("only Ed25519 workload signatures are supported in v0.2")
        _b64url("signature_base64url", self.signature_base64url, expected_bytes=64)
        _digest("signing_document_digest", self.signing_document_digest)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class WorkloadIdentityTrustKey:
    institution_id: str
    key_id: str
    public_key_base64url: str
    not_before: str
    not_after: str
    status: TrustKeyStatus = TrustKeyStatus.ACTIVE
    algorithm: str = "Ed25519"

    def __post_init__(self) -> None:
        _identifier("institution_id", self.institution_id)
        _identifier("key_id", self.key_id)
        if self.algorithm != "Ed25519":
            raise ValueError("only Ed25519 workload trust keys are supported in v0.2")
        _b64url("public_key_base64url", self.public_key_base64url, expected_bytes=32)
        start = _timestamp("not_before", self.not_before)
        end = _timestamp("not_after", self.not_after)
        if end <= start:
            raise ValueError("not_after must be after not_before")


@dataclass(frozen=True, slots=True)
class WorkloadIdentityTrustBundle:
    institution_id: str
    keys: tuple[WorkloadIdentityTrustKey, ...]
    schema_version: str = "regagentops.workload-identity-trust-bundle.v1"

    def __post_init__(self) -> None:
        _identifier("institution_id", self.institution_id)
        if not self.keys:
            raise ValueError("workload trust bundle must contain at least one key")
        if any(key.institution_id != self.institution_id for key in self.keys):
            raise ValueError("all workload trust keys must belong to the bundle institution")
        key_ids = [key.key_id for key in self.keys]
        if len(set(key_ids)) != len(key_ids):
            raise ValueError("workload trust bundle contains duplicate key ids")
        public_keys = [key.public_key_base64url for key in self.keys]
        if len(set(public_keys)) != len(public_keys):
            raise ValueError("workload trust bundle contains duplicate public keys")
        if not any(key.status is TrustKeyStatus.ACTIVE for key in self.keys):
            raise ValueError("workload trust bundle requires at least one active key")

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class AuthenticatedAgentIdentity:
    institution_id: str
    agent_id: str
    human_owner_id: str
    provider_id: str
    workload_id: str
    agent_descriptor_digest: str
    human_identity_digest: str
    workload_identity_digest: str
    established_at: str
    valid_until: str
    schema_version: str = "regagentops.authenticated-agent-identity.v1"

    def __post_init__(self) -> None:
        for name in ("institution_id", "agent_id", "human_owner_id", "provider_id", "workload_id"):
            _identifier(name, getattr(self, name))
        for name in ("agent_descriptor_digest", "human_identity_digest", "workload_identity_digest"):
            _digest(name, getattr(self, name))
        established = _timestamp("established_at", self.established_at)
        valid_until = _timestamp("valid_until", self.valid_until)
        if valid_until <= established:
            raise ValueError("valid_until must be after established_at")

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)
