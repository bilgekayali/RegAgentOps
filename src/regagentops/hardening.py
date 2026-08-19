from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import hashlib
import re
import secrets
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .models import Environment, canonical_json, digest_artifact, _require_text, _require_utc_timestamp

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_SQL_IDENTIFIER = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
_SESSION_SETTING = re.compile(r"^regagentops\.[a-z_][a-z0-9_]{0,62}$")


def _require_digest(name: str, value: str | None, *, optional: bool = False) -> None:
    if value is None and optional:
        return
    if not isinstance(value, str) or not _HEX_64.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase SHA-256 hex digest")


def _require_positive_int(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")


def _parse_time(name: str, value: str) -> datetime:
    _require_utc_timestamp(name, value)
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise ValueError("base64url values must be non-empty unpadded text")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:  # pragma: no cover
        raise ValueError("invalid base64url value") from exc


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _require_sorted_digests(name: str, values: tuple[str, ...], *, allow_empty: bool = False) -> None:
    if not allow_empty and not values:
        raise ValueError(f"{name} must not be empty")
    for value in values:
        _require_digest(name, value)
    if len(values) != len(set(values)) or tuple(sorted(values)) != values:
        raise ValueError(f"{name} must be unique and sorted")


def _require_identifier(name: str, value: str) -> None:
    if not isinstance(value, str) or not _SQL_IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name} must be a safe lowercase PostgreSQL identifier")


def _require_setting(name: str, value: str) -> None:
    if not isinstance(value, str) or not _SESSION_SETTING.fullmatch(value):
        raise ValueError(f"{name} must be a regagentops.* PostgreSQL session setting")


class CryptoKeyPurpose(str, Enum):
    CONFIG_SIGNING = "config_signing"
    EVIDENCE_ENCRYPTION = "evidence_encryption"


class CryptoKeyCustody(str, Enum):
    KMS = "kms"
    HSM = "hsm"


class CryptoKeyStatus(str, Enum):
    ACTIVE = "active"
    RETIRED = "retired"
    DISABLED = "disabled"


class CryptoAlgorithm(str, Enum):
    ED25519 = "Ed25519"
    AES_256_GCM = "AES-256-GCM"


@dataclass(frozen=True, slots=True)
class PostgresRlsPolicy:
    institution_id: str
    policy_id: str
    policy_version: int
    table_name: str
    policy_name: str
    institution_column: str
    tenant_column: str
    institution_setting: str
    tenant_setting: str
    force_row_level_security: bool
    registered_at: str
    schema_version: str = "regagentops.postgres-rls-policy.v1"

    def __post_init__(self) -> None:
        for name in ("institution_id", "policy_id", "schema_version"):
            _require_text(name, getattr(self, name))
        _require_positive_int("policy_version", self.policy_version)
        for name in ("table_name", "policy_name", "institution_column", "tenant_column"):
            _require_identifier(name, getattr(self, name))
        _require_setting("institution_setting", self.institution_setting)
        _require_setting("tenant_setting", self.tenant_setting)
        if self.institution_setting == self.tenant_setting:
            raise ValueError("institution and tenant session settings must be distinct")
        if self.institution_column == self.tenant_column:
            raise ValueError("institution and tenant RLS columns must be distinct")
        if self.force_row_level_security is not True:
            raise ValueError("v0.8 PostgreSQL RLS reference policies must force row level security")
        _require_utc_timestamp("registered_at", self.registered_at)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


def render_postgres_rls_sql(policy: PostgresRlsPolicy) -> str:
    if not isinstance(policy, PostgresRlsPolicy):
        raise ValueError("RLS renderer requires a PostgresRlsPolicy")
    predicate = (
        f"{policy.institution_column} = current_setting('{policy.institution_setting}', true) "
        f"AND {policy.tenant_column} = current_setting('{policy.tenant_setting}', true)"
    )
    return "\n".join(
        (
            f"ALTER TABLE {policy.table_name} ENABLE ROW LEVEL SECURITY;",
            f"ALTER TABLE {policy.table_name} FORCE ROW LEVEL SECURITY;",
            f"CREATE POLICY {policy.policy_name} ON {policy.table_name}",
            f"USING ({predicate})",
            f"WITH CHECK ({predicate});",
        )
    )


@dataclass(frozen=True, slots=True)
class TenantIsolationProfile:
    institution_id: str
    tenant_id: str
    profile_version: int
    environment: Environment
    database_role: str
    rls_policy_digests: tuple[str, ...]
    registered_at: str
    schema_version: str = "regagentops.tenant-isolation-profile.v1"

    def __post_init__(self) -> None:
        for name in ("institution_id", "tenant_id", "schema_version"):
            _require_text(name, getattr(self, name))
        _require_positive_int("profile_version", self.profile_version)
        if not isinstance(self.environment, Environment):
            raise ValueError("environment must be governed")
        _require_identifier("database_role", self.database_role)
        _require_sorted_digests("rls_policy_digests", self.rls_policy_digests)
        _require_utc_timestamp("registered_at", self.registered_at)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


class TenantIsolationRegistry:
    """Append-only tenant isolation metadata. It renders reference RLS DDL but never connects to PostgreSQL."""

    def __init__(self) -> None:
        self._policies: dict[tuple[str, str, int], PostgresRlsPolicy] = {}
        self._profiles: dict[tuple[str, str, int], TenantIsolationProfile] = {}

    def register_policy(self, policy: PostgresRlsPolicy) -> str:
        key = (policy.institution_id, policy.policy_id, policy.policy_version)
        existing = self._policies.get(key)
        if existing is not None:
            if existing.artifact_digest != policy.artifact_digest:
                raise ValueError("RLS policy identity/version already exists with different content")
            return existing.artifact_digest
        history = self.policy_history(policy.institution_id, policy.policy_id)
        expected = 1 if not history else history[-1].policy_version + 1
        if policy.policy_version != expected:
            raise ValueError(f"RLS policy_version must be contiguous; expected version {expected}")
        if history and _parse_time("registered_at", policy.registered_at) < _parse_time(
            "previous registered_at", history[-1].registered_at
        ):
            raise ValueError("new RLS policy cannot predate the previous version")
        self._policies[key] = policy
        return policy.artifact_digest

    def policy_history(self, institution_id: str, policy_id: str) -> tuple[PostgresRlsPolicy, ...]:
        return tuple(
            sorted(
                (
                    policy
                    for (scope, candidate_id, _), policy in self._policies.items()
                    if scope == institution_id and candidate_id == policy_id
                ),
                key=lambda policy: policy.policy_version,
            )
        )

    def _policy_by_digest(self, institution_id: str, digest: str) -> PostgresRlsPolicy:
        for (scope, _, _), policy in self._policies.items():
            if scope == institution_id and policy.artifact_digest == digest:
                return policy
        raise ValueError("unknown PostgreSQL RLS policy digest")

    def register_profile(self, profile: TenantIsolationProfile) -> str:
        for digest in profile.rls_policy_digests:
            self._policy_by_digest(profile.institution_id, digest)
        key = (profile.institution_id, profile.tenant_id, profile.profile_version)
        existing = self._profiles.get(key)
        if existing is not None:
            if existing.artifact_digest != profile.artifact_digest:
                raise ValueError("tenant isolation profile identity/version already exists with different content")
            return existing.artifact_digest
        history = self.profile_history(profile.institution_id, profile.tenant_id)
        expected = 1 if not history else history[-1].profile_version + 1
        if profile.profile_version != expected:
            raise ValueError(f"tenant isolation profile_version must be contiguous; expected version {expected}")
        if history and _parse_time("registered_at", profile.registered_at) < _parse_time(
            "previous registered_at", history[-1].registered_at
        ):
            raise ValueError("new tenant isolation profile cannot predate the previous version")
        self._profiles[key] = profile
        return profile.artifact_digest

    def profile_history(self, institution_id: str, tenant_id: str) -> tuple[TenantIsolationProfile, ...]:
        return tuple(
            sorted(
                (
                    profile
                    for (scope, tenant, _), profile in self._profiles.items()
                    if scope == institution_id and tenant == tenant_id
                ),
                key=lambda profile: profile.profile_version,
            )
        )

    def current_profile(self, institution_id: str, tenant_id: str) -> TenantIsolationProfile:
        history = self.profile_history(institution_id, tenant_id)
        if not history:
            raise ValueError("tenant isolation profile is not registered")
        return history[-1]

    def snapshot_digest(self, institution_id: str, tenant_id: str) -> str:
        profile = self.current_profile(institution_id, tenant_id)
        return digest_artifact(
            {
                "institution_id": institution_id,
                "tenant_id": tenant_id,
                "profile_digest": profile.artifact_digest,
                "rls_policy_digests": profile.rls_policy_digests,
            }
        )


@dataclass(frozen=True, slots=True)
class InstitutionCryptoKeyReference:
    institution_id: str
    tenant_id: str
    purpose: CryptoKeyPurpose
    key_version: int
    key_id: str
    custody: CryptoKeyCustody
    algorithm: CryptoAlgorithm
    public_key_base64url: str | None
    status: CryptoKeyStatus
    not_before: str
    not_after: str
    registered_at: str
    schema_version: str = "regagentops.institution-crypto-key-reference.v1"

    def __post_init__(self) -> None:
        for name in ("institution_id", "tenant_id", "key_id", "schema_version"):
            _require_text(name, getattr(self, name))
        if not isinstance(self.purpose, CryptoKeyPurpose):
            raise ValueError("key purpose must be governed")
        _require_positive_int("key_version", self.key_version)
        if not isinstance(self.custody, CryptoKeyCustody):
            raise ValueError("key custody must be KMS or HSM")
        if not isinstance(self.algorithm, CryptoAlgorithm):
            raise ValueError("key algorithm must be governed")
        if not isinstance(self.status, CryptoKeyStatus):
            raise ValueError("initial key status must be governed")
        if self.purpose is CryptoKeyPurpose.CONFIG_SIGNING:
            if self.algorithm is not CryptoAlgorithm.ED25519:
                raise ValueError("configuration signing keys must use Ed25519")
            if self.public_key_base64url is None or len(_decode(self.public_key_base64url)) != 32:
                raise ValueError("Ed25519 configuration signing keys require a 32-byte public key")
        elif self.purpose is CryptoKeyPurpose.EVIDENCE_ENCRYPTION:
            if self.algorithm is not CryptoAlgorithm.AES_256_GCM:
                raise ValueError("evidence encryption keys must use AES-256-GCM")
            if self.public_key_base64url is not None:
                raise ValueError("symmetric KMS/HSM encryption key material must not be embedded")
        start = _parse_time("not_before", self.not_before)
        end = _parse_time("not_after", self.not_after)
        registered = _parse_time("registered_at", self.registered_at)
        if end <= start:
            raise ValueError("key not_after must be after not_before")
        if registered > end:
            raise ValueError("key registration cannot occur after key expiry")

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class CryptoKeyLifecycleState:
    institution_id: str
    tenant_id: str
    purpose: CryptoKeyPurpose
    key_reference_digest: str
    state_version: int
    status: CryptoKeyStatus
    effective_at: str
    schema_version: str = "regagentops.crypto-key-lifecycle-state.v1"

    def __post_init__(self) -> None:
        for name in ("institution_id", "tenant_id", "schema_version"):
            _require_text(name, getattr(self, name))
        if not isinstance(self.purpose, CryptoKeyPurpose):
            raise ValueError("lifecycle key purpose must be governed")
        _require_digest("key_reference_digest", self.key_reference_digest)
        _require_positive_int("state_version", self.state_version)
        if not isinstance(self.status, CryptoKeyStatus):
            raise ValueError("lifecycle status must be governed")
        _require_utc_timestamp("effective_at", self.effective_at)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


_ALLOWED_KEY_TRANSITIONS = {
    CryptoKeyStatus.ACTIVE: {CryptoKeyStatus.RETIRED, CryptoKeyStatus.DISABLED},
    CryptoKeyStatus.RETIRED: {CryptoKeyStatus.DISABLED},
    CryptoKeyStatus.DISABLED: set(),
}


class InstitutionCryptoKeyRegistry:
    """Append-only KMS/HSM key references and lifecycle states; no private or symmetric key bytes are stored."""

    def __init__(self) -> None:
        self._keys: dict[tuple[str, str, CryptoKeyPurpose, int], InstitutionCryptoKeyReference] = {}
        self._states: dict[tuple[str, str, str, int], CryptoKeyLifecycleState] = {}

    def register(self, key: InstitutionCryptoKeyReference) -> str:
        identity = (key.institution_id, key.tenant_id, key.purpose, key.key_version)
        existing = self._keys.get(identity)
        if existing is not None:
            if existing.artifact_digest != key.artifact_digest:
                raise ValueError("crypto key purpose/version already exists with different content")
            return existing.artifact_digest
        history = self.history(key.institution_id, key.tenant_id, key.purpose)
        expected = 1 if not history else history[-1].key_version + 1
        if key.key_version != expected:
            raise ValueError(f"crypto key_version must be contiguous; expected version {expected}")
        if history and _parse_time("registered_at", key.registered_at) < _parse_time(
            "previous registered_at", history[-1].registered_at
        ):
            raise ValueError("new crypto key reference cannot predate the previous version")
        if any(previous.key_id == key.key_id for previous in history):
            raise ValueError("rotated key versions must use distinct key_id values")
        self._keys[identity] = key
        initial = CryptoKeyLifecycleState(
            institution_id=key.institution_id,
            tenant_id=key.tenant_id,
            purpose=key.purpose,
            key_reference_digest=key.artifact_digest,
            state_version=1,
            status=key.status,
            effective_at=key.registered_at,
        )
        self._states[(key.institution_id, key.tenant_id, key.artifact_digest, 1)] = initial
        return key.artifact_digest

    def history(
        self,
        institution_id: str,
        tenant_id: str,
        purpose: CryptoKeyPurpose,
    ) -> tuple[InstitutionCryptoKeyReference, ...]:
        return tuple(
            sorted(
                (
                    key
                    for (scope, tenant, candidate_purpose, _), key in self._keys.items()
                    if scope == institution_id and tenant == tenant_id and candidate_purpose is purpose
                ),
                key=lambda key: key.key_version,
            )
        )

    def by_digest(self, institution_id: str, tenant_id: str, digest: str) -> InstitutionCryptoKeyReference:
        for (scope, tenant, _, _), key in self._keys.items():
            if scope == institution_id and tenant == tenant_id and key.artifact_digest == digest:
                return key
        raise ValueError("unknown tenant crypto key reference digest")

    def lifecycle_history(self, key: InstitutionCryptoKeyReference) -> tuple[CryptoKeyLifecycleState, ...]:
        return tuple(
            sorted(
                (
                    state
                    for (scope, tenant, digest, _), state in self._states.items()
                    if scope == key.institution_id and tenant == key.tenant_id and digest == key.artifact_digest
                ),
                key=lambda state: state.state_version,
            )
        )

    def register_state(self, state: CryptoKeyLifecycleState) -> str:
        key = self.by_digest(state.institution_id, state.tenant_id, state.key_reference_digest)
        if state.purpose is not key.purpose:
            raise ValueError("key lifecycle purpose does not match exact key reference")
        history = self.lifecycle_history(key)
        expected = history[-1].state_version + 1
        if state.state_version != expected:
            raise ValueError(f"key lifecycle state_version must be contiguous; expected {expected}")
        if _parse_time("effective_at", state.effective_at) < _parse_time("previous effective_at", history[-1].effective_at):
            raise ValueError("key lifecycle cannot move backward in time")
        if state.status not in _ALLOWED_KEY_TRANSITIONS[history[-1].status]:
            raise ValueError("key lifecycle transition is not permitted")
        identity = (state.institution_id, state.tenant_id, state.key_reference_digest, state.state_version)
        existing = self._states.get(identity)
        if existing is not None:
            if existing.artifact_digest != state.artifact_digest:
                raise ValueError("key lifecycle version already exists with different content")
            return existing.artifact_digest
        self._states[identity] = state
        return state.artifact_digest

    def status_at(self, key: InstitutionCryptoKeyReference, *, at: str) -> CryptoKeyStatus:
        at_dt = _parse_time("at", at)
        effective = [
            state
            for state in self.lifecycle_history(key)
            if _parse_time("effective_at", state.effective_at) <= at_dt
        ]
        if not effective:
            raise ValueError("key lifecycle is not yet effective at requested time")
        return effective[-1].status

    def current_active(
        self,
        institution_id: str,
        tenant_id: str,
        purpose: CryptoKeyPurpose,
        *,
        at: str,
    ) -> InstitutionCryptoKeyReference:
        at_dt = _parse_time("at", at)
        candidates = [
            key
            for key in self.history(institution_id, tenant_id, purpose)
            if self.status_at(key, at=at) is CryptoKeyStatus.ACTIVE
            and _parse_time("not_before", key.not_before) <= at_dt < _parse_time("not_after", key.not_after)
        ]
        if not candidates:
            raise ValueError("no active tenant crypto key exists for requested purpose/time")
        return candidates[-1]

    def assert_new_operation_allowed(self, key: InstitutionCryptoKeyReference, *, artifact_time: str, now: str) -> None:
        artifact_dt = _parse_time("artifact_time", artifact_time)
        now_dt = _parse_time("now", now)
        if artifact_dt > now_dt:
            raise ValueError("cryptographic artifact time cannot be in the future")
        if self.status_at(key, at=artifact_time) is not CryptoKeyStatus.ACTIVE:
            raise ValueError("key was not active at cryptographic artifact time")
        if self.status_at(key, at=now) is not CryptoKeyStatus.ACTIVE:
            raise ValueError("new cryptographic operation requires the key to be currently active")
        if not (_parse_time("not_before", key.not_before) <= artifact_dt < _parse_time("not_after", key.not_after)):
            raise ValueError("key is outside its validity interval at cryptographic artifact time")


@dataclass(frozen=True, slots=True)
class ConfigurationChangeRequest:
    change_id: str
    institution_id: str
    tenant_id: str
    sequence: int
    object_type: str
    object_id: str
    previous_configuration_digest: str | None
    proposed_configuration_digest: str
    change_reason_digest: str
    requested_by_human_id: str
    requested_at: str
    effective_at: str
    schema_version: str = "regagentops.configuration-change-request.v1"

    def __post_init__(self) -> None:
        for name in (
            "change_id", "institution_id", "tenant_id", "object_type", "object_id",
            "requested_by_human_id", "schema_version",
        ):
            _require_text(name, getattr(self, name))
        _require_positive_int("sequence", self.sequence)
        _require_digest("previous_configuration_digest", self.previous_configuration_digest, optional=True)
        _require_digest("proposed_configuration_digest", self.proposed_configuration_digest)
        _require_digest("change_reason_digest", self.change_reason_digest)
        if self.previous_configuration_digest == self.proposed_configuration_digest:
            raise ValueError("configuration change must alter the represented configuration digest")
        if _parse_time("effective_at", self.effective_at) < _parse_time("requested_at", self.requested_at):
            raise ValueError("configuration change effective_at cannot predate requested_at")

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class SignedConfigurationChange:
    request: ConfigurationChangeRequest
    previous_change_digest: str | None
    key_reference_digest: str
    key_id: str
    key_version: int
    algorithm: str
    signed_at: str
    signature_base64url: str
    signing_document_digest: str
    schema_version: str = "regagentops.signed-configuration-change.v1"

    def __post_init__(self) -> None:
        if not isinstance(self.request, ConfigurationChangeRequest):
            raise ValueError("signed configuration change requires a ConfigurationChangeRequest")
        _require_digest("previous_change_digest", self.previous_change_digest, optional=True)
        if self.request.sequence == 1 and self.previous_change_digest is not None:
            raise ValueError("first configuration change must not have a previous change digest")
        if self.request.sequence > 1 and self.previous_change_digest is None:
            raise ValueError("subsequent configuration changes require a previous change digest")
        _require_digest("key_reference_digest", self.key_reference_digest)
        _require_text("key_id", self.key_id)
        _require_positive_int("key_version", self.key_version)
        if self.algorithm != CryptoAlgorithm.ED25519.value:
            raise ValueError("signed configuration changes require Ed25519")
        _require_utc_timestamp("signed_at", self.signed_at)
        if len(_decode(self.signature_base64url)) != 64:
            raise ValueError("Ed25519 configuration signature must decode to 64 bytes")
        _require_digest("signing_document_digest", self.signing_document_digest)
        _require_text("schema_version", self.schema_version)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


class ConfigurationChangeSigner(Protocol):
    institution_id: str
    tenant_id: str
    key_id: str
    key_version: int
    algorithm: str

    def sign(self, message: bytes) -> bytes: ...


def configuration_change_signing_document(
    request: ConfigurationChangeRequest,
    *, previous_change_digest: str | None, key_reference_digest: str,
    key_id: str, key_version: int, algorithm: str, signed_at: str,
) -> dict[str, object]:
    return {
        "purpose": "regagentops.configuration-change.v1",
        "institution_id": request.institution_id,
        "tenant_id": request.tenant_id,
        "sequence": request.sequence,
        "request_digest": request.artifact_digest,
        "previous_change_digest": previous_change_digest,
        "key_reference_digest": key_reference_digest,
        "key_id": key_id,
        "key_version": key_version,
        "algorithm": algorithm,
        "signed_at": signed_at,
    }


def sign_configuration_change(
    request: ConfigurationChangeRequest,
    *, previous_change_digest: str | None,
    key_reference: InstitutionCryptoKeyReference,
    key_registry: InstitutionCryptoKeyRegistry,
    signer: ConfigurationChangeSigner,
    signed_at: str,
    now: str,
) -> SignedConfigurationChange:
    registered = key_registry.by_digest(request.institution_id, request.tenant_id, key_reference.artifact_digest)
    if registered.artifact_digest != key_reference.artifact_digest:
        raise ValueError("configuration signing key reference mismatch")
    if key_reference.purpose is not CryptoKeyPurpose.CONFIG_SIGNING:
        raise ValueError("configuration changes require a configuration-signing key")
    if signer.institution_id != request.institution_id or signer.tenant_id != request.tenant_id:
        raise ValueError("configuration signer tenant scope mismatch")
    if (
        signer.key_id != key_reference.key_id
        or signer.key_version != key_reference.key_version
        or signer.algorithm != CryptoAlgorithm.ED25519.value
    ):
        raise ValueError("configuration signer does not match exact key reference")
    signed_dt = _parse_time("signed_at", signed_at)
    if signed_dt < _parse_time("requested_at", request.requested_at) or signed_dt > _parse_time("effective_at", request.effective_at):
        raise ValueError("configuration signature must occur between request and effective time")
    key_registry.assert_new_operation_allowed(key_reference, artifact_time=signed_at, now=now)
    document = configuration_change_signing_document(
        request,
        previous_change_digest=previous_change_digest,
        key_reference_digest=key_reference.artifact_digest,
        key_id=key_reference.key_id,
        key_version=key_reference.key_version,
        algorithm=CryptoAlgorithm.ED25519.value,
        signed_at=signed_at,
    )
    signature = signer.sign(canonical_json(document).encode("utf-8"))
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise ValueError("Ed25519 configuration signer must return a 64-byte signature")
    return SignedConfigurationChange(
        request=request,
        previous_change_digest=previous_change_digest,
        key_reference_digest=key_reference.artifact_digest,
        key_id=key_reference.key_id,
        key_version=key_reference.key_version,
        algorithm=CryptoAlgorithm.ED25519.value,
        signed_at=signed_at,
        signature_base64url=_encode(signature),
        signing_document_digest=digest_artifact(document),
    )


def verify_signed_configuration_change(
    signed: SignedConfigurationChange,
    *, key_registry: InstitutionCryptoKeyRegistry,
    now: str,
) -> ConfigurationChangeRequest:
    now_dt = _parse_time("now", now)
    signed_dt = _parse_time("signed_at", signed.signed_at)
    if signed_dt > now_dt:
        raise ValueError("configuration change signature cannot be from the future")
    key = key_registry.by_digest(signed.request.institution_id, signed.request.tenant_id, signed.key_reference_digest)
    if key.purpose is not CryptoKeyPurpose.CONFIG_SIGNING:
        raise ValueError("configuration signature key purpose mismatch")
    if key.key_id != signed.key_id or key.key_version != signed.key_version:
        raise ValueError("configuration signature key identity mismatch")
    if key_registry.status_at(key, at=signed.signed_at) is not CryptoKeyStatus.ACTIVE:
        raise ValueError("configuration signing key was not active at signature time")
    if key_registry.status_at(key, at=now) is CryptoKeyStatus.DISABLED:
        raise ValueError("disabled configuration signing key cannot verify changes")
    if not (_parse_time("not_before", key.not_before) <= signed_dt < _parse_time("not_after", key.not_after)):
        raise ValueError("configuration signing key was not valid at signature time")
    document = configuration_change_signing_document(
        signed.request,
        previous_change_digest=signed.previous_change_digest,
        key_reference_digest=signed.key_reference_digest,
        key_id=signed.key_id,
        key_version=signed.key_version,
        algorithm=signed.algorithm,
        signed_at=signed.signed_at,
    )
    if digest_artifact(document) != signed.signing_document_digest:
        raise ValueError("configuration signing document digest mismatch")
    try:
        public_key = Ed25519PublicKey.from_public_bytes(_decode(key.public_key_base64url or ""))
        public_key.verify(_decode(signed.signature_base64url), canonical_json(document).encode("utf-8"))
    except (ValueError, InvalidSignature) as exc:
        raise ValueError("configuration change signature is invalid") from exc
    return signed.request


class ConfigurationChangeRegistry:
    """Append-only tenant configuration chain. Only effective, exactly verified changes become current."""

    def __init__(self) -> None:
        self._changes: dict[tuple[str, str, int], SignedConfigurationChange] = {}
        self._latest_object_digest: dict[tuple[str, str, str, str], str] = {}

    def history(self, institution_id: str, tenant_id: str) -> tuple[SignedConfigurationChange, ...]:
        return tuple(
            sorted(
                (
                    change for (scope, tenant, _), change in self._changes.items()
                    if scope == institution_id and tenant == tenant_id
                ),
                key=lambda change: change.request.sequence,
            )
        )

    def append(self, signed: SignedConfigurationChange, *, key_registry: InstitutionCryptoKeyRegistry, now: str) -> str:
        request = signed.request
        identity = (request.institution_id, request.tenant_id, request.sequence)
        existing = self._changes.get(identity)
        if existing is not None:
            if existing.artifact_digest != signed.artifact_digest:
                raise ValueError("configuration change sequence already exists with different content")
            return existing.artifact_digest
        verify_signed_configuration_change(signed, key_registry=key_registry, now=now)
        if _parse_time("now", now) < _parse_time("effective_at", request.effective_at):
            raise ValueError("configuration change cannot become current before effective_at")
        history = self.history(request.institution_id, request.tenant_id)
        expected = 1 if not history else history[-1].request.sequence + 1
        if request.sequence != expected:
            raise ValueError(f"configuration change sequence must be contiguous; expected {expected}")
        expected_previous = None if not history else history[-1].artifact_digest
        if signed.previous_change_digest != expected_previous:
            raise ValueError("configuration change does not extend the exact tenant change chain")
        if history and _parse_time("signed_at", signed.signed_at) < _parse_time("previous signed_at", history[-1].signed_at):
            raise ValueError("configuration change chain cannot move backward in time")
        object_key = (request.institution_id, request.tenant_id, request.object_type, request.object_id)
        current_digest = self._latest_object_digest.get(object_key)
        if current_digest is not None and request.previous_configuration_digest != current_digest:
            raise ValueError("configuration change previous digest does not match current object state")
        self._changes[identity] = signed
        self._latest_object_digest[object_key] = request.proposed_configuration_digest
        return signed.artifact_digest


@dataclass(frozen=True, slots=True)
class EncryptedGovernanceEvidence:
    envelope_id: str
    institution_id: str
    tenant_id: str
    key_reference_digest: str
    key_id: str
    key_version: int
    algorithm: str
    subject_artifact_digest: str
    plaintext_digest: str
    aad_digest: str
    nonce_base64url: str
    ciphertext_base64url: str
    encrypted_at: str
    schema_version: str = "regagentops.encrypted-governance-evidence.v1"

    def __post_init__(self) -> None:
        for name in ("envelope_id", "institution_id", "tenant_id", "key_id", "schema_version"):
            _require_text(name, getattr(self, name))
        _require_digest("key_reference_digest", self.key_reference_digest)
        _require_positive_int("key_version", self.key_version)
        if self.algorithm != CryptoAlgorithm.AES_256_GCM.value:
            raise ValueError("tenant governance evidence must use AES-256-GCM")
        for name in ("subject_artifact_digest", "plaintext_digest", "aad_digest"):
            _require_digest(name, getattr(self, name))
        if len(_decode(self.nonce_base64url)) != 12:
            raise ValueError("AES-256-GCM nonce must decode to 12 bytes")
        if len(_decode(self.ciphertext_base64url)) < 16:
            raise ValueError("AES-256-GCM ciphertext must contain an authentication tag")
        _require_utc_timestamp("encrypted_at", self.encrypted_at)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


class TenantEvidenceEncryptor(Protocol):
    institution_id: str
    tenant_id: str
    key_id: str
    key_version: int
    algorithm: str

    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes: ...


class TenantEvidenceDecryptor(Protocol):
    institution_id: str
    tenant_id: str
    key_id: str
    key_version: int
    algorithm: str

    def decrypt(self, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes: ...


def encrypted_evidence_aad_document(
    *, envelope_id: str, institution_id: str, tenant_id: str,
    key_reference_digest: str, subject_artifact_digest: str,
) -> dict[str, str]:
    return {
        "purpose": "regagentops.tenant-encrypted-governance-evidence.v1",
        "envelope_id": envelope_id,
        "institution_id": institution_id,
        "tenant_id": tenant_id,
        "key_reference_digest": key_reference_digest,
        "subject_artifact_digest": subject_artifact_digest,
    }


def encrypt_governance_evidence(
    plaintext: bytes,
    *, envelope_id: str, institution_id: str, tenant_id: str,
    subject_artifact_digest: str,
    key_reference: InstitutionCryptoKeyReference,
    key_registry: InstitutionCryptoKeyRegistry,
    encryptor: TenantEvidenceEncryptor,
    encrypted_at: str,
    now: str,
) -> EncryptedGovernanceEvidence:
    if not isinstance(plaintext, bytes) or not plaintext:
        raise ValueError("governance evidence plaintext must be non-empty bytes")
    _require_digest("subject_artifact_digest", subject_artifact_digest)
    registered = key_registry.by_digest(institution_id, tenant_id, key_reference.artifact_digest)
    if registered.artifact_digest != key_reference.artifact_digest:
        raise ValueError("evidence encryption key reference mismatch")
    if key_reference.purpose is not CryptoKeyPurpose.EVIDENCE_ENCRYPTION:
        raise ValueError("governance evidence requires an evidence-encryption key")
    key_registry.assert_new_operation_allowed(key_reference, artifact_time=encrypted_at, now=now)
    if (
        encryptor.institution_id != institution_id
        or encryptor.tenant_id != tenant_id
        or encryptor.key_id != key_reference.key_id
        or encryptor.key_version != key_reference.key_version
        or encryptor.algorithm != CryptoAlgorithm.AES_256_GCM.value
    ):
        raise ValueError("evidence encryptor does not match exact tenant key reference")
    selected_nonce = secrets.token_bytes(12)
    aad_document = encrypted_evidence_aad_document(
        envelope_id=envelope_id,
        institution_id=institution_id,
        tenant_id=tenant_id,
        key_reference_digest=key_reference.artifact_digest,
        subject_artifact_digest=subject_artifact_digest,
    )
    aad = canonical_json(aad_document).encode("utf-8")
    ciphertext = encryptor.encrypt(selected_nonce, plaintext, aad)
    if not isinstance(ciphertext, bytes) or len(ciphertext) < 16:
        raise ValueError("AES-256-GCM encryptor must return ciphertext with authentication tag")
    return EncryptedGovernanceEvidence(
        envelope_id=envelope_id,
        institution_id=institution_id,
        tenant_id=tenant_id,
        key_reference_digest=key_reference.artifact_digest,
        key_id=key_reference.key_id,
        key_version=key_reference.key_version,
        algorithm=CryptoAlgorithm.AES_256_GCM.value,
        subject_artifact_digest=subject_artifact_digest,
        plaintext_digest=_sha256_bytes(plaintext),
        aad_digest=_sha256_bytes(aad),
        nonce_base64url=_encode(selected_nonce),
        ciphertext_base64url=_encode(ciphertext),
        encrypted_at=encrypted_at,
    )


def decrypt_and_verify_governance_evidence(
    envelope: EncryptedGovernanceEvidence,
    *, key_registry: InstitutionCryptoKeyRegistry,
    decryptor: TenantEvidenceDecryptor,
    now: str,
) -> bytes:
    now_dt = _parse_time("now", now)
    encrypted_dt = _parse_time("encrypted_at", envelope.encrypted_at)
    if encrypted_dt > now_dt:
        raise ValueError("encrypted governance evidence cannot be from the future")
    key = key_registry.by_digest(envelope.institution_id, envelope.tenant_id, envelope.key_reference_digest)
    if key.purpose is not CryptoKeyPurpose.EVIDENCE_ENCRYPTION:
        raise ValueError("encrypted evidence key purpose mismatch")
    if key.key_id != envelope.key_id or key.key_version != envelope.key_version:
        raise ValueError("encrypted evidence key identity mismatch")
    if key_registry.status_at(key, at=envelope.encrypted_at) is not CryptoKeyStatus.ACTIVE:
        raise ValueError("encryption key was not active when evidence was encrypted")
    if key_registry.status_at(key, at=now) is CryptoKeyStatus.DISABLED:
        raise ValueError("disabled encryption key cannot decrypt governance evidence")
    if not (_parse_time("not_before", key.not_before) <= encrypted_dt < _parse_time("not_after", key.not_after)):
        raise ValueError("encryption key was not valid when evidence was encrypted")
    if (
        decryptor.institution_id != envelope.institution_id
        or decryptor.tenant_id != envelope.tenant_id
        or decryptor.key_id != envelope.key_id
        or decryptor.key_version != envelope.key_version
        or decryptor.algorithm != CryptoAlgorithm.AES_256_GCM.value
    ):
        raise ValueError("evidence decryptor does not match encrypted tenant key reference")
    aad_document = encrypted_evidence_aad_document(
        envelope_id=envelope.envelope_id,
        institution_id=envelope.institution_id,
        tenant_id=envelope.tenant_id,
        key_reference_digest=envelope.key_reference_digest,
        subject_artifact_digest=envelope.subject_artifact_digest,
    )
    aad = canonical_json(aad_document).encode("utf-8")
    if _sha256_bytes(aad) != envelope.aad_digest:
        raise ValueError("encrypted governance evidence AAD digest mismatch")
    try:
        plaintext = decryptor.decrypt(_decode(envelope.nonce_base64url), _decode(envelope.ciphertext_base64url), aad)
    except Exception as exc:
        raise ValueError("encrypted governance evidence authentication failed") from exc
    if not isinstance(plaintext, bytes) or _sha256_bytes(plaintext) != envelope.plaintext_digest:
        raise ValueError("encrypted governance evidence plaintext digest mismatch")
    return plaintext


@dataclass(frozen=True, slots=True)
class AuditAnchorBatch:
    batch_id: str
    institution_id: str
    tenant_id: str
    sequence: int
    previous_anchor_record_digest: str | None
    evidence_artifact_digests: tuple[str, ...]
    assembled_at: str
    schema_version: str = "regagentops.audit-anchor-batch.v1"

    def __post_init__(self) -> None:
        for name in ("batch_id", "institution_id", "tenant_id", "schema_version"):
            _require_text(name, getattr(self, name))
        _require_positive_int("sequence", self.sequence)
        _require_digest("previous_anchor_record_digest", self.previous_anchor_record_digest, optional=True)
        if self.sequence == 1 and self.previous_anchor_record_digest is not None:
            raise ValueError("first audit anchor batch must not have a previous record digest")
        if self.sequence > 1 and self.previous_anchor_record_digest is None:
            raise ValueError("subsequent audit anchor batches require previous record digest")
        _require_sorted_digests("evidence_artifact_digests", self.evidence_artifact_digests)
        _require_utc_timestamp("assembled_at", self.assembled_at)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class ExternalAuditAnchorReceipt:
    institution_id: str
    tenant_id: str
    batch_digest: str
    provider_id: str
    anchor_id: str
    provider_receipt_digest: str
    anchored_at: str
    schema_version: str = "regagentops.external-audit-anchor-receipt.v1"

    def __post_init__(self) -> None:
        for name in ("institution_id", "tenant_id", "provider_id", "anchor_id", "schema_version"):
            _require_text(name, getattr(self, name))
        _require_digest("batch_digest", self.batch_digest)
        _require_digest("provider_receipt_digest", self.provider_receipt_digest)
        _require_utc_timestamp("anchored_at", self.anchored_at)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class AuditAnchorRecord:
    institution_id: str
    tenant_id: str
    sequence: int
    batch_digest: str
    external_receipt_digest: str
    previous_anchor_record_digest: str | None
    recorded_at: str
    schema_version: str = "regagentops.audit-anchor-record.v1"

    def __post_init__(self) -> None:
        for name in ("institution_id", "tenant_id", "schema_version"):
            _require_text(name, getattr(self, name))
        _require_positive_int("sequence", self.sequence)
        _require_digest("batch_digest", self.batch_digest)
        _require_digest("external_receipt_digest", self.external_receipt_digest)
        _require_digest("previous_anchor_record_digest", self.previous_anchor_record_digest, optional=True)
        _require_utc_timestamp("recorded_at", self.recorded_at)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


class AuditAnchorRegistry:
    """Append-only hash chain bound to opaque receipts produced by an external immutable anchoring service."""

    def __init__(self) -> None:
        self._records: dict[tuple[str, str, int], AuditAnchorRecord] = {}

    def history(self, institution_id: str, tenant_id: str) -> tuple[AuditAnchorRecord, ...]:
        return tuple(
            sorted(
                (
                    record for (scope, tenant, _), record in self._records.items()
                    if scope == institution_id and tenant == tenant_id
                ),
                key=lambda record: record.sequence,
            )
        )

    def register(self, batch: AuditAnchorBatch, receipt: ExternalAuditAnchorReceipt, *, recorded_at: str) -> AuditAnchorRecord:
        identity = (batch.institution_id, batch.tenant_id, batch.sequence)
        existing = self._records.get(identity)
        if existing is not None:
            candidate = AuditAnchorRecord(
                institution_id=batch.institution_id,
                tenant_id=batch.tenant_id,
                sequence=batch.sequence,
                batch_digest=batch.artifact_digest,
                external_receipt_digest=receipt.artifact_digest,
                previous_anchor_record_digest=batch.previous_anchor_record_digest,
                recorded_at=recorded_at,
            )
            if existing.artifact_digest != candidate.artifact_digest:
                raise ValueError("audit anchor sequence already exists with different content")
            return existing
        history = self.history(batch.institution_id, batch.tenant_id)
        expected = 1 if not history else history[-1].sequence + 1
        expected_previous = None if not history else history[-1].artifact_digest
        if batch.sequence != expected:
            raise ValueError(f"audit anchor sequence must be contiguous; expected {expected}")
        if batch.previous_anchor_record_digest != expected_previous:
            raise ValueError("audit anchor batch does not extend the exact previous record")
        if receipt.institution_id != batch.institution_id or receipt.tenant_id != batch.tenant_id:
            raise ValueError("external anchor receipt tenant scope mismatch")
        if receipt.batch_digest != batch.artifact_digest:
            raise ValueError("external anchor receipt does not bind the exact audit batch")
        assembled = _parse_time("assembled_at", batch.assembled_at)
        anchored = _parse_time("anchored_at", receipt.anchored_at)
        recorded = _parse_time("recorded_at", recorded_at)
        if anchored < assembled:
            raise ValueError("external audit anchor cannot predate batch assembly")
        if recorded < anchored:
            raise ValueError("audit anchor record cannot predate external anchoring")
        if history and recorded < _parse_time("previous recorded_at", history[-1].recorded_at):
            raise ValueError("audit anchor chain cannot move backward in time")
        record = AuditAnchorRecord(
            institution_id=batch.institution_id,
            tenant_id=batch.tenant_id,
            sequence=batch.sequence,
            batch_digest=batch.artifact_digest,
            external_receipt_digest=receipt.artifact_digest,
            previous_anchor_record_digest=batch.previous_anchor_record_digest,
            recorded_at=recorded_at,
        )
        self._records[identity] = record
        return record
