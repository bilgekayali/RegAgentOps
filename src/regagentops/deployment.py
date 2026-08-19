from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import ipaddress
import re

from .models import digest_artifact, _require_text, _require_utc_timestamp

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_40 = re.compile(r"^[0-9a-f]{40}$")
_SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_SAFE_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,254}$")


def _require_digest(name: str, value: str) -> None:
    if not isinstance(value, str) or not _HEX_64.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase SHA-256 hex digest")


def _require_positive_int(name: str, value: int, *, maximum: int | None = None) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    if maximum is not None and value > maximum:
        raise ValueError(f"{name} must not exceed {maximum}")


def _parse_time(name: str, value: str) -> datetime:
    _require_utc_timestamp(name, value)
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _semver(value: str) -> tuple[int, int, int]:
    if not isinstance(value, str):
        raise ValueError("release_version must be strict MAJOR.MINOR.PATCH text")
    match = _SEMVER.fullmatch(value)
    if match is None:
        raise ValueError("release_version must be strict MAJOR.MINOR.PATCH text")
    return tuple(int(part) for part in match.groups())


def _require_host(value: str) -> None:
    if not isinstance(value, str) or not value or value != value.lower() or "*" in value or "/" in value or "://" in value:
        raise ValueError("egress host must be an exact lowercase host or IP with no wildcard/path/scheme")
    try:
        ipaddress.ip_address(value)
        return
    except ValueError:
        pass
    if len(value) > 253 or value.endswith("."):
        raise ValueError("egress host must be a bounded canonical hostname")
    labels = value.split(".")
    if any(_HOST_LABEL.fullmatch(label) is None for label in labels):
        raise ValueError("egress host must be a bounded canonical hostname")


def _require_sorted_digests(name: str, values: tuple[str, ...], *, allow_empty: bool = False) -> None:
    if not allow_empty and not values:
        raise ValueError(f"{name} must not be empty")
    for value in values:
        _require_digest(name, value)
    if len(values) != len(set(values)) or values != tuple(sorted(values)):
        raise ValueError(f"{name} must be unique and sorted")


class EgressProtocol(str, Enum):
    HTTPS = "https"
    TLS = "tls"


@dataclass(frozen=True, slots=True)
class EgressDestination:
    destination_id: str
    protocol: EgressProtocol
    host: str
    port: int
    purpose: str
    trust_policy_digest: str

    def __post_init__(self) -> None:
        _require_text("destination_id", self.destination_id)
        if not isinstance(self.protocol, EgressProtocol):
            raise ValueError("egress protocol must be governed")
        _require_host(self.host)
        _require_positive_int("port", self.port, maximum=65535)
        _require_text("purpose", self.purpose, limit=512)
        _require_digest("trust_policy_digest", self.trust_policy_digest)


@dataclass(frozen=True, slots=True)
class EgressPolicy:
    institution_id: str
    tenant_id: str
    policy_version: int
    allowed_destinations: tuple[EgressDestination, ...]
    default_deny: bool
    allow_wildcards: bool
    allow_plaintext: bool
    registered_at: str
    schema_version: str = "regagentops.egress-policy.v1"

    def __post_init__(self) -> None:
        for name in ("institution_id", "tenant_id", "schema_version"):
            _require_text(name, getattr(self, name))
        _require_positive_int("policy_version", self.policy_version)
        if self.default_deny is not True:
            raise ValueError("production egress policy must be default deny")
        if self.allow_wildcards is not False:
            raise ValueError("production egress policy must forbid wildcard destinations")
        if self.allow_plaintext is not False:
            raise ValueError("production egress policy must forbid plaintext transport")
        if any(not isinstance(item, EgressDestination) for item in self.allowed_destinations):
            raise ValueError("allowed_destinations must contain EgressDestination values")
        keys = tuple((item.destination_id, item.protocol.value, item.host, item.port) for item in self.allowed_destinations)
        if len(keys) != len(set(keys)) or keys != tuple(sorted(keys)):
            raise ValueError("allowed_destinations must be unique and canonically sorted")
        endpoint_keys = [(item.protocol.value, item.host, item.port) for item in self.allowed_destinations]
        if len(endpoint_keys) != len(set(endpoint_keys)):
            raise ValueError("one exact endpoint may appear only once in an egress policy")
        _require_utc_timestamp("registered_at", self.registered_at)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class ToolDispatchBinding:
    governed_tool_id: str
    executor_id: str
    governance_binding_digest: str

    def __post_init__(self) -> None:
        _require_text("governed_tool_id", self.governed_tool_id)
        _require_text("executor_id", self.executor_id)
        _require_digest("governance_binding_digest", self.governance_binding_digest)


@dataclass(frozen=True, slots=True)
class ToolAllowlistPolicy:
    institution_id: str
    tenant_id: str
    policy_version: int
    bindings: tuple[ToolDispatchBinding, ...]
    default_deny: bool
    direct_tool_invocation_allowed: bool
    registered_at: str
    schema_version: str = "regagentops.tool-allowlist-policy.v1"

    def __post_init__(self) -> None:
        for name in ("institution_id", "tenant_id", "schema_version"):
            _require_text(name, getattr(self, name))
        _require_positive_int("policy_version", self.policy_version)
        if self.default_deny is not True:
            raise ValueError("production tool allowlist must be default deny")
        if self.direct_tool_invocation_allowed is not False:
            raise ValueError("policy worker must not directly invoke tools")
        if any(not isinstance(item, ToolDispatchBinding) for item in self.bindings):
            raise ValueError("bindings must contain ToolDispatchBinding values")
        keys = tuple((item.governed_tool_id, item.executor_id, item.governance_binding_digest) for item in self.bindings)
        if len(keys) != len(set(keys)) or keys != tuple(sorted(keys)):
            raise ValueError("tool dispatch bindings must be unique and canonically sorted")
        tool_ids = [item.governed_tool_id for item in self.bindings]
        if len(tool_ids) != len(set(tool_ids)):
            raise ValueError("one governed tool may bind to only one executor in an allowlist")
        _require_utc_timestamp("registered_at", self.registered_at)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class IsolatedPolicyWorkerProfile:
    institution_id: str
    tenant_id: str
    worker_profile_version: int
    worker_image_digest: str
    service_account_id: str
    egress_policy_digest: str
    tool_allowlist_policy_digest: str
    tenant_isolation_profile_digest: str
    network_namespace_isolated: bool
    run_as_non_root: bool
    read_only_root_filesystem: bool
    no_new_privileges: bool
    drop_all_linux_capabilities: bool
    seccomp_profile: str
    privileged: bool
    host_network: bool
    host_pid: bool
    host_ipc: bool
    direct_tool_invocation: bool
    registered_at: str
    schema_version: str = "regagentops.isolated-policy-worker-profile.v1"

    def __post_init__(self) -> None:
        for name in ("institution_id", "tenant_id", "service_account_id", "schema_version"):
            _require_text(name, getattr(self, name))
        _require_positive_int("worker_profile_version", self.worker_profile_version)
        for name in (
            "worker_image_digest",
            "egress_policy_digest",
            "tool_allowlist_policy_digest",
            "tenant_isolation_profile_digest",
        ):
            _require_digest(name, getattr(self, name))
        required_true = (
            "network_namespace_isolated",
            "run_as_non_root",
            "read_only_root_filesystem",
            "no_new_privileges",
            "drop_all_linux_capabilities",
        )
        for name in required_true:
            if getattr(self, name) is not True:
                raise ValueError(f"production policy worker requires {name}=true")
        required_false = ("privileged", "host_network", "host_pid", "host_ipc", "direct_tool_invocation")
        for name in required_false:
            if getattr(self, name) is not False:
                raise ValueError(f"production policy worker requires {name}=false")
        if self.seccomp_profile != "RuntimeDefault":
            raise ValueError("production policy worker requires RuntimeDefault seccomp")
        _require_utc_timestamp("registered_at", self.registered_at)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class DeploymentReleaseManifest:
    institution_id: str
    tenant_id: str
    release_id: str
    release_version: str
    source_commit_sha: str
    artifact_name: str
    artifact_sha256: str
    worker_profile_digest: str
    configuration_digest: str
    codeql_evidence_digest: str
    provenance_attestation_digest: str
    checksum_manifest_digest: str
    created_at: str
    schema_version: str = "regagentops.deployment-release-manifest.v1"

    def __post_init__(self) -> None:
        for name in ("institution_id", "tenant_id", "release_id", "schema_version"):
            _require_text(name, getattr(self, name))
        _semver(self.release_version)
        if not isinstance(self.source_commit_sha, str) or _COMMIT_40.fullmatch(self.source_commit_sha) is None:
            raise ValueError("source_commit_sha must be a lowercase 40-character Git commit SHA")
        if not isinstance(self.artifact_name, str) or _SAFE_FILENAME.fullmatch(self.artifact_name) is None:
            raise ValueError("artifact_name must be a safe bounded filename")
        for name in (
            "artifact_sha256",
            "worker_profile_digest",
            "configuration_digest",
            "codeql_evidence_digest",
            "provenance_attestation_digest",
            "checksum_manifest_digest",
        ):
            _require_digest(name, getattr(self, name))
        _require_utc_timestamp("created_at", self.created_at)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class RollbackPlan:
    institution_id: str
    tenant_id: str
    rollback_id: str
    source_release_digest: str
    target_release_digest: str
    trigger_condition_digests: tuple[str, ...]
    verification_procedure_digest: str
    max_window_seconds: int
    created_at: str
    schema_version: str = "regagentops.rollback-plan.v1"

    def __post_init__(self) -> None:
        for name in ("institution_id", "tenant_id", "rollback_id", "schema_version"):
            _require_text(name, getattr(self, name))
        _require_digest("source_release_digest", self.source_release_digest)
        _require_digest("target_release_digest", self.target_release_digest)
        if self.source_release_digest == self.target_release_digest:
            raise ValueError("rollback source and target releases must differ")
        _require_sorted_digests("trigger_condition_digests", self.trigger_condition_digests)
        _require_digest("verification_procedure_digest", self.verification_procedure_digest)
        _require_positive_int("max_window_seconds", self.max_window_seconds, maximum=604800)
        _require_utc_timestamp("created_at", self.created_at)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class UpgradePlan:
    institution_id: str
    tenant_id: str
    upgrade_id: str
    from_release_digest: str
    to_release_digest: str
    migration_plan_digest: str
    preflight_check_digest: str
    post_deploy_check_digest: str
    rollback_plan_digest: str
    signed_configuration_change_digest: str
    created_at: str
    schema_version: str = "regagentops.upgrade-plan.v1"

    def __post_init__(self) -> None:
        for name in ("institution_id", "tenant_id", "upgrade_id", "schema_version"):
            _require_text(name, getattr(self, name))
        for name in (
            "from_release_digest",
            "to_release_digest",
            "migration_plan_digest",
            "preflight_check_digest",
            "post_deploy_check_digest",
            "rollback_plan_digest",
            "signed_configuration_change_digest",
        ):
            _require_digest(name, getattr(self, name))
        if self.from_release_digest == self.to_release_digest:
            raise ValueError("upgrade from/to release must differ")
        _require_utc_timestamp("created_at", self.created_at)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class RecoveryCheckpoint:
    institution_id: str
    tenant_id: str
    checkpoint_id: str
    release_digest: str
    configuration_digest: str
    encrypted_backup_digest: str
    audit_anchor_record_digest: str
    restore_verification_digest: str
    created_at: str
    schema_version: str = "regagentops.recovery-checkpoint.v1"

    def __post_init__(self) -> None:
        for name in ("institution_id", "tenant_id", "checkpoint_id", "schema_version"):
            _require_text(name, getattr(self, name))
        for name in (
            "release_digest",
            "configuration_digest",
            "encrypted_backup_digest",
            "audit_anchor_record_digest",
            "restore_verification_digest",
        ):
            _require_digest(name, getattr(self, name))
        _require_utc_timestamp("created_at", self.created_at)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


class ProductionDeploymentRegistry:
    """Append-only production-reference deployment metadata. It never opens sockets, deploys workloads or invokes tools."""

    def __init__(self) -> None:
        self._egress: dict[tuple[str, str, int], EgressPolicy] = {}
        self._tools: dict[tuple[str, str, int], ToolAllowlistPolicy] = {}
        self._workers: dict[tuple[str, str, int], IsolatedPolicyWorkerProfile] = {}
        self._releases: dict[tuple[str, str, str], DeploymentReleaseManifest] = {}
        self._rollbacks: dict[tuple[str, str, str], RollbackPlan] = {}
        self._upgrades: dict[tuple[str, str, str], UpgradePlan] = {}
        self._recovery: dict[tuple[str, str, str], RecoveryCheckpoint] = {}

    @staticmethod
    def _same_or_conflict(existing, candidate, label: str) -> str:
        if existing.artifact_digest != candidate.artifact_digest:
            raise ValueError(f"{label} identity already exists with different content")
        return existing.artifact_digest

    def register_egress_policy(self, policy: EgressPolicy) -> str:
        key = (policy.institution_id, policy.tenant_id, policy.policy_version)
        existing = self._egress.get(key)
        if existing is not None:
            return self._same_or_conflict(existing, policy, "egress policy")
        history = self.egress_history(policy.institution_id, policy.tenant_id)
        expected = 1 if not history else history[-1].policy_version + 1
        if policy.policy_version != expected:
            raise ValueError(f"egress policy_version must be contiguous; expected version {expected}")
        if history and _parse_time("registered_at", policy.registered_at) < _parse_time(
            "previous registered_at", history[-1].registered_at
        ):
            raise ValueError("new egress policy cannot predate the previous version")
        self._egress[key] = policy
        return policy.artifact_digest

    def egress_history(self, institution_id: str, tenant_id: str) -> tuple[EgressPolicy, ...]:
        return tuple(sorted(
            (item for (scope, tenant, _), item in self._egress.items() if scope == institution_id and tenant == tenant_id),
            key=lambda item: item.policy_version,
        ))

    def current_egress_policy(self, institution_id: str, tenant_id: str) -> EgressPolicy:
        history = self.egress_history(institution_id, tenant_id)
        if not history:
            raise ValueError("egress policy is not registered")
        return history[-1]

    def register_tool_allowlist(self, policy: ToolAllowlistPolicy) -> str:
        key = (policy.institution_id, policy.tenant_id, policy.policy_version)
        existing = self._tools.get(key)
        if existing is not None:
            return self._same_or_conflict(existing, policy, "tool allowlist")
        history = self.tool_history(policy.institution_id, policy.tenant_id)
        expected = 1 if not history else history[-1].policy_version + 1
        if policy.policy_version != expected:
            raise ValueError(f"tool allowlist policy_version must be contiguous; expected version {expected}")
        if history and _parse_time("registered_at", policy.registered_at) < _parse_time(
            "previous registered_at", history[-1].registered_at
        ):
            raise ValueError("new tool allowlist cannot predate the previous version")
        self._tools[key] = policy
        return policy.artifact_digest

    def tool_history(self, institution_id: str, tenant_id: str) -> tuple[ToolAllowlistPolicy, ...]:
        return tuple(sorted(
            (item for (scope, tenant, _), item in self._tools.items() if scope == institution_id and tenant == tenant_id),
            key=lambda item: item.policy_version,
        ))

    def current_tool_allowlist(self, institution_id: str, tenant_id: str) -> ToolAllowlistPolicy:
        history = self.tool_history(institution_id, tenant_id)
        if not history:
            raise ValueError("tool allowlist is not registered")
        return history[-1]

    def _egress_by_digest(self, institution_id: str, tenant_id: str, digest: str) -> EgressPolicy:
        for (scope, tenant, _), item in self._egress.items():
            if scope == institution_id and tenant == tenant_id and item.artifact_digest == digest:
                return item
        raise ValueError("unknown tenant egress policy digest")

    def _tools_by_digest(self, institution_id: str, tenant_id: str, digest: str) -> ToolAllowlistPolicy:
        for (scope, tenant, _), item in self._tools.items():
            if scope == institution_id and tenant == tenant_id and item.artifact_digest == digest:
                return item
        raise ValueError("unknown tenant tool allowlist digest")

    def register_worker_profile(self, profile: IsolatedPolicyWorkerProfile) -> str:
        egress = self._egress_by_digest(profile.institution_id, profile.tenant_id, profile.egress_policy_digest)
        tools = self._tools_by_digest(profile.institution_id, profile.tenant_id, profile.tool_allowlist_policy_digest)
        if egress.artifact_digest != self.current_egress_policy(profile.institution_id, profile.tenant_id).artifact_digest:
            raise ValueError("worker profile must bind current egress policy")
        if tools.artifact_digest != self.current_tool_allowlist(profile.institution_id, profile.tenant_id).artifact_digest:
            raise ValueError("worker profile must bind current tool allowlist")
        key = (profile.institution_id, profile.tenant_id, profile.worker_profile_version)
        existing = self._workers.get(key)
        if existing is not None:
            return self._same_or_conflict(existing, profile, "worker profile")
        history = self.worker_history(profile.institution_id, profile.tenant_id)
        expected = 1 if not history else history[-1].worker_profile_version + 1
        if profile.worker_profile_version != expected:
            raise ValueError(f"worker_profile_version must be contiguous; expected version {expected}")
        if history and _parse_time("registered_at", profile.registered_at) < _parse_time(
            "previous registered_at", history[-1].registered_at
        ):
            raise ValueError("new worker profile cannot predate the previous version")
        self._workers[key] = profile
        return profile.artifact_digest

    def worker_history(self, institution_id: str, tenant_id: str) -> tuple[IsolatedPolicyWorkerProfile, ...]:
        return tuple(sorted(
            (item for (scope, tenant, _), item in self._workers.items() if scope == institution_id and tenant == tenant_id),
            key=lambda item: item.worker_profile_version,
        ))

    def current_worker_profile(self, institution_id: str, tenant_id: str) -> IsolatedPolicyWorkerProfile:
        history = self.worker_history(institution_id, tenant_id)
        if not history:
            raise ValueError("policy worker profile is not registered")
        return history[-1]

    def _worker_by_digest(self, institution_id: str, tenant_id: str, digest: str) -> IsolatedPolicyWorkerProfile:
        for (scope, tenant, _), item in self._workers.items():
            if scope == institution_id and tenant == tenant_id and item.artifact_digest == digest:
                return item
        raise ValueError("unknown tenant worker profile digest")

    def register_release(self, release: DeploymentReleaseManifest) -> str:
        worker = self._worker_by_digest(release.institution_id, release.tenant_id, release.worker_profile_digest)
        if worker.artifact_digest != self.current_worker_profile(release.institution_id, release.tenant_id).artifact_digest:
            raise ValueError("release must bind the current worker profile")
        key = (release.institution_id, release.tenant_id, release.release_id)
        existing = self._releases.get(key)
        if existing is not None:
            return self._same_or_conflict(existing, release, "release")
        history = self.release_history(release.institution_id, release.tenant_id)
        if any(item.release_version == release.release_version for item in history):
            raise ValueError("release_version already exists for tenant")
        if history and _semver(release.release_version) <= _semver(history[-1].release_version):
            raise ValueError("release_version must increase monotonically")
        if history and _parse_time("created_at", release.created_at) < _parse_time("previous created_at", history[-1].created_at):
            raise ValueError("new release cannot predate the previous release")
        self._releases[key] = release
        return release.artifact_digest

    def release_history(self, institution_id: str, tenant_id: str) -> tuple[DeploymentReleaseManifest, ...]:
        return tuple(sorted(
            (item for (scope, tenant, _), item in self._releases.items() if scope == institution_id and tenant == tenant_id),
            key=lambda item: _semver(item.release_version),
        ))

    def _release_by_digest(self, institution_id: str, tenant_id: str, digest: str) -> DeploymentReleaseManifest:
        for (scope, tenant, _), item in self._releases.items():
            if scope == institution_id and tenant == tenant_id and item.artifact_digest == digest:
                return item
        raise ValueError("unknown tenant release digest")

    def assert_release_current(self, release: DeploymentReleaseManifest) -> None:
        registered = self._release_by_digest(release.institution_id, release.tenant_id, release.artifact_digest)
        if registered.artifact_digest != release.artifact_digest:
            raise ValueError("release identity mismatch")
        worker = self._worker_by_digest(release.institution_id, release.tenant_id, release.worker_profile_digest)
        if worker.artifact_digest != self.current_worker_profile(release.institution_id, release.tenant_id).artifact_digest:
            raise ValueError("release worker profile is stale")
        if worker.egress_policy_digest != self.current_egress_policy(release.institution_id, release.tenant_id).artifact_digest:
            raise ValueError("release egress policy is stale")
        if worker.tool_allowlist_policy_digest != self.current_tool_allowlist(release.institution_id, release.tenant_id).artifact_digest:
            raise ValueError("release tool allowlist is stale")

    def register_rollback(self, plan: RollbackPlan) -> str:
        source = self._release_by_digest(plan.institution_id, plan.tenant_id, plan.source_release_digest)
        target = self._release_by_digest(plan.institution_id, plan.tenant_id, plan.target_release_digest)
        if _semver(target.release_version) >= _semver(source.release_version):
            raise ValueError("rollback target must be an older release")
        if _parse_time("created_at", plan.created_at) < max(_parse_time("source created_at", source.created_at), _parse_time("target created_at", target.created_at)):
            raise ValueError("rollback plan cannot predate referenced releases")
        key = (plan.institution_id, plan.tenant_id, plan.rollback_id)
        existing = self._rollbacks.get(key)
        if existing is not None:
            return self._same_or_conflict(existing, plan, "rollback plan")
        self._rollbacks[key] = plan
        return plan.artifact_digest

    def _rollback_by_digest(self, institution_id: str, tenant_id: str, digest: str) -> RollbackPlan:
        for (scope, tenant, _), item in self._rollbacks.items():
            if scope == institution_id and tenant == tenant_id and item.artifact_digest == digest:
                return item
        raise ValueError("unknown tenant rollback plan digest")

    def register_upgrade(self, plan: UpgradePlan) -> str:
        old = self._release_by_digest(plan.institution_id, plan.tenant_id, plan.from_release_digest)
        new = self._release_by_digest(plan.institution_id, plan.tenant_id, plan.to_release_digest)
        if _semver(new.release_version) <= _semver(old.release_version):
            raise ValueError("upgrade target must be a newer release")
        rollback = self._rollback_by_digest(plan.institution_id, plan.tenant_id, plan.rollback_plan_digest)
        if rollback.source_release_digest != new.artifact_digest or rollback.target_release_digest != old.artifact_digest:
            raise ValueError("upgrade rollback plan must exactly reverse the release transition")
        if _parse_time("created_at", plan.created_at) < max(
            _parse_time("new release created_at", new.created_at),
            _parse_time("rollback created_at", rollback.created_at),
        ):
            raise ValueError("upgrade plan cannot predate its target release or rollback plan")
        key = (plan.institution_id, plan.tenant_id, plan.upgrade_id)
        existing = self._upgrades.get(key)
        if existing is not None:
            return self._same_or_conflict(existing, plan, "upgrade plan")
        self._upgrades[key] = plan
        return plan.artifact_digest

    def register_recovery_checkpoint(self, checkpoint: RecoveryCheckpoint) -> str:
        release = self._release_by_digest(checkpoint.institution_id, checkpoint.tenant_id, checkpoint.release_digest)
        if _parse_time("created_at", checkpoint.created_at) < _parse_time("release created_at", release.created_at):
            raise ValueError("recovery checkpoint cannot predate its release")
        key = (checkpoint.institution_id, checkpoint.tenant_id, checkpoint.checkpoint_id)
        existing = self._recovery.get(key)
        if existing is not None:
            return self._same_or_conflict(existing, checkpoint, "recovery checkpoint")
        self._recovery[key] = checkpoint
        return checkpoint.artifact_digest
