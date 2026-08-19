from dataclasses import replace
import unittest

from regagentops.deployment import (
    DeploymentReleaseManifest,
    EgressDestination,
    EgressPolicy,
    EgressProtocol,
    IsolatedPolicyWorkerProfile,
    ProductionDeploymentRegistry,
    RecoveryCheckpoint,
    RollbackPlan,
    ToolAllowlistPolicy,
    ToolDispatchBinding,
    UpgradePlan,
)
from regagentops.hardening import PostgresRlsPolicy, TenantIsolationProfile, TenantIsolationRegistry
from regagentops.models import Environment

T_MINUS = "2026-08-19T14:29:00Z"
T0 = "2026-08-19T14:30:00Z"
T1 = "2026-08-19T14:31:00Z"
T2 = "2026-08-19T14:32:00Z"
T3 = "2026-08-19T14:33:00Z"
T4 = "2026-08-19T14:34:00Z"


class ProductionReferenceDeploymentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tenant_registry = TenantIsolationRegistry()
        self.rls = self.make_rls()
        self.tenant_registry.register_policy(self.rls)
        self.tenant_profile = TenantIsolationProfile(
            institution_id="bank-demo",
            tenant_id="tenant-a",
            profile_version=1,
            environment=Environment.PRODUCTION,
            database_role="regagentops_worker",
            rls_policy_digests=(self.rls.artifact_digest,),
            registered_at=T0,
        )
        self.tenant_registry.register_profile(self.tenant_profile)
        self.registry = ProductionDeploymentRegistry(tenant_isolation_registry=self.tenant_registry)
        self.egress = self.make_egress()
        self.tools = self.make_tools()
        self.registry.register_egress_policy(self.egress)
        self.registry.register_tool_allowlist(self.tools)
        self.worker = self.make_worker()
        self.registry.register_worker_profile(self.worker)

    def make_rls(self, *, version=1, registered_at=T0):
        return PostgresRlsPolicy(
            institution_id="bank-demo",
            policy_id="tenant-rls",
            policy_version=version,
            table_name="governance_evidence",
            policy_name="tenant_guard",
            institution_column="institution_id",
            tenant_column="tenant_id",
            institution_setting="regagentops.institution_id",
            tenant_setting="regagentops.tenant_id",
            force_row_level_security=True,
            registered_at=registered_at,
        )

    def make_egress(self, *, version=1, registered_at=T0, host="kms.bank.example"):
        destinations = (
            EgressDestination(
                destination_id="kms-api",
                protocol=EgressProtocol.HTTPS,
                host=host,
                port=443,
                purpose="Institution KMS adapter endpoint",
                trust_policy_digest="1" * 64,
            ),
        )
        return EgressPolicy(
            institution_id="bank-demo",
            tenant_id="tenant-a",
            policy_version=version,
            allowed_destinations=destinations,
            default_deny=True,
            allow_wildcards=False,
            allow_plaintext=False,
            registered_at=registered_at,
        )

    def make_tools(self, *, version=1, registered_at=T0):
        return ToolAllowlistPolicy(
            institution_id="bank-demo",
            tenant_id="tenant-a",
            policy_version=version,
            bindings=(
                ToolDispatchBinding(
                    governed_tool_id="mcp:payments:read",
                    executor_id="executor-a",
                    governance_binding_digest="2" * 64,
                ),
            ),
            default_deny=True,
            direct_tool_invocation_allowed=False,
            registered_at=registered_at,
        )

    def make_worker(
        self,
        *,
        version=1,
        registered_at=T0,
        egress_digest=None,
        tools_digest=None,
        tenant_profile_digest=None,
        tenant_id="tenant-a",
    ):
        return IsolatedPolicyWorkerProfile(
            institution_id="bank-demo",
            tenant_id=tenant_id,
            worker_profile_version=version,
            worker_image_digest="3" * 64,
            service_account_id="regagentops-policy-worker",
            egress_policy_digest=egress_digest or self.egress.artifact_digest,
            tool_allowlist_policy_digest=tools_digest or self.tools.artifact_digest,
            tenant_isolation_profile_digest=tenant_profile_digest or self.tenant_profile.artifact_digest,
            network_namespace_isolated=True,
            run_as_non_root=True,
            read_only_root_filesystem=True,
            no_new_privileges=True,
            drop_all_linux_capabilities=True,
            seccomp_profile="RuntimeDefault",
            privileged=False,
            host_network=False,
            host_pid=False,
            host_ipc=False,
            direct_tool_invocation=False,
            registered_at=registered_at,
        )

    def make_release(self, release_id, version, created_at, *, worker_digest=None, commit="a" * 40, suffix="5"):
        return DeploymentReleaseManifest(
            institution_id="bank-demo",
            tenant_id="tenant-a",
            release_id=release_id,
            release_version=version,
            source_commit_sha=commit,
            artifact_name=f"regagentops-{version}-py3-none-any.whl",
            artifact_sha256=suffix * 64,
            worker_profile_digest=worker_digest or self.worker.artifact_digest,
            configuration_digest="6" * 64,
            codeql_evidence_digest="7" * 64,
            provenance_attestation_digest="8" * 64,
            checksum_manifest_digest="9" * 64,
            created_at=created_at,
        )

    def register_two_releases(self):
        old = self.make_release("release-080", "0.8.0", T1, suffix="a")
        new = self.make_release("release-090", "0.9.0", T2, suffix="b", commit="b" * 40)
        self.registry.register_release(old)
        self.registry.register_release(new)
        return old, new

    def test_egress_is_exact_tls_only_default_deny_and_rejects_wildcards(self):
        self.assertTrue(self.egress.default_deny)
        self.assertFalse(self.egress.allow_plaintext)
        with self.assertRaisesRegex(ValueError, "exact lowercase host"):
            self.make_egress(host="*.bank.example")
        with self.assertRaisesRegex(ValueError, "default deny"):
            replace(self.egress, default_deny=False)
        with self.assertRaisesRegex(ValueError, "forbid plaintext"):
            replace(self.egress, allow_plaintext=True)

    def test_egress_rejects_noncanonical_ip_aliases(self):
        with self.assertRaisesRegex(ValueError, "canonical textual form"):
            EgressDestination(
                destination_id="ipv6-alias",
                protocol=EgressProtocol.TLS,
                host="2001:0db8::1",
                port=443,
                purpose="Must not bypass exact endpoint identity by textual IPv6 aliasing",
                trust_policy_digest="a" * 64,
            )
        with self.assertRaisesRegex(ValueError, "canonical IP address"):
            EgressDestination(
                destination_id="ipv4-like-alias",
                protocol=EgressProtocol.TLS,
                host="010.0.0.1",
                port=443,
                purpose="IPv4-like numeric host must not fall through to hostname grammar",
                trust_policy_digest="b" * 64,
            )

    def test_tool_allowlist_is_default_deny_and_one_executor_per_tool(self):
        with self.assertRaisesRegex(ValueError, "default deny"):
            replace(self.tools, default_deny=False)
        with self.assertRaisesRegex(ValueError, "must not directly invoke"):
            replace(self.tools, direct_tool_invocation_allowed=True)
        duplicate = ToolDispatchBinding(
            governed_tool_id="mcp:payments:read",
            executor_id="executor-b",
            governance_binding_digest="a" * 64,
        )
        with self.assertRaisesRegex(ValueError, "only one executor"):
            replace(
                self.tools,
                bindings=tuple(
                    sorted(
                        self.tools.bindings + (duplicate,),
                        key=lambda item: (item.governed_tool_id, item.executor_id, item.governance_binding_digest),
                    )
                ),
            )

    def test_worker_profile_requires_hard_isolation_and_exact_current_policies(self):
        with self.assertRaisesRegex(ValueError, "run_as_non_root=true"):
            replace(self.worker, run_as_non_root=False)
        with self.assertRaisesRegex(ValueError, "direct_tool_invocation=false"):
            replace(self.worker, direct_tool_invocation=True)
        with self.assertRaisesRegex(ValueError, "RuntimeDefault"):
            replace(self.worker, seccomp_profile="Unconfined")

        egress_v2 = self.make_egress(version=2, registered_at=T1, host="kms2.bank.example")
        self.registry.register_egress_policy(egress_v2)
        stale_worker = self.make_worker(version=2, registered_at=T1)
        with self.assertRaisesRegex(ValueError, "current egress"):
            self.registry.register_worker_profile(stale_worker)

    def test_worker_profile_rejects_cross_tenant_policy_substitution(self):
        foreign = self.make_worker(tenant_id="tenant-b")
        with self.assertRaisesRegex(ValueError, "unknown tenant egress"):
            self.registry.register_worker_profile(foreign)

    def test_worker_profile_requires_exact_current_tenant_isolation(self):
        wrong = self.make_worker(tenant_profile_digest="f" * 64)
        with self.assertRaisesRegex(ValueError, "current tenant isolation"):
            self.registry.register_worker_profile(wrong)

    def test_worker_profile_cannot_predate_bound_policies(self):
        backdated = self.make_worker(version=2, registered_at=T_MINUS)
        with self.assertRaisesRegex(ValueError, "cannot predate its current deployment policies"):
            self.registry.register_worker_profile(backdated)

    def test_release_binds_codeql_provenance_checksum_and_strict_commit(self):
        release = self.make_release("release-080", "0.8.0", T1)
        self.registry.register_release(release)
        self.registry.assert_release_current(release)
        self.assertEqual(release.codeql_evidence_digest, "7" * 64)
        self.assertEqual(release.provenance_attestation_digest, "8" * 64)
        with self.assertRaisesRegex(ValueError, "40-character Git commit SHA"):
            replace(release, release_id="bad-commit", source_commit_sha="not-a-sha")
        with self.assertRaisesRegex(ValueError, "strict MAJOR.MINOR.PATCH"):
            replace(release, release_id="bad-version", release_version="v0.8")

    def test_release_cannot_predate_worker_profile(self):
        release = self.make_release("release-backdated", "0.8.0", T_MINUS)
        with self.assertRaisesRegex(ValueError, "cannot predate its worker profile"):
            self.registry.register_release(release)

    def test_release_versions_are_monotonic_and_immutable(self):
        old = self.make_release("release-080", "0.8.0", T1)
        self.registry.register_release(old)
        with self.assertRaisesRegex(ValueError, "increase monotonically"):
            self.registry.register_release(self.make_release("release-070", "0.7.0", T2, suffix="a"))
        with self.assertRaisesRegex(ValueError, "different content"):
            self.registry.register_release(replace(old, artifact_sha256="f" * 64))

    def test_new_release_registration_fails_closed_after_egress_drift(self):
        self.registry.register_egress_policy(self.make_egress(version=2, registered_at=T2, host="kms2.bank.example"))
        release = self.make_release("release-090", "0.9.0", T3, suffix="b", commit="b" * 40)
        with self.assertRaisesRegex(ValueError, "egress policy is stale"):
            self.registry.register_release(release)

    def test_exact_worker_and_release_retry_remain_idempotent_after_drift(self):
        release = self.make_release("release-080", "0.8.0", T1)
        self.registry.register_release(release)
        self.registry.register_egress_policy(self.make_egress(version=2, registered_at=T2, host="kms2.bank.example"))
        self.assertEqual(self.registry.register_worker_profile(self.worker), self.worker.artifact_digest)
        self.assertEqual(self.registry.register_release(release), release.artifact_digest)

    def test_release_currentness_fails_closed_after_egress_drift(self):
        release = self.make_release("release-080", "0.8.0", T1)
        self.registry.register_release(release)
        self.registry.assert_release_current(release)
        self.registry.register_egress_policy(self.make_egress(version=2, registered_at=T2, host="kms2.bank.example"))
        with self.assertRaisesRegex(ValueError, "egress policy is stale"):
            self.registry.assert_release_current(release)

    def test_release_currentness_fails_closed_after_tenant_isolation_drift(self):
        release = self.make_release("release-080", "0.8.0", T1)
        self.registry.register_release(release)
        self.registry.assert_release_current(release)

        rls_v2 = self.make_rls(version=2, registered_at=T2)
        self.tenant_registry.register_policy(rls_v2)
        profile_v2 = TenantIsolationProfile(
            institution_id="bank-demo",
            tenant_id="tenant-a",
            profile_version=2,
            environment=Environment.PRODUCTION,
            database_role="regagentops_worker",
            rls_policy_digests=(rls_v2.artifact_digest,),
            registered_at=T2,
        )
        self.tenant_registry.register_profile(profile_v2)
        with self.assertRaisesRegex(ValueError, "tenant isolation profile is stale"):
            self.registry.assert_release_current(release)

    def test_upgrade_requires_exact_reverse_rollback_and_newer_target(self):
        old, new = self.register_two_releases()
        rollback = RollbackPlan(
            institution_id="bank-demo",
            tenant_id="tenant-a",
            rollback_id="rollback-090-to-080",
            source_release_digest=new.artifact_digest,
            target_release_digest=old.artifact_digest,
            trigger_condition_digests=("c" * 64,),
            verification_procedure_digest="d" * 64,
            max_window_seconds=3600,
            created_at=T3,
        )
        self.registry.register_rollback(rollback)
        upgrade = UpgradePlan(
            institution_id="bank-demo",
            tenant_id="tenant-a",
            upgrade_id="upgrade-080-to-090",
            from_release_digest=old.artifact_digest,
            to_release_digest=new.artifact_digest,
            migration_plan_digest="e" * 64,
            preflight_check_digest="f" * 64,
            post_deploy_check_digest="1" * 64,
            rollback_plan_digest=rollback.artifact_digest,
            signed_configuration_change_digest="2" * 64,
            created_at=T4,
        )
        self.registry.register_upgrade(upgrade)

        wrong = replace(
            rollback,
            rollback_id="wrong-direction",
            source_release_digest=old.artifact_digest,
            target_release_digest=new.artifact_digest,
        )
        with self.assertRaisesRegex(ValueError, "older release"):
            self.registry.register_rollback(wrong)

    def test_upgrade_rejects_unrelated_rollback(self):
        old, new = self.register_two_releases()
        rollback = RollbackPlan(
            institution_id="bank-demo",
            tenant_id="tenant-a",
            rollback_id="rollback-090-to-080",
            source_release_digest=new.artifact_digest,
            target_release_digest=old.artifact_digest,
            trigger_condition_digests=("c" * 64,),
            verification_procedure_digest="d" * 64,
            max_window_seconds=3600,
            created_at=T3,
        )
        self.registry.register_rollback(rollback)
        unrelated = self.make_release("release-100", "1.0.0", T3, suffix="e", commit="c" * 40)
        self.registry.register_release(unrelated)
        bad_upgrade = UpgradePlan(
            institution_id="bank-demo",
            tenant_id="tenant-a",
            upgrade_id="upgrade-080-to-100",
            from_release_digest=old.artifact_digest,
            to_release_digest=unrelated.artifact_digest,
            migration_plan_digest="e" * 64,
            preflight_check_digest="f" * 64,
            post_deploy_check_digest="1" * 64,
            rollback_plan_digest=rollback.artifact_digest,
            signed_configuration_change_digest="2" * 64,
            created_at=T4,
        )
        with self.assertRaisesRegex(ValueError, "exactly reverse"):
            self.registry.register_upgrade(bad_upgrade)

    def test_recovery_checkpoint_binds_release_backup_anchor_and_restore_verification(self):
        release = self.make_release("release-080", "0.8.0", T1)
        self.registry.register_release(release)
        checkpoint = RecoveryCheckpoint(
            institution_id="bank-demo",
            tenant_id="tenant-a",
            checkpoint_id="checkpoint-1",
            release_digest=release.artifact_digest,
            configuration_digest="6" * 64,
            encrypted_backup_digest="a" * 64,
            audit_anchor_record_digest="b" * 64,
            restore_verification_digest="c" * 64,
            created_at=T2,
        )
        self.registry.register_recovery_checkpoint(checkpoint)
        with self.assertRaisesRegex(ValueError, "cannot predate"):
            self.registry.register_recovery_checkpoint(replace(checkpoint, checkpoint_id="checkpoint-old", created_at=T0))


if __name__ == "__main__":
    unittest.main()
