from __future__ import annotations

import base64
from dataclasses import replace
import hashlib
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import test_mcp as mcp_test_module

from regagentops.approval_engine import ApprovalGate
from regagentops.approval_models import ApprovalEscalationPolicy, ApprovalResolution
from regagentops.execution import (
    EmergencyStopRegistry,
    EmergencyStopState,
    ExecutionGate,
    ExecutionLeaseConsumption,
    ExecutionLeaseLedger,
    ExecutionOutcome,
    ExecutionReceiptSignatureError,
    ExecutionTrustBundle,
    ExecutionTrustKey,
    sign_tool_execution_receipt,
    verify_signed_tool_execution_receipt,
)
from regagentops.models import Decision, RiskTier

NOW = "2026-01-01T00:05:00Z"
EXECUTOR = "executor-1"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class _ExecutionSigner:
    institution_id = "bank-demo"
    executor_id = EXECUTOR
    key_id = "executor-key-1"
    algorithm = "Ed25519"

    def __init__(self) -> None:
        self.private_key = Ed25519PrivateKey.generate()

    def sign(self, message: bytes) -> bytes:
        return self.private_key.sign(message)

    def trust_bundle(self) -> ExecutionTrustBundle:
        public = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return ExecutionTrustBundle(
            institution_id=self.institution_id,
            keys=(
                ExecutionTrustKey(
                    institution_id=self.institution_id,
                    executor_id=self.executor_id,
                    key_id=self.key_id,
                    public_key_base64url=_b64(public),
                    not_before="2026-01-01T00:00:00Z",
                    not_after="2026-01-02T00:00:00Z",
                ),
            ),
        )


class ExecutionBoundaryTests(unittest.TestCase):
    def _allowed_stack(self):
        case = mcp_test_module.McpGovernanceTests()
        identity, registry, server, descriptor, snapshot, binding = case._stack()
        request = case._request(binding)
        outcome = case._pep(identity, registry).evaluate(
            request,
            case._policy(binding),
            identity.signed_identity(),
            identity_trust_bundle=identity.trust,
            evaluated_at=NOW,
        )
        stops = EmergencyStopRegistry()
        stops.register(
            EmergencyStopState(
                institution_id="bank-demo",
                state_version=1,
                halted=False,
                reason_digest=None,
                effective_at="2026-01-01T00:04:50Z",
            )
        )
        ledger = ExecutionLeaseLedger()
        gate = ExecutionGate(registry, stops, ledger)
        return case, identity, registry, server, descriptor, snapshot, binding, request, outcome, stops, ledger, gate

    def _lease(self, gate, outcome, *, lease_id="lease-1"):
        return gate.issue_lease(
            outcome,
            lease_id=lease_id,
            executor_id=EXECUTOR,
            issued_at="2026-01-01T00:05:01Z",
            expires_at="2026-01-01T00:06:01Z",
        )

    def _lease_and_consumption(self):
        stack = self._allowed_stack()
        outcome, gate = stack[8], stack[11]
        lease = self._lease(gate, outcome)
        consumption = gate.redeem_lease(
            lease,
            outcome,
            executor_id=EXECUTOR,
            consumed_at="2026-01-01T00:05:02Z",
        )
        return stack, lease, consumption

    def test_exact_lease_result_receipt_and_signature_round_trip(self):
        stack, lease, consumption = self._lease_and_consumption()
        request, outcome, gate = stack[7], stack[8], stack[11]
        receipt = gate.build_receipt(
            request,
            outcome,
            lease,
            consumption,
            receipt_id="receipt-1",
            executor_id=EXECUTOR,
            result_digest=_digest("tool-result-v1"),
            execution_outcome=ExecutionOutcome.SUCCEEDED,
            started_at="2026-01-01T00:05:02Z",
            completed_at="2026-01-01T00:05:03Z",
        )
        self.assertEqual(lease.executor_id, EXECUTOR)
        self.assertEqual(consumption.executor_id, EXECUTOR)
        self.assertEqual(receipt.executor_id, EXECUTOR)
        self.assertEqual(receipt.request_digest, request.artifact_digest)
        self.assertEqual(receipt.input_digest, request.input_digest)
        self.assertEqual(receipt.execution_lease_digest, lease.artifact_digest)
        self.assertEqual(receipt.lease_consumption_digest, consumption.artifact_digest)
        self.assertEqual(receipt.mcp_policy_enforcement_result_digest, outcome.result.artifact_digest)
        self.assertEqual(receipt.authenticated_authorization_digest, outcome.authorization.artifact_digest)
        self.assertEqual(receipt.policy_decision_digest, outcome.authorization.authorization.decision_digest)
        self.assertEqual(receipt.policy_decision, Decision.ALLOW)

        signer = _ExecutionSigner()
        signed = sign_tool_execution_receipt(receipt, signer=signer)
        verified = verify_signed_tool_execution_receipt(
            signed,
            trust_bundle=signer.trust_bundle(),
            now="2026-01-01T00:05:10Z",
        )
        self.assertEqual(verified.artifact_digest, receipt.artifact_digest)

    def test_execution_lease_is_atomic_and_one_time(self):
        stack = self._allowed_stack()
        outcome, gate, ledger = stack[8], stack[11], stack[10]
        lease = self._lease(gate, outcome, lease_id="lease-once")
        gate.redeem_lease(
            lease,
            outcome,
            executor_id=EXECUTOR,
            consumed_at="2026-01-01T00:05:02Z",
        )
        with self.assertRaisesRegex(ValueError, "already been consumed"):
            gate.redeem_lease(
                lease,
                outcome,
                executor_id=EXECUTOR,
                consumed_at="2026-01-01T00:05:03Z",
            )
        self.assertEqual(ledger.consumption_count(), 1)

    def test_executor_binding_prevents_lease_and_receipt_substitution(self):
        stack = self._allowed_stack()
        request, outcome, gate = stack[7], stack[8], stack[11]
        lease = self._lease(gate, outcome, lease_id="lease-executor-bound")
        with self.assertRaisesRegex(ValueError, "different executor"):
            gate.redeem_lease(
                lease,
                outcome,
                executor_id="executor-2",
                consumed_at="2026-01-01T00:05:02Z",
            )
        consumption = gate.redeem_lease(
            lease,
            outcome,
            executor_id=EXECUTOR,
            consumed_at="2026-01-01T00:05:02Z",
        )
        with self.assertRaisesRegex(ValueError, "executor does not match"):
            gate.build_receipt(
                request,
                outcome,
                lease,
                consumption,
                receipt_id="receipt-wrong-executor",
                executor_id="executor-2",
                result_digest=_digest("result"),
                execution_outcome=ExecutionOutcome.SUCCEEDED,
                started_at="2026-01-01T00:05:02Z",
                completed_at="2026-01-01T00:05:03Z",
            )

    def test_unrecorded_consumption_cannot_produce_receipt(self):
        stack = self._allowed_stack()
        request, outcome, gate = stack[7], stack[8], stack[11]
        lease = self._lease(gate, outcome, lease_id="lease-unrecorded")
        forged = ExecutionLeaseConsumption(
            institution_id=lease.institution_id,
            executor_id=lease.executor_id,
            lease_digest=lease.artifact_digest,
            request_digest=lease.request_digest,
            mcp_registry_snapshot_digest=lease.mcp_registry_snapshot_digest,
            emergency_stop_state_digest=lease.emergency_stop_state_digest,
            consumed_at="2026-01-01T00:05:02Z",
        )
        with self.assertRaisesRegex(ValueError, "not recorded"):
            gate.build_receipt(
                request,
                outcome,
                lease,
                forged,
                receipt_id="receipt-forged-consumption",
                executor_id=EXECUTOR,
                result_digest=_digest("result"),
                execution_outcome=ExecutionOutcome.SUCCEEDED,
                started_at="2026-01-01T00:05:02Z",
                completed_at="2026-01-01T00:05:03Z",
            )

    def test_approval_required_execution_binds_fresh_requirement_and_resolution(self):
        case = mcp_test_module.McpGovernanceTests()
        identity, registry, _, _, _, binding = case._stack()
        request = case._request(binding, risk=RiskTier.HIGH)
        outcome = case._pep(identity, registry).evaluate(
            request,
            case._policy(binding, effect=Decision.REQUIRE_HUMAN_APPROVAL, risk=RiskTier.HIGH),
            identity.signed_identity(),
            identity_trust_bundle=identity.trust,
            evaluated_at=NOW,
        )
        requirement = ApprovalGate.build_requirement(
            request,
            outcome.authorization,
            escalation_policy=ApprovalEscalationPolicy("bank-demo"),
            issued_at=NOW,
        )
        self.assertIsNotNone(requirement)
        resolution = ApprovalResolution(
            institution_id="bank-demo",
            requirement_digest=requirement.artifact_digest,
            request_digest=request.artifact_digest,
            approval_package_digest=_digest("approval-package"),
            approval_satisfied=True,
            replay_consumed=True,
            approved_by=("approver-1",),
            denied_by=(),
            reason_codes=("approval_satisfied",),
            authorization_continuation_permitted=True,
            evaluated_at="2026-01-01T00:05:01Z",
        )
        stops = EmergencyStopRegistry()
        stops.register(EmergencyStopState("bank-demo", 1, False, None, "2026-01-01T00:04:50Z"))
        gate = ExecutionGate(registry, stops, ExecutionLeaseLedger())
        with self.assertRaisesRegex(ValueError, "exact requirement and resolution"):
            gate.issue_lease(
                outcome,
                lease_id="approval-missing",
                executor_id=EXECUTOR,
                issued_at="2026-01-01T00:05:02Z",
                expires_at="2026-01-01T00:06:02Z",
            )
        lease = gate.issue_lease(
            outcome,
            lease_id="approval-bound",
            executor_id=EXECUTOR,
            issued_at="2026-01-01T00:05:02Z",
            expires_at="2026-01-01T00:06:02Z",
            approval_requirement=requirement,
            approval_resolution=resolution,
        )
        self.assertEqual(lease.approval_requirement_digest, requirement.artifact_digest)
        self.assertEqual(lease.approval_resolution_digest, resolution.artifact_digest)

        wrong_requirement = replace(requirement, authenticated_authorization_digest=_digest("wrong-authorization"))
        wrong_resolution = replace(resolution, requirement_digest=wrong_requirement.artifact_digest)
        with self.assertRaisesRegex(ValueError, "authorization mismatch"):
            gate.issue_lease(
                outcome,
                lease_id="approval-wrong-auth",
                executor_id=EXECUTOR,
                issued_at="2026-01-01T00:05:02Z",
                expires_at="2026-01-01T00:06:02Z",
                approval_requirement=wrong_requirement,
                approval_resolution=wrong_resolution,
            )

        expired_requirement = replace(requirement, expires_at="2026-01-01T00:05:02Z")
        expired_resolution = replace(
            resolution,
            requirement_digest=expired_requirement.artifact_digest,
            evaluated_at="2026-01-01T00:05:01Z",
        )
        with self.assertRaisesRegex(ValueError, "expired or not yet valid"):
            gate.issue_lease(
                outcome,
                lease_id="approval-expired",
                executor_id=EXECUTOR,
                issued_at="2026-01-01T00:05:02Z",
                expires_at="2026-01-01T00:06:02Z",
                approval_requirement=expired_requirement,
                approval_resolution=expired_resolution,
            )

    def test_stale_authenticated_authorization_cannot_issue_fresh_lease(self):
        stack = self._allowed_stack()
        outcome, gate = stack[8], stack[11]
        with self.assertRaisesRegex(ValueError, "too old"):
            gate.issue_lease(
                outcome,
                lease_id="stale-authorization",
                executor_id=EXECUTOR,
                issued_at="2026-01-01T00:07:01Z",
                expires_at="2026-01-01T00:08:01Z",
            )

    def test_emergency_stop_blocks_issue_and_state_drift_invalidates_existing_lease(self):
        stack = self._allowed_stack()
        outcome, stops, gate = stack[8], stack[9], stack[11]
        lease = self._lease(gate, outcome, lease_id="lease-before-stop")
        stops.register(
            EmergencyStopState(
                institution_id="bank-demo",
                state_version=2,
                halted=True,
                reason_digest=_digest("incident-1"),
                effective_at="2026-01-01T00:05:02Z",
            )
        )
        with self.assertRaisesRegex(ValueError, "emergency stop is active"):
            gate.redeem_lease(
                lease,
                outcome,
                executor_id=EXECUTOR,
                consumed_at="2026-01-01T00:05:03Z",
            )
        with self.assertRaisesRegex(ValueError, "emergency stop is active"):
            gate.issue_lease(
                outcome,
                lease_id="lease-during-stop",
                executor_id=EXECUTOR,
                issued_at="2026-01-01T00:05:03Z",
                expires_at="2026-01-01T00:06:03Z",
            )

    def test_mcp_governance_drift_invalidates_lease_before_redemption(self):
        stack = self._allowed_stack()
        registry, server, outcome, gate = stack[2], stack[3], stack[8], stack[11]
        lease = self._lease(gate, outcome, lease_id="lease-before-mcp-drift")
        registry.register_server(
            replace(
                server,
                server_version=2,
                approved=False,
                metadata_digest=_digest("revoked-after-authorization"),
                registered_at="2026-01-01T00:05:02Z",
            )
        )
        with self.assertRaisesRegex(ValueError, "MCP governance state changed"):
            gate.redeem_lease(
                lease,
                outcome,
                executor_id=EXECUTOR,
                consumed_at="2026-01-01T00:05:03Z",
            )

    def test_result_digest_tampering_breaks_signed_receipt_verification(self):
        stack, lease, consumption = self._lease_and_consumption()
        request, outcome, gate = stack[7], stack[8], stack[11]
        receipt = gate.build_receipt(
            request,
            outcome,
            lease,
            consumption,
            receipt_id="receipt-tamper",
            executor_id=EXECUTOR,
            result_digest=_digest("original-result"),
            execution_outcome=ExecutionOutcome.SUCCEEDED,
            started_at="2026-01-01T00:05:02Z",
            completed_at="2026-01-01T00:05:03Z",
        )
        signer = _ExecutionSigner()
        signed = sign_tool_execution_receipt(receipt, signer=signer)
        tampered = replace(signed, receipt=replace(receipt, result_digest=_digest("tampered-result")))
        with self.assertRaises(ExecutionReceiptSignatureError):
            verify_signed_tool_execution_receipt(
                tampered,
                trust_bundle=signer.trust_bundle(),
                now="2026-01-01T00:05:10Z",
            )

    def test_historical_receipt_remains_verifiable_after_key_validity_window(self):
        stack, lease, consumption = self._lease_and_consumption()
        request, outcome, gate = stack[7], stack[8], stack[11]
        receipt = gate.build_receipt(
            request,
            outcome,
            lease,
            consumption,
            receipt_id="receipt-historical",
            executor_id=EXECUTOR,
            result_digest=_digest("historical-result"),
            execution_outcome=ExecutionOutcome.SUCCEEDED,
            started_at="2026-01-01T00:05:02Z",
            completed_at="2026-01-01T00:05:03Z",
        )
        signer = _ExecutionSigner()
        signed = sign_tool_execution_receipt(receipt, signer=signer)
        verified = verify_signed_tool_execution_receipt(
            signed,
            trust_bundle=signer.trust_bundle(),
            now="2026-01-03T00:00:00Z",
        )
        self.assertEqual(verified.artifact_digest, receipt.artifact_digest)

    def test_expired_lease_cannot_be_redeemed(self):
        stack = self._allowed_stack()
        outcome, gate = stack[8], stack[11]
        lease = gate.issue_lease(
            outcome,
            lease_id="lease-expired",
            executor_id=EXECUTOR,
            issued_at="2026-01-01T00:05:01Z",
            expires_at="2026-01-01T00:05:03Z",
        )
        with self.assertRaisesRegex(ValueError, "expired or not yet valid"):
            gate.redeem_lease(
                lease,
                outcome,
                executor_id=EXECUTOR,
                consumed_at="2026-01-01T00:05:03Z",
            )


if __name__ == "__main__":
    unittest.main()