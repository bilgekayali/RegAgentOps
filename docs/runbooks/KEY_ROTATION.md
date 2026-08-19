# KMS/HSM Key Rotation Runbook

## Scope

Use this runbook for scheduled rotation, emergency replacement or retirement of v0.8 KMS/HSM-backed configuration-signing and evidence-encryption key references. Private and symmetric key material must remain inside the institution's KMS/HSM boundary; RegAgentOps stores references, public verification material where applicable and append-only lifecycle evidence only.

## Planned rotation

1. Create a new institution/tenant/purpose-scoped KMS/HSM key under the institution's approved custody and IAM controls.
2. Register a new contiguous `InstitutionCryptoKeyReference` with a distinct `key_id`, correct purpose/algorithm and validity interval. Do not embed private or symmetric key bytes.
3. Verify that the new key is `ACTIVE` and valid at the exact time of any new signing or encryption operation.
4. Update dependent configuration through a v0.8 signed configuration change. The change must bind the exact previous/proposed configuration digests, signing-key reference and prior change-chain digest.
5. For evidence encryption, begin creating new envelopes only with the new active key reference. RegAgentOps generates the AES-GCM nonce for the public encryption path; integrations must not reintroduce caller-selected nonce reuse.
6. Validate decrypt/read paths for historical data before retiring the old key.
7. Append a lifecycle transition for the old key from `ACTIVE` to `RETIRED`. Retirement stops new cryptographic artefacts while allowing historical verification/decryption where the key remains available and policy permits.
8. Anchor the rotation/change evidence externally and update deployment configuration digests as required.

## Emergency compromise

For suspected compromise, transition the affected key to `DISABLED` rather than `RETIRED`. A disabled key must not be used for new operations and historical verification/decryption through the v0.8 registry is intentionally rejected. Preserve incident evidence and follow institutional forensic/key-recovery procedures before deciding how historical encrypted material will be handled.

Never reactivate a `RETIRED` or `DISABLED` key reference. A replacement always receives a new key reference/version and distinct `key_id`.

## Validation

Confirm that tenant and purpose bindings are unchanged, new key validity is correct, configuration-change signatures validate, current worker/release configuration points to the intended references, and no stale release remains eligible under `assert_release_current()` if its worker/egress/tool dependencies changed during rotation.

## Evidence to retain

Retain KMS/HSM provider key identifiers, lifecycle-state digests, signed configuration-change digests, effective timestamps, operator/change-ticket evidence, affected release/configuration digests, test results and external audit-anchor records. Provider attestation and hardware-custody claims remain external evidence and are not inferred by RegAgentOps.
