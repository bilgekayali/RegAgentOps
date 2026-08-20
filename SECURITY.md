# Security Policy

## Supported versions

RegAgentOps v1 defines the stable public API/CLI/JSON compatibility boundary. Security fixes are applied to the current supported 1.x line unless a release note states otherwise.

The compatibility policy does not require preserving behavior that creates or materially enables an authorization, identity, approval, tenant-isolation, cryptographic, execution or release-integrity bypass. A fail-closed security correction may therefore tighten behavior in a patch release when preserving the vulnerable behavior would be unsafe.

Pre-1.0 releases are historical development baselines and do not receive the v1 public compatibility guarantee.

## Reporting a vulnerability

Please use GitHub's **Private vulnerability reporting / Security Advisories** for this repository when available. Do not publish exploitable details in a public issue before coordinated disclosure.

A useful report includes:

- affected commit or release;
- impacted authorization or trust boundary;
- minimal reproduction steps;
- expected vs. observed fail-closed behavior;
- whether the issue crosses institution, tenant, identity, policy, approval, MCP, data-purpose, execution, cryptographic or release boundaries; and
- whether the issue affects the stable `regagentops.api`, CLI or JSON compatibility surface.

## High-priority scope

High-priority issues include:

- authorization bypass or precedence inversion;
- cross-institution or cross-tenant policy/data/evidence confusion;
- identity, workload, approver or executor substitution;
- approval delegation/replay bypass;
- stale or unapproved MCP server/tool use;
- one-time execution-lease replay or receipt forgery/substitution;
- data-purpose/category/retention under-enforcement;
- key-lifecycle, AES-GCM AAD/nonce or configuration-chain failures;
- PostgreSQL RLS reference injection or tenant-profile substitution;
- default-deny egress/tool-allowlist bypass;
- release/provenance/checksum or upgrade/rollback evidence substitution;
- stable baseline bypass of independent-review requirements; and
- capability creep that introduces hidden network, shell, deployment or tool-execution behavior into an offline/reference core.

## Reference boundary

RegAgentOps defines governance and production-reference contracts but does not itself deploy workloads, install PostgreSQL RLS, manage KMS/HSM services, invoke enterprise tools, verify external infrastructure truthfulness or guarantee production fitness.

Reports about an external adapter or deployment should identify the specific adapter/release and distinguish a RegAgentOps contract failure from a platform configuration failure when possible.

## Stable release review

The `v1.0.0` tagged-release path requires a completed independent security-review artifact or explicit item-level accountable-human risk acceptance. Repository/PR approval alone is not silently reinterpreted as security-risk acceptance.

See `docs/SECURITY_REVIEW.md` and `security-review/README.md`.
