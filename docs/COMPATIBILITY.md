# v1 Compatibility Policy

RegAgentOps 1.x introduces an explicit public compatibility boundary. Stability applies to the surfaces named below; it is not a promise that every internal module, implementation detail, private helper, test fixture or documentation sentence will remain unchanged.

## Stable Python API

The stable Python surface is **only** the symbols re-exported by `regagentops.api` and pinned in `compatibility/v1-public-api.json`.

Internal modules remain importable for transparency and advanced use, but importing directly from modules such as `regagentops.execution`, `regagentops.hardening` or `regagentops.deployment` does not by itself place that symbol inside the 1.x public compatibility guarantee unless the symbol is also exported by `regagentops.api`.

Within major version 1:

- removing a stable `regagentops.api` symbol is a breaking change and requires a new major version;
- changing a stable symbol so that accepted valid v1 inputs become invalid or represented semantics materially change is treated as breaking unless the change fixes an unsafe behavior that cannot reasonably be preserved;
- additive symbols may be introduced in a minor release;
- a planned public removal must remain deprecated for at least two minor releases before a future major removes it.

Security fixes remain fail-closed. The compatibility policy does not require preserving behavior that creates an authorization, identity, approval, tenant, cryptographic or execution bypass.

## Stable CLI

The v1 stable CLI commands are pinned in `compatibility/v1-public-api.json`:

- `regagentops contract-snapshot`
- `regagentops demo-decision`

Removing a stable command or changing its represented purpose incompatibly requires a new major version. Additive commands and additive output fields may be introduced in a minor release when existing documented fields retain their meaning.

`contract-snapshot` is the machine-readable runtime statement of the stable package version, Python API symbols, CLI commands and JSON compatibility-baseline identifier. It is offline and non-executing.

## Stable JSON contracts

`compatibility/v1-schema-baseline.json` pins every schema filename and `schema_version` discriminator that exists at the v1 baseline. Within major version 1:

- a baseline schema file must not disappear;
- its baseline `schema_version` discriminator must not change;
- required-field removal, enum-value removal or reinterpretation of an existing valid field is breaking;
- all baseline schemas continue to reject unknown properties through `additionalProperties: false`;
- new schemas may be added in a minor release without changing baseline discriminators.

When a genuinely incompatible contract is required, a new discriminator and a new major compatibility decision are required rather than silently mutating the existing v1 contract.

## Semantic versioning

RegAgentOps uses `MAJOR.MINOR.PATCH` semantics for the stable public boundary:

- **MAJOR**: incompatible public API/CLI/JSON contract changes;
- **MINOR**: backwards-compatible public functionality or new contract surfaces;
- **PATCH**: backwards-compatible fixes, including fail-closed security corrections.

The version policy does not convert RegAgentOps into a hosted service SLA, vendor support contract or regulatory certification program.

## Baseline enforcement

CI compares runtime `regagentops.api.__all__`, CLI contract output and schema discriminators against the committed compatibility baselines. The dedicated Stable Governance Reference Boundary repeats these checks independently of the generic test job.
