# Security Policy

## Supported versions

RegAgentOps is pre-1.0. Security fixes are applied to the current development line unless a release note states otherwise.

## Reporting a vulnerability

Please use GitHub's **Private vulnerability reporting / Security Advisories** for this repository when available. Do not publish exploitable details in a public issue before coordinated disclosure.

A useful report includes:

- affected commit or release;
- impacted authorization or trust boundary;
- minimal reproduction steps;
- expected vs. observed fail-closed behavior;
- whether the issue crosses institution, identity, policy, or tool/action boundaries.

## Scope

High-priority issues include authorization bypass, cross-tenant policy confusion, artifact-digest ambiguity, decision tampering, identity substitution, unsafe default behavior, or capability creep that introduces hidden execution/network behavior into an offline core.

RegAgentOps v0.1 does not itself execute tools or hold production credentials. Reports about future adapters should identify the specific adapter/release where that capability exists.
