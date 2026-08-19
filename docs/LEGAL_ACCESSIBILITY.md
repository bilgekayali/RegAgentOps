# Legal, Regulatory and Accessibility Responsibility Scope

RegAgentOps v1 makes its responsibility boundary explicit. The software can structure governance evidence; it does not replace accountable institutional legal, compliance, privacy, accessibility, IAM or operational review.

## Structural non-claims

`LegalAccessibilityResponsibilityScope` requires all of the following to remain false:

- `legal_advice_provided`;
- `regulatory_compliance_determined`;
- `certification_claimed`; and
- `accessibility_conformance_claimed`.

The v1 baseline also retains explicit non-claims that RegAgentOps is not, by itself:

- an accessibility-conformance certification;
- an autonomous tool executor in the offline core;
- a certification or conformity-assessment body;
- proof that PostgreSQL RLS is correctly deployed and non-bypassable;
- proof that an external audit anchor is immutable;
- proof of actual KMS/HSM hardware custody;
- legal advice or a legal determination;
- a production-fitness guarantee; or
- a regulatory-compliance determination.

These non-claims are contract data, not only prose.

## Institution-owned reviews

Before production use, the responsible institution remains accountable for at least:

- legal review of the intended use and contracts;
- privacy and data-protection review;
- accessibility review of the actual user-facing deployment;
- records-retention and deletion obligations;
- jurisdiction-specific role and regulatory analysis;
- production IAM/service-account/secrets review; and
- any sector-specific supervisory or outsourcing requirements.

RegAgentOps assurance crosswalks may help organize evidence for these processes, but they do not determine that obligations are satisfied.

## Accessibility

The core package is primarily a Python library, JSON-contract set and CLI reference. Accessibility obligations arise in the concrete interfaces through which people use a deployment: web UI, operator console, documentation portal, approval experience, alerts, generated reports and other channels.

The repository does not claim conformance to WCAG or another accessibility standard merely because its core is non-visual or command-line based. Deployers should evaluate the actual human-facing product and provide appropriate alternatives, keyboard/navigation behavior, readable error states, semantic structure and assistive-technology support for their context.

## Legal and regulatory frameworks

NIST AI RMF, ISO/IEC 42001 and the EU AI Act are used by the assurance layer as evidence-reference namespaces under human-confirmed applicability. Their inclusion does not turn RegAgentOps into a legal rules engine, accredited certification service or automated conformity assessment.

## Evidence versus conclusion

A digest-bound artifact can prove what RegAgentOps represented and linked. It does not independently prove that an external actor told the truth, a regulator agrees with the interpretation, a production control was deployed correctly, or a human review was legally sufficient.
