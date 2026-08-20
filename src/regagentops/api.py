"""Stable RegAgentOps v1 public Python API.

Only symbols exported through this module are covered by the v1 semantic-versioning
compatibility policy. Internal modules remain importable but are not part of the
stable public Python surface unless re-exported here.
"""

from .deployment import (
    DeploymentReleaseManifest,
    EgressPolicy,
    IsolatedPolicyWorkerProfile,
    ProductionDeploymentRegistry,
    RecoveryCheckpoint,
    RollbackPlan,
    ToolAllowlistPolicy,
    UpgradePlan,
)
from .models import (
    AgentActionEnvelope,
    AgentDescriptor,
    AuthorizationDecision,
    DataClassification,
    Decision,
    Environment,
    RiskTier,
    ToolActionDescriptor,
    canonical_json,
    digest_artifact,
)
from .policy import PolicyBundle, PolicyEngine, PolicyRule
from .registry import AgentRegistry, ToolRegistry
from .stability import (
    BoundaryEvidenceReference,
    GovernanceBoundary,
    IndependentSecurityReviewChecklist,
    LegalAccessibilityResponsibilityScope,
    PublicSurfaceManifest,
    SecurityReviewItem,
    SecurityReviewStatus,
    StableCompatibilityPolicy,
    StableReleaseBaseline,
    StableReleaseRegistry,
    SupportedUpgradePath,
)

# Keep this tuple sorted. Tests and the v1 contract snapshot pin it exactly.
__all__ = (
    "AgentActionEnvelope",
    "AgentDescriptor",
    "AgentRegistry",
    "AuthorizationDecision",
    "BoundaryEvidenceReference",
    "DataClassification",
    "Decision",
    "DeploymentReleaseManifest",
    "EgressPolicy",
    "Environment",
    "GovernanceBoundary",
    "IndependentSecurityReviewChecklist",
    "IsolatedPolicyWorkerProfile",
    "LegalAccessibilityResponsibilityScope",
    "PolicyBundle",
    "PolicyEngine",
    "PolicyRule",
    "ProductionDeploymentRegistry",
    "PublicSurfaceManifest",
    "RecoveryCheckpoint",
    "RiskTier",
    "RollbackPlan",
    "SecurityReviewItem",
    "SecurityReviewStatus",
    "StableCompatibilityPolicy",
    "StableReleaseBaseline",
    "StableReleaseRegistry",
    "SupportedUpgradePath",
    "ToolActionDescriptor",
    "ToolAllowlistPolicy",
    "ToolRegistry",
    "UpgradePlan",
    "canonical_json",
    "digest_artifact",
)
