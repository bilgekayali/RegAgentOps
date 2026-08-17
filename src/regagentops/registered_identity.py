from __future__ import annotations

from typing import Any

from .identity_binding import HumanIdentityRegistry
from .identity_models import HumanIdentityAssertion, OidcVerifierConfig
from .oidc import OidcIdentityError, verify_oidc_identity


def verify_registered_oidc_identity(
    raw_token: str,
    *,
    config: OidcVerifierConfig,
    jwks: dict[str, Any],
    registry: HumanIdentityRegistry,
    human_owner_id: str,
    expected_nonce: str,
    now_epoch: int,
) -> HumanIdentityAssertion:
    registration = registry.get(config.institution_id, human_owner_id)
    if registration is None:
        raise OidcIdentityError("human owner has no registered OIDC identity")
    if registration.institution_id != config.institution_id:
        raise OidcIdentityError("human identity registration institution mismatch")
    if registration.provider_id != config.provider_id:
        raise OidcIdentityError("human identity registration provider mismatch")
    return verify_oidc_identity(
        raw_token,
        config=config,
        jwks=jwks,
        human_owner_id=registration.human_owner_id,
        expected_subject=registration.subject,
        expected_nonce=expected_nonce,
        now_epoch=now_epoch,
    )
