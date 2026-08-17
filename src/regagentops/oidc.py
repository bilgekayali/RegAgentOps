from __future__ import annotations

import hashlib
from typing import Any

import jwt
from jwt import PyJWK

from .identity_models import HumanIdentityAssertion, OidcVerifierConfig, to_rfc3339_utc
from .models import digest_artifact

_MAX_TOKEN_BYTES = 65536
_MAX_JWKS_KEYS = 64
_FORBIDDEN_REMOTE_KEY_HEADERS = frozenset({"jku", "x5u", "crit"})


class OidcIdentityError(ValueError):
    pass


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _require_int_claim(claims: dict[str, Any], name: str) -> int:
    value = claims.get(name)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise OidcIdentityError(f"OIDC claim {name!r} must be a non-negative integer")
    return value


def _audiences(claims: dict[str, Any]) -> tuple[str, ...]:
    value = claims.get("aud")
    if isinstance(value, str) and value:
        return (value,)
    if isinstance(value, list) and value and all(isinstance(item, str) and item for item in value):
        result = tuple(value)
        if len(set(result)) != len(result):
            raise OidcIdentityError("OIDC aud claim must not contain duplicates")
        return result
    raise OidcIdentityError("OIDC aud claim must be a string or non-empty string list")


def _select_jwk(jwks: dict[str, Any], *, key_id: str, algorithm: str) -> dict[str, Any]:
    if not isinstance(jwks, dict) or set(jwks) - {"keys"}:
        raise OidcIdentityError("JWKS must be an object containing only the keys member")
    keys = jwks.get("keys")
    if not isinstance(keys, list) or not keys or len(keys) > _MAX_JWKS_KEYS:
        raise OidcIdentityError(f"JWKS keys must contain between 1 and {_MAX_JWKS_KEYS} entries")
    matches = [item for item in keys if isinstance(item, dict) and item.get("kid") == key_id]
    if len(matches) != 1:
        raise OidcIdentityError("OIDC key id must resolve to exactly one pinned JWK")
    jwk = matches[0]
    declared_alg = jwk.get("alg")
    if declared_alg is not None and declared_alg != algorithm:
        raise OidcIdentityError("JWK algorithm does not match token header algorithm")
    use = jwk.get("use")
    if use is not None and use != "sig":
        raise OidcIdentityError("JWK use must be sig when present")
    key_ops = jwk.get("key_ops")
    if key_ops is not None:
        if not isinstance(key_ops, list) or "verify" not in key_ops:
            raise OidcIdentityError("JWK key_ops must permit verify when present")
    return jwk


def verify_oidc_identity(
    raw_token: str,
    *,
    config: OidcVerifierConfig,
    jwks: dict[str, Any],
    human_owner_id: str,
    expected_subject: str,
    expected_nonce: str,
    now_epoch: int,
) -> HumanIdentityAssertion:
    """Verify one OIDC ID token entirely offline against a pinned JWKS document.

    The raw token and nonce are consumed only for verification. Returned artifacts retain
    digests, never the bearer token or raw nonce.
    """
    if not isinstance(raw_token, str) or not raw_token or len(raw_token.encode("utf-8")) > _MAX_TOKEN_BYTES:
        raise OidcIdentityError("raw_token must be non-empty and bounded")
    if not isinstance(expected_nonce, str) or not expected_nonce or len(expected_nonce) > 512:
        raise OidcIdentityError("expected_nonce must be non-empty bounded text")
    if not isinstance(expected_subject, str) or not expected_subject or len(expected_subject) > 256:
        raise OidcIdentityError("expected_subject must be non-empty bounded text")
    if not isinstance(human_owner_id, str) or not human_owner_id or len(human_owner_id) > 256:
        raise OidcIdentityError("human_owner_id must be non-empty bounded text")
    if not isinstance(now_epoch, int) or isinstance(now_epoch, bool) or now_epoch < 0:
        raise OidcIdentityError("now_epoch must be a non-negative integer")

    try:
        header = jwt.get_unverified_header(raw_token)
    except jwt.PyJWTError as exc:
        raise OidcIdentityError("OIDC token header is invalid") from exc
    if not isinstance(header, dict):
        raise OidcIdentityError("OIDC token header must be an object")
    if _FORBIDDEN_REMOTE_KEY_HEADERS & set(header):
        raise OidcIdentityError("remote/dynamic key-selection JWT headers are forbidden")
    key_id = header.get("kid")
    algorithm = header.get("alg")
    if not isinstance(key_id, str) or not key_id or len(key_id) > 256:
        raise OidcIdentityError("OIDC token must contain a bounded kid header")
    if algorithm not in config.allowed_algorithms:
        raise OidcIdentityError("OIDC token algorithm is not allowed by provider configuration")

    jwk = _select_jwk(jwks, key_id=key_id, algorithm=algorithm)
    try:
        verification_key = PyJWK.from_dict(jwk, algorithm=algorithm).key
        claims = jwt.decode(
            raw_token,
            key=verification_key,
            algorithms=[algorithm],
            issuer=config.issuer,
            audience=config.client_id,
            options={
                "require": ["iss", "sub", "aud", "exp", "iat", "nonce"],
                "verify_exp": False,
                "verify_iat": False,
                "verify_nbf": False,
            },
        )
    except (jwt.PyJWTError, ValueError, TypeError) as exc:
        raise OidcIdentityError("OIDC token signature or registered claims are invalid") from exc
    if not isinstance(claims, dict):
        raise OidcIdentityError("OIDC claims must decode to an object")

    subject = claims.get("sub")
    nonce = claims.get("nonce")
    if subject != expected_subject:
        raise OidcIdentityError("OIDC subject does not match the registered human identity")
    if nonce != expected_nonce:
        raise OidcIdentityError("OIDC nonce does not match the authorization transaction")

    audiences = _audiences(claims)
    if config.client_id not in audiences:
        raise OidcIdentityError("OIDC audience does not include the configured client id")
    if len(audiences) > 1 and claims.get("azp") != config.client_id:
        raise OidcIdentityError("multi-audience OIDC token requires azp equal to the configured client id")

    issued_at = _require_int_claim(claims, "iat")
    expires_at = _require_int_claim(claims, "exp")
    if expires_at <= issued_at:
        raise OidcIdentityError("OIDC exp must be after iat")
    if issued_at > now_epoch:
        raise OidcIdentityError("OIDC token was issued in the future")
    if now_epoch - issued_at > config.max_token_age_seconds:
        raise OidcIdentityError("OIDC token exceeds configured maximum token age")
    if expires_at <= now_epoch:
        raise OidcIdentityError("OIDC token is expired")
    nbf = claims.get("nbf")
    if nbf is not None:
        if not isinstance(nbf, int) or isinstance(nbf, bool) or nbf < 0 or nbf > now_epoch:
            raise OidcIdentityError("OIDC token is not yet valid")

    acr = claims.get("acr")
    if acr is not None and (not isinstance(acr, str) or not acr or len(acr) > 256):
        raise OidcIdentityError("OIDC acr claim must be bounded text when present")
    if config.required_acr_values and acr not in config.required_acr_values:
        raise OidcIdentityError("OIDC acr does not satisfy the configured assurance requirement")

    auth_time_claim = claims.get("auth_time")
    auth_time: str | None = None
    if auth_time_claim is not None:
        if not isinstance(auth_time_claim, int) or isinstance(auth_time_claim, bool) or auth_time_claim < 0:
            raise OidcIdentityError("OIDC auth_time must be a non-negative integer when present")
        if auth_time_claim > now_epoch:
            raise OidcIdentityError("OIDC auth_time cannot be in the future")
        auth_time = to_rfc3339_utc(auth_time_claim)

    return HumanIdentityAssertion(
        institution_id=config.institution_id,
        provider_id=config.provider_id,
        human_owner_id=human_owner_id,
        issuer=config.issuer,
        subject=expected_subject,
        audiences=audiences,
        client_id=config.client_id,
        key_id=key_id,
        algorithm=algorithm,
        token_digest=_sha256_text(raw_token),
        claims_digest=digest_artifact(claims),
        nonce_digest=_sha256_text(expected_nonce),
        jwks_digest=digest_artifact(jwks),
        provider_config_digest=config.artifact_digest,
        issued_at=to_rfc3339_utc(issued_at),
        expires_at=to_rfc3339_utc(expires_at),
        auth_time=auth_time,
        acr=acr,
    )
