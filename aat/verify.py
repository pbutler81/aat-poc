import base64

import jwt

from aat.attenuation import hash_token, is_attenuation
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)


def jwk_to_public_key(jwk):
    if jwk["kty"] != "OKP":
        raise ValueError("Unsupported key type")

    if jwk["crv"] != "Ed25519":
        raise ValueError("Unsupported curve")

    x = jwk["x"]

    padding = "=" * (-len(x) % 4)

    raw = base64.urlsafe_b64decode(
        x + padding
    )

    return Ed25519PublicKey.from_public_bytes(raw)


def verify_token(token, issuer_public_key):
    return jwt.decode(
        token,
        issuer_public_key,
        algorithms=["EdDSA"],
        options={
            "require": [
                "iss",
                "sub",
                "jti",
                "iat",
                "exp",
                "cnf",
                "authorization_details",
            ]
        },
    )


def verify_child_token(
    parent_token,
    parent_payload,
    child_token,
):
    """
    Verify a delegated child token.

    Checks:

    1. Child is signed by the holder of the parent.
    2. Child references the actual parent token.
    3. Child capabilities are a subset of parent capabilities.
    """

    # ---------------------------------------------------------
    # 1. Determine who holds the parent token
    # ---------------------------------------------------------

    parent_holder_jwk = parent_payload["cnf"]["jwk"]

    parent_holder_key = jwk_to_public_key(
        parent_holder_jwk
    )

    # ---------------------------------------------------------
    # 2. Verify the child's signature
    # ---------------------------------------------------------

    child_payload = jwt.decode(
        child_token,
        parent_holder_key,
        algorithms=["EdDSA"],
        options={
            "require": [
                "iss",
                "sub",
                "jti",
                "iat",
                "exp",
                "cnf",
                "authorization_details",
                "parent",
            ]
        },
    )

    # ---------------------------------------------------------
    # 3. Verify parent binding
    # ---------------------------------------------------------

    expected_parent_hash = hash_token(parent_token)

    actual_parent_hash = child_payload["parent"]

    if actual_parent_hash != expected_parent_hash:
        raise ValueError(
            "Child token does not reference the supplied parent token"
        )

    # ---------------------------------------------------------
    # 4. Verify attenuation
    # ---------------------------------------------------------

    if not is_attenuation(
        parent_payload,
        child_payload,
    ):
        raise ValueError(
            "Child token has greater capabilities than parent"
        )

    return child_payload


def verify_chain(
    aat0_token,
    aat1_token,
    aat2_token,
    issuer_public_key,
):
    # ---------------------------------------------------------
    # AAT₀
    # ---------------------------------------------------------

    aat0_payload = verify_token(
        aat0_token,
        issuer_public_key,
    )

    # ---------------------------------------------------------
    # AAT₁
    #
    # Signed by holder of AAT₀.
    # References AAT₀.
    # Must attenuate AAT₀.
    # ---------------------------------------------------------

    aat1_payload = verify_child_token(
        aat0_token,
        aat0_payload,
        aat1_token,
    )

    # ---------------------------------------------------------
    # AAT₂
    #
    # Signed by holder of AAT₁.
    # References AAT₁.
    # Must attenuate AAT₁.
    # ---------------------------------------------------------

    aat2_payload = verify_child_token(
        aat1_token,
        aat1_payload,
        aat2_token,
    )

    return (
        aat0_payload,
        aat1_payload,
        aat2_payload,
    )
