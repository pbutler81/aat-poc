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
    """
    Verify the root AAT.

    The root token must:

    1. Have a valid signature.
    2. Contain all required claims.
    3. Start at delegation depth 0.
    4. Have a valid maximum delegation depth.
    """

    payload = jwt.decode(
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
                "del_depth",
                "del_max_depth",
            ]
        },
    )

    # ---------------------------------------------------------
    # Root delegation-depth validation
    # ---------------------------------------------------------

    depth = payload["del_depth"]
    max_depth = payload["del_max_depth"]

    if not isinstance(depth, int):
        raise ValueError(
            "del_depth must be an integer"
        )

    if not isinstance(max_depth, int):
        raise ValueError(
            "del_max_depth must be an integer"
        )

    if depth != 0:
        raise ValueError(
            "Root token must have del_depth = 0"
        )

    if max_depth < 0:
        raise ValueError(
            "del_max_depth cannot be negative"
        )

    if depth > max_depth:
        raise ValueError(
            "Root token exceeds maximum delegation depth"
        )

    return payload


def verify_delegation_depth(
    parent_payload,
    child_payload,
):
    """
    Verify delegation-depth invariants.

    Rules:

    1. Depth values must be integers.
    2. Child depth must equal parent depth + 1.
    3. Child cannot increase del_max_depth.
    4. Child cannot exceed its maximum depth.
    5. Parent must itself be within its maximum depth.
    """

    parent_depth = parent_payload["del_depth"]
    parent_max_depth = parent_payload["del_max_depth"]

    child_depth = child_payload["del_depth"]
    child_max_depth = child_payload["del_max_depth"]

    # ---------------------------------------------------------
    # Validate types
    # ---------------------------------------------------------

    for name, value in (
        ("parent del_depth", parent_depth),
        ("parent del_max_depth", parent_max_depth),
        ("child del_depth", child_depth),
        ("child del_max_depth", child_max_depth),
    ):
        if not isinstance(value, int):
            raise ValueError(
                f"{name} must be an integer"
            )

    # ---------------------------------------------------------
    # Validate parent state
    # ---------------------------------------------------------

    if parent_depth < 0:
        raise ValueError(
            "Parent delegation depth cannot be negative"
        )

    if parent_max_depth < 0:
        raise ValueError(
            "Parent maximum delegation depth cannot be negative"
        )

    if parent_depth > parent_max_depth:
        raise ValueError(
            "Parent token exceeds maximum delegation depth"
        )

    # ---------------------------------------------------------
    # Child depth must increase by exactly one
    # ---------------------------------------------------------

    expected_child_depth = parent_depth + 1

    if child_depth != expected_child_depth:
        raise ValueError(
            "Invalid delegation depth: "
            f"expected {expected_child_depth}, "
            f"got {child_depth}"
        )

    # ---------------------------------------------------------
    # Child cannot increase maximum delegation depth
    # ---------------------------------------------------------

    if child_max_depth > parent_max_depth:
        raise ValueError(
            "Child token cannot increase del_max_depth"
        )

    # ---------------------------------------------------------
    # Child maximum depth cannot be negative
    # ---------------------------------------------------------

    if child_max_depth < 0:
        raise ValueError(
            "Child del_max_depth cannot be negative"
        )

    # ---------------------------------------------------------
    # Child cannot exceed its permitted maximum
    # ---------------------------------------------------------

    if child_depth > child_max_depth:
        raise ValueError(
            "Maximum delegation depth exceeded"
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
    3. Child delegation depth is valid.
    4. Child capabilities are a subset of parent capabilities.
    """

    # ---------------------------------------------------------
    # 1. Determine who holds the parent token
    # ---------------------------------------------------------

    parent_holder_jwk = parent_payload["cnf"]["jwk"]

    parent_holder_key = jwk_to_public_key(
        parent_holder_jwk
    )

    # ---------------------------------------------------------
    # 2. Verify child's signature
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
                "del_depth",
                "del_max_depth",
            ]
        },
    )

    # ---------------------------------------------------------
    # 3. Verify parent binding
    # ---------------------------------------------------------

    expected_parent_hash = hash_token(
        parent_token
    )

    actual_parent_hash = child_payload["parent"]

    if actual_parent_hash != expected_parent_hash:
        raise ValueError(
            "Child token does not reference the supplied parent token"
        )

    # ---------------------------------------------------------
    # 4. Verify delegation depth
    # ---------------------------------------------------------

    verify_delegation_depth(
        parent_payload,
        child_payload,
    )

    # ---------------------------------------------------------
    # 5. Verify capability attenuation
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
    tokens,
    issuer_public_key,
):
    """
    Verify an arbitrary-length AAT delegation chain.

    The first token is treated as the root token and must be
    signed by the trusted root issuer.

    Every subsequent token must:

    1. Be signed by the holder of its parent.
    2. Reference the exact parent token.
    3. Increment delegation depth by exactly one.
    4. Remain within the permitted maximum depth.
    5. Not increase del_max_depth.
    6. Attenuate the parent's capabilities.

    Returns a list of verified payloads in chain order.
    """

    # ---------------------------------------------------------
    # Basic chain validation
    # ---------------------------------------------------------

    if not isinstance(tokens, (list, tuple)):
        raise ValueError(
            "Token chain must be a list or tuple"
        )

    if len(tokens) == 0:
        raise ValueError(
            "Token chain cannot be empty"
        )

    # ---------------------------------------------------------
    # Verify root token
    # ---------------------------------------------------------

    root_payload = verify_token(
        tokens[0],
        issuer_public_key,
    )

    payloads = [
        root_payload
    ]

    # ---------------------------------------------------------
    # Walk the delegation chain
    #
    # tokens[0] = root
    # tokens[1] = child of root
    # tokens[2] = child of tokens[1]
    # ...
    # ---------------------------------------------------------

    for index in range(1, len(tokens)):

        parent_token = tokens[index - 1]
        parent_payload = payloads[index - 1]

        child_token = tokens[index]

        child_payload = verify_child_token(
            parent_token,
            parent_payload,
            child_token,
        )

        payloads.append(
            child_payload
        )

    return payloads
