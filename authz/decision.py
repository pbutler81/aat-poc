from aat.keys import load_public_key
from aat.pop import verify_token_proof
from aat.verify import verify_chain
from authz.policy import is_request_allowed


def authorize(
    tokens,
    challenge,
    proof,
    action,
    constraints,
):
    """
    Perform complete authorization.

    1. Verify the complete AAT delegation chain.
    2. Select the final verified token.
    3. Verify proof-of-possession for the final token.
    4. Check the requested action against the final token.

    The authorization layer does not assume a fixed
    number of delegation levels.
    """

    # ---------------------------------------------------------
    # Basic validation
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
    # Load trusted root issuer key
    # ---------------------------------------------------------

    issuer_public_key = load_public_key(
        "issuer"
    )

    # ---------------------------------------------------------
    # Verify complete delegation chain
    # ---------------------------------------------------------

    payloads = verify_chain(
        tokens,
        issuer_public_key,
    )

    # ---------------------------------------------------------
    # Authorization is based on the final delegated token.
    #
    # This could be:
    #
    # AAT₀
    #
    # AAT₀ -> AAT₁
    #
    # AAT₀ -> AAT₁ -> AAT₂
    #
    # AAT₀ -> ... -> AATₙ
    # ---------------------------------------------------------

    final_payload = payloads[-1]

    # ---------------------------------------------------------
    # Verify proof-of-possession
    #
    # The caller must prove possession of the private key
    # corresponding to the public key in final_payload.cnf.
    # ---------------------------------------------------------

    if not verify_token_proof(
        final_payload,
        challenge,
        proof,
    ):
        return False

    # ---------------------------------------------------------
    # Evaluate requested action against final authority
    # ---------------------------------------------------------

    return is_request_allowed(
        final_payload,
        action,
        constraints,
    )
