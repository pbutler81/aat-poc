from aat.keys import load_public_key
from aat.pop import verify_token_proof
from aat.verify import verify_chain
from authz.policy import is_request_allowed


def authorize(
    aat0_token,
    aat1_token,
    aat2_token,
    challenge,
    proof,
    action,
    constraints,
):
    """
    Perform complete authorization.

    1. Verify the complete AAT delegation chain.
    2. Verify proof-of-possession for the final token.
    3. Check the requested action against the final token.
    """

    issuer_public_key = load_public_key("issuer")

    (
        aat0_payload,
        aat1_payload,
        aat2_payload,
    ) = verify_chain(
        aat0_token,
        aat1_token,
        aat2_token,
        issuer_public_key,
    )

    if not verify_token_proof(
        aat2_payload,
        challenge,
        proof,
    ):
        return False

    return is_request_allowed(
        aat2_payload,
        action,
        constraints,
    )
