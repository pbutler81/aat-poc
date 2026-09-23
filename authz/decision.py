from aat.pop import verify_token_proof
from aat.verify import verify_chain
from authz.policy import is_request_allowed


def authorize_request(
    aat0_token,
    aat1_token,
    aat2_token,
    issuer_public_key,
    challenge,
    proof,
    tool,
    request_constraints,
):
    """
    Perform the complete resource-server authorization decision.

    Returns True if:
      1. The AAT delegation chain is valid.
      2. The caller proves possession of the final holder key.
      3. The requested operation is allowed by the final AAT.
    """

    # --------------------------------------------------
    # 1. Verify the complete delegation chain
    # --------------------------------------------------

    (
        _aat0_payload,
        _aat1_payload,
        aat2_payload,
    ) = verify_chain(
        aat0_token,
        aat1_token,
        aat2_token,
        issuer_public_key,
    )

    # --------------------------------------------------
    # 2. Verify proof of possession
    # --------------------------------------------------

    if not verify_token_proof(
        aat2_payload,
        challenge,
        proof,
    ):
        return False

    # --------------------------------------------------
    # 3. Check whether the requested operation is allowed
    # --------------------------------------------------

    return is_request_allowed(
        aat2_payload,
        tool,
        request_constraints,
    )
