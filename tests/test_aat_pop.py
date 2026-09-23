from aat.keys import load_private_key
from aat.pop import (
    create_challenge,
    sign_challenge,
    verify_token_proof,
)
from aat.verify import verify_token
from aat.keys import load_public_key


def main():

    # ---------------------------------------------------------
    # Load AAT₂
    # ---------------------------------------------------------

    with open("aat2.jwt") as f:
        token = f.read().strip()

    # ---------------------------------------------------------
    # Decode/verify AAT₂
    # ---------------------------------------------------------

    # For this test we know AAT₂ is signed by Agent B.
    agent_b_public_key = load_public_key("agent-b")

    payload = verify_token(
        token,
        agent_b_public_key,
    )

    # ---------------------------------------------------------
    # Resource server creates challenge
    # ---------------------------------------------------------

    challenge = create_challenge()

    # ---------------------------------------------------------
    # Legitimate Tool Agent signs it
    # ---------------------------------------------------------

    tool_agent_private_key = load_private_key(
        "tool-agent"
    )

    signature = sign_challenge(
        tool_agent_private_key,
        challenge,
    )

    # ---------------------------------------------------------
    # Verify against the key embedded in AAT₂
    # ---------------------------------------------------------

    valid = verify_token_proof(
        payload,
        challenge,
        signature,
    )

    print()
    print("AAT₂ PROOF OF POSSESSION")
    print("=" * 80)
    print(valid)


if __name__ == "__main__":
    main()
