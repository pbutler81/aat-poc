from aat.keys import load_private_key, load_public_key
from aat.pop import (
    create_challenge,
    sign_challenge,
    verify_token_proof,
)
from aat.verify import verify_chain


def main():

    # ---------------------------------------------------------
    # Load the complete AAT delegation chain
    # ---------------------------------------------------------

    with open("aat0.jwt") as f:
        aat0 = f.read().strip()

    with open("aat1.jwt") as f:
        aat1 = f.read().strip()

    with open("aat2.jwt") as f:
        aat2 = f.read().strip()

    # ---------------------------------------------------------
    # Verify the full chain from the trusted root issuer
    # ---------------------------------------------------------

    issuer_public_key = load_public_key("issuer")

    payloads = verify_chain(
        [aat0, aat1, aat2],
        issuer_public_key,
    )

    # Use the verified final token (AAT₂) for the PoP test
    payload = payloads[-1]

    # ---------------------------------------------------------
    # Resource server creates challenge
    # ---------------------------------------------------------

    challenge = create_challenge()

    # ---------------------------------------------------------
    # Legitimate Tool Agent signs the challenge
    # ---------------------------------------------------------

    tool_agent_private_key = load_private_key(
        "tool-agent"
    )

    signature = sign_challenge(
        tool_agent_private_key,
        challenge,
    )

    # ---------------------------------------------------------
    # Verify proof against the key embedded in AAT₂
    # ---------------------------------------------------------

    valid = verify_token_proof(
        payload,
        challenge,
        signature,
    )

    print()
    print("AAT₂ PROOF OF POSSESSION")
    print("=" * 80)
    print(f"Delegation chain verified: True")
    print(f"Proof of possession valid: {valid}")

    if not valid:
        raise SystemExit("Proof-of-possession test failed")


if __name__ == "__main__":
    main()