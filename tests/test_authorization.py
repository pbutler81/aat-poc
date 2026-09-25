from aat.keys import load_private_key
from aat.pop import create_challenge, sign_challenge
from authz.decision import authorize


def load_token(filename):
    with open(filename) as f:
        return f.read().strip()


def main():

    # ---------------------------------------------------------
    # Load complete delegation chain
    # ---------------------------------------------------------

    tokens = [
        load_token("aat0.jwt"),
        load_token("aat1.jwt"),
        load_token("aat2.jwt"),
    ]

    # ---------------------------------------------------------
    # Create proof-of-possession
    # ---------------------------------------------------------

    challenge = create_challenge()

    tool_agent_private_key = load_private_key(
        "tool-agent"
    )

    proof = sign_challenge(
        tool_agent_private_key,
        challenge,
    )

    print()
    print("FULL AUTHORISATION TEST")
    print("=" * 80)

    # ---------------------------------------------------------
    # Valid request
    # ---------------------------------------------------------

    allowed = authorize(
        tokens,
        challenge,
        proof,
        "deploy",
        {
            "namespace": "payments",
            "environment": "production",
        },
    )

    print(
        "VALID REQUEST:",
        allowed,
    )

    # ---------------------------------------------------------
    # Invalid request
    #
    # Final token only allows namespace=payments.
    # ---------------------------------------------------------

    denied = authorize(
        tokens,
        challenge,
        proof,
        "deploy",
        {
            "namespace": "billing",
            "environment": "production",
        },
    )

    print(
        "WRONG NAMESPACE:",
        denied,
    )


if __name__ == "__main__":
    main()
