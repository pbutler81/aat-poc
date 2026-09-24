from aat.keys import load_private_key
from aat.pop import create_challenge, sign_challenge
from authz.decision import authorize


def load_token(filename):
    with open(filename) as f:
        return f.read().strip()


def main():

    aat0 = load_token("aat0.jwt")
    aat1 = load_token("aat1.jwt")
    aat2 = load_token("aat2.jwt")

    challenge = create_challenge()

    tool_agent_private_key = load_private_key("tool-agent")

    proof = sign_challenge(
        tool_agent_private_key,
        challenge,
    )

    print()
    print("FULL AUTHORISATION TEST")
    print("=" * 80)

    allowed = authorize(
        aat0,
        aat1,
        aat2,
        challenge,
        proof,
        "deploy",
        {
            "namespace": "payments",
            "environment": "production",
        },
    )

    print("VALID REQUEST:", allowed)

    denied = authorize(
        aat0,
        aat1,
        aat2,
        challenge,
        proof,
        "deploy",
        {
            "namespace": "billing",
            "environment": "production",
        },
    )

    print("WRONG NAMESPACE:", denied)


if __name__ == "__main__":
    main()
