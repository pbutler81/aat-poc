from aat.keys import load_private_key, load_public_key
from aat.pop import create_challenge, sign_challenge
from authz.decision import authorize_request


def load_token(filename):
    with open(filename) as f:
        return f.read().strip()


def main():

    # --------------------------------------------------
    # Load the delegation chain
    # --------------------------------------------------

    aat0 = load_token("aat0.jwt")
    aat1 = load_token("aat1.jwt")
    aat2 = load_token("aat2.jwt")

    issuer_public_key = load_public_key("issuer")

    # --------------------------------------------------
    # Resource server creates a challenge
    # --------------------------------------------------

    challenge = create_challenge()

    # --------------------------------------------------
    # Legitimate Tool Agent proves possession
    # --------------------------------------------------

    tool_agent_private_key = load_private_key(
        "tool-agent"
    )

    proof = sign_challenge(
        tool_agent_private_key,
        challenge,
    )

    # --------------------------------------------------
    # Test 1: legitimate request
    # --------------------------------------------------

    allowed = authorize_request(
        aat0,
        aat1,
        aat2,
        issuer_public_key,
        challenge,
        proof,
        "deploy",
        {
            "namespace": "payments",
            "environment": "production",
        },
    )

    print()
    print("LEGITIMATE REQUEST")
    print("=" * 80)
    print("Decision:", "ALLOW" if allowed else "DENY")

    # --------------------------------------------------
    # Test 2: wrong namespace
    # --------------------------------------------------

    allowed = authorize_request(
        aat0,
        aat1,
        aat2,
        issuer_public_key,
        challenge,
        proof,
        "deploy",
        {
            "namespace": "billing",
            "environment": "production",
        },
    )

    print()
    print("WRONG NAMESPACE")
    print("=" * 80)
    print("Decision:", "ALLOW" if allowed else "DENY")

    # --------------------------------------------------
    # Test 3: wrong environment
    # --------------------------------------------------

    allowed = authorize_request(
        aat0,
        aat1,
        aat2,
        issuer_public_key,
        challenge,
        proof,
        "deploy",
        {
            "namespace": "payments",
            "environment": "development",
        },
    )

    print()
    print("WRONG ENVIRONMENT")
    print("=" * 80)
    print("Decision:", "ALLOW" if allowed else "DENY")

    # --------------------------------------------------
    # Test 4: unauthorised tool
    # --------------------------------------------------

    allowed = authorize_request(
        aat0,
        aat1,
        aat2,
        issuer_public_key,
        challenge,
        proof,
        "read_cluster",
        {},
    )

    print()
    print("UNAUTHORISED TOOL")
    print("=" * 80)
    print("Decision:", "ALLOW" if allowed else "DENY")

    # --------------------------------------------------
    # Test 5: attacker uses Agent B key
    # --------------------------------------------------

    attacker_private_key = load_private_key(
        "agent-b"
    )

    attacker_proof = sign_challenge(
        attacker_private_key,
        challenge,
    )

    allowed = authorize_request(
        aat0,
        aat1,
        aat2,
        issuer_public_key,
        challenge,
        attacker_proof,
        "deploy",
        {
            "namespace": "payments",
            "environment": "production",
        },
    )

    print()
    print("ATTACKER USING AGENT B KEY")
    print("=" * 80)
    print("Decision:", "ALLOW" if allowed else "DENY")


if __name__ == "__main__":
    main()
