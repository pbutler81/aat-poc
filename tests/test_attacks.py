import copy

import jwt

from aat.keys import load_private_key, load_public_key
from aat.pop import create_challenge, sign_challenge, verify_token_proof
from aat.verify import verify_chain, verify_token
from authz.policy import is_request_allowed


def load_token(filename):
    with open(filename) as f:
        return f.read().strip()


def expect_failure(name, function):
    try:
        function()
        print(f"❌ {name}: ATTACK SUCCEEDED")
    except Exception as exc:
        print(f"✅ {name}: REJECTED")
        print(f"   {type(exc).__name__}: {exc}")


def main():

    aat0 = load_token("aat0.jwt")
    aat1 = load_token("aat1.jwt")
    aat2 = load_token("aat2.jwt")

    issuer_public_key = load_public_key("issuer")

    # --------------------------------------------------
    # Attack 1: Modify AAT₂ payload
    # --------------------------------------------------

    def modify_token():

        header = jwt.get_unverified_header(aat2)
        payload = jwt.decode(
            aat2,
            options={"verify_signature": False},
        )

        payload["authorization_details"][0]["tools"][
            "deploy"
        ]["namespace"] = "*"

        forged_token = jwt.encode(
            payload,
            load_private_key("agent-b"),
            algorithm="EdDSA",
            headers=header,
        )

        verify_chain(
            aat0,
            aat1,
            forged_token,
            issuer_public_key,
        )

    expect_failure(
        "Modify AAT₂ namespace",
        modify_token,
    )

    # --------------------------------------------------
    # Attack 2: Sign AAT₂ with the wrong key
    # --------------------------------------------------

    def wrong_signing_key():

        payload = jwt.decode(
            aat2,
            options={"verify_signature": False},
        )

        forged_token = jwt.encode(
            payload,
            load_private_key("tool-agent"),
            algorithm="EdDSA",
        )

        verify_chain(
            aat0,
            aat1,
            forged_token,
            issuer_public_key,
        )

    expect_failure(
        "AAT₂ signed by wrong agent",
        wrong_signing_key,
    )

    # --------------------------------------------------
    # Attack 3: Change parent reference
    # --------------------------------------------------

    def wrong_parent():

        payload = jwt.decode(
            aat2,
            options={"verify_signature": False},
        )

        payload["parent"] = "THIS_IS_NOT_THE_PARENT"

        forged_token = jwt.encode(
            payload,
            load_private_key("agent-b"),
            algorithm="EdDSA",
        )

        verify_chain(
            aat0,
            aat1,
            forged_token,
            issuer_public_key,
        )

    expect_failure(
        "Wrong parent reference",
        wrong_parent,
    )

    # --------------------------------------------------
    # Attack 4: Expand AAT₂ namespace
    # --------------------------------------------------

    def expand_namespace():

        payload = jwt.decode(
            aat2,
            options={"verify_signature": False},
        )

        payload["authorization_details"][0]["tools"][
            "deploy"
        ]["namespace"] = "*"

        forged_token = jwt.encode(
            payload,
            load_private_key("agent-b"),
            algorithm="EdDSA",
        )

        verify_chain(
            aat0,
            aat1,
            forged_token,
            issuer_public_key,
        )

    expect_failure(
        "Expand payments → *",
        expand_namespace,
    )

    # --------------------------------------------------
    # Attack 5: Add read_cluster to AAT₂
    # --------------------------------------------------

    def add_tool():

        payload = jwt.decode(
            aat2,
            options={"verify_signature": False},
        )

        payload["authorization_details"][0]["tools"][
            "read_cluster"
        ] = {}

        forged_token = jwt.encode(
            payload,
            load_private_key("agent-b"),
            algorithm="EdDSA",
        )

        verify_chain(
            aat0,
            aat1,
            forged_token,
            issuer_public_key,
        )

    expect_failure(
        "Restore read_cluster",
        add_tool,
    )

    # --------------------------------------------------
    # Attack 6: Wrong proof-of-possession key
    # --------------------------------------------------

    challenge = create_challenge()

    wrong_proof = sign_challenge(
        load_private_key("agent-b"),
        challenge,
    )

    payload = verify_token(
        aat2,
        load_public_key("agent-b"),
    )

    valid = verify_token_proof(
        payload,
        challenge,
        wrong_proof,
    )

    print()
    if valid:
        print("❌ Wrong PoP key: ATTACK SUCCEEDED")
    else:
        print("✅ Wrong PoP key: REJECTED")

    # --------------------------------------------------
    # Attack 7: Replay old proof
    # --------------------------------------------------

    tool_agent_private_key = load_private_key(
        "tool-agent"
    )

    old_challenge = create_challenge()

    old_proof = sign_challenge(
        tool_agent_private_key,
        old_challenge,
    )

    new_challenge = create_challenge()

    replay = verify_token_proof(
        payload,
        new_challenge,
        old_proof,
    )

    print()
    if replay:
        print("❌ PoP replay: ATTACK SUCCEEDED")
    else:
        print("✅ PoP replay: REJECTED")

    # --------------------------------------------------
    # Attack 8: Request outside AAT₂
    # --------------------------------------------------

    allowed = is_request_allowed(
        payload,
        "deploy",
        {
            "namespace": "billing",
            "environment": "production",
        },
    )

    print()
    if allowed:
        print("❌ Billing deployment: ATTACK SUCCEEDED")
    else:
        print("✅ Billing deployment: REJECTED")


if __name__ == "__main__":
    main()
