import base64
import json

import jwt

from aat.keys import load_private_key, load_public_key
from aat.pop import (
    create_challenge,
    sign_challenge,
    verify_token_proof,
)
from aat.verify import verify_chain, verify_child_token


def load_token(filename):
    with open(filename) as f:
        return f.read().strip()


def expect_failure(name, function):
    try:
        function()
        print(f"❌ {name}: ATTACK SUCCEEDED")
    except Exception as exc:
        print(f"✅ {name}: blocked ({type(exc).__name__})")


def expect_false(name, function):
    result = function()

    if result is False:
        print(f"✅ {name}: blocked")
    else:
        print(f"❌ {name}: ATTACK SUCCEEDED")


def main():

    aat0 = load_token("aat0.jwt")
    aat1 = load_token("aat1.jwt")
    aat2 = load_token("aat2.jwt")

    issuer_public_key = load_public_key("issuer")

    print()
    print("AAT SECURITY TESTS")
    print("=" * 80)

    # ------------------------------------------------------------
    # 1. Tamper with AAT₂
    # ------------------------------------------------------------

    def tamper_token():

        parts = aat2.split(".")

        payload = json.loads(
            base64.urlsafe_b64decode(
                parts[1] + "=" * (-len(parts[1]) % 4)
            )
        )

        payload["sub"] = "attacker"

        new_payload = base64.urlsafe_b64encode(
            json.dumps(
                payload,
                separators=(",", ":"),
            ).encode()
        ).rstrip(b"=").decode()

        tampered = (
            parts[0]
            + "."
            + new_payload
            + "."
            + parts[2]
        )

        verify_chain(
            aat0,
            aat1,
            tampered,
            issuer_public_key,
        )

    expect_failure(
        "Tamper with AAT₂",
        tamper_token,
    )

    # ------------------------------------------------------------
    # 2. Try to add read_cluster
    # ------------------------------------------------------------

    def add_capability():

        payload = jwt.decode(
            aat2,
            options={"verify_signature": False},
        )

        payload["authorization_details"][0]["tools"][
            "read_cluster"
        ] = {}

        agent_b_private_key = load_private_key("agent-b")

        forged = jwt.encode(
            payload,
            agent_b_private_key,
            algorithm="EdDSA",
        )

        parent_payload = jwt.decode(
            aat1,
            options={"verify_signature": False},
        )

        verify_child_token(
            aat1,
            parent_payload,
            forged,
        )

    expect_failure(
        "Add read_cluster capability",
        add_capability,
    )

    # ------------------------------------------------------------
    # 3. Broaden namespace
    # ------------------------------------------------------------

    def broaden_namespace():

        payload = jwt.decode(
            aat2,
            options={"verify_signature": False},
        )

        payload["authorization_details"][0]["tools"][
            "deploy"
        ]["namespace"] = "*"

        agent_b_private_key = load_private_key("agent-b")

        forged = jwt.encode(
            payload,
            agent_b_private_key,
            algorithm="EdDSA",
        )

        parent_payload = jwt.decode(
            aat1,
            options={"verify_signature": False},
        )

        verify_child_token(
            aat1,
            parent_payload,
            forged,
        )

    expect_failure(
        "Broaden namespace to *",
        broaden_namespace,
    )

    # ------------------------------------------------------------
    # 4. Change parent reference
    # ------------------------------------------------------------

    def change_parent():

        payload = jwt.decode(
            aat2,
            options={"verify_signature": False},
        )

        payload["parent"] = "fake-parent-hash"

        agent_b_private_key = load_private_key("agent-b")

        forged = jwt.encode(
            payload,
            agent_b_private_key,
            algorithm="EdDSA",
        )

        parent_payload = jwt.decode(
            aat1,
            options={"verify_signature": False},
        )

        verify_child_token(
            aat1,
            parent_payload,
            forged,
        )

    expect_failure(
        "Change parent reference",
        change_parent,
    )

    # ------------------------------------------------------------
    # 5. Sign with wrong key
    # ------------------------------------------------------------

    def wrong_signing_key():

        payload = jwt.decode(
            aat2,
            options={"verify_signature": False},
        )

        wrong_key = load_private_key("agent-a")

        forged = jwt.encode(
            payload,
            wrong_key,
            algorithm="EdDSA",
        )

        parent_payload = jwt.decode(
            aat1,
            options={"verify_signature": False},
        )

        verify_child_token(
            aat1,
            parent_payload,
            forged,
        )

    expect_failure(
        "Sign AAT₂ with Agent A key",
        wrong_signing_key,
    )

    # ------------------------------------------------------------
    # 6. Wrong proof-of-possession key
    # ------------------------------------------------------------

    def wrong_pop_key():

        payload = jwt.decode(
            aat2,
            options={"verify_signature": False},
        )

        challenge = create_challenge()

        wrong_private_key = load_private_key("agent-b")

        proof = sign_challenge(
            wrong_private_key,
            challenge,
        )

        return verify_token_proof(
            payload,
            challenge,
            proof,
        )

    expect_false(
        "Proof signed with wrong key",
        wrong_pop_key,
    )

    # ------------------------------------------------------------
    # 7. Replay proof against a different challenge
    # ------------------------------------------------------------

    def replay_pop():

        payload = jwt.decode(
            aat2,
            options={"verify_signature": False},
        )

        original_challenge = create_challenge()

        tool_private_key = load_private_key(
            "tool-agent"
        )

        proof = sign_challenge(
            tool_private_key,
            original_challenge,
        )

        new_challenge = create_challenge()

        return verify_token_proof(
            payload,
            new_challenge,
            proof,
        )

    expect_false(
        "Replay proof against new challenge",
        replay_pop,
    )


if __name__ == "__main__":
    main()
