import base64

from aat.attenuation import hash_token
from aat.keys import load_private_key, load_public_key
from aat.token import create_token
from aat.verify import verify_child_token, verify_token


def public_key_to_jwk(public_key):
    raw = public_key.public_bytes_raw()

    x = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": x,
    }


def print_result(name, passed, detail=""):
    status = "✅" if passed else "❌"

    if detail:
        print(f"{status} {name}: {detail}")
    else:
        print(f"{status} {name}")


def expect_rejected(name, test_function):
    try:
        test_function()

        print_result(
            name,
            False,
            "ATTACK SUCCEEDED",
        )

    except Exception as exc:
        print_result(
            name,
            True,
            f"blocked ({type(exc).__name__}: {exc})",
        )


def main():
    print()
    print("AAT DELEGATION DEPTH SECURITY TESTS")
    print("=" * 80)

    # ---------------------------------------------------------
    # Load keys
    # ---------------------------------------------------------

    issuer_public_key = load_public_key("issuer")

    agent_b_private_key = load_private_key("agent-b")

    tool_agent_public_key = load_public_key("tool-agent")

    tool_agent_jwk = public_key_to_jwk(
        tool_agent_public_key
    )

    # ---------------------------------------------------------
    # Load AAT₀ and AAT₁
    # ---------------------------------------------------------

    with open("aat0.jwt") as f:
        aat0_token = f.read().strip()

    with open("aat1.jwt") as f:
        aat1_token = f.read().strip()

    # ---------------------------------------------------------
    # Verify AAT₀
    # ---------------------------------------------------------

    aat0_payload = verify_token(
        aat0_token,
        issuer_public_key,
    )

    # ---------------------------------------------------------
    # Verify legitimate AAT₁
    # ---------------------------------------------------------

    aat1_payload = verify_child_token(
        aat0_token,
        aat0_payload,
        aat1_token,
    )

    parent_hash = hash_token(
        aat1_token
    )

    capabilities = {
        "deploy": {
            "namespace": "payments",
            "environment": "production",
        }
    }

    # ---------------------------------------------------------
    # Display legitimate parent depth
    # ---------------------------------------------------------

    print()
    print(
        "AAT₁:",
        f"depth={aat1_payload['del_depth']}",
        f"max={aat1_payload['del_max_depth']}",
    )

    print()

    # =========================================================
    # TEST 1
    #
    # Legitimate child:
    #
    # AAT₁ depth=1
    # AAT₂ depth=2
    #
    # This should succeed.
    # =========================================================

    legitimate_child = create_token(
        private_key=agent_b_private_key,
        issuer="https://aat-poc.local/agent-b",
        subject="paul",
        holder_public_key=tool_agent_jwk,
        capabilities=capabilities,
        del_depth=2,
        del_max_depth=3,
        parent=parent_hash,
    )

    try:
        verify_child_token(
            aat1_token,
            aat1_payload,
            legitimate_child,
        )

        print_result(
            "Legitimate depth 1 -> 2",
            True,
            "allowed",
        )

    except Exception as exc:
        print_result(
            "Legitimate depth 1 -> 2",
            False,
            f"unexpected rejection ({exc})",
        )

    # =========================================================
    # TEST 2
    #
    # ATTACK:
    #
    # Reset depth back to zero.
    #
    # Parent = 1
    # Child  = 0
    #
    # Expected child depth = 2.
    # =========================================================

    def attack_reset_depth():
        token = create_token(
            private_key=agent_b_private_key,
            issuer="https://aat-poc.local/agent-b",
            subject="paul",
            holder_public_key=tool_agent_jwk,
            capabilities=capabilities,
            del_depth=0,
            del_max_depth=3,
            parent=parent_hash,
        )

        verify_child_token(
            aat1_token,
            aat1_payload,
            token,
        )

    expect_rejected(
        "Reset delegation depth to 0",
        attack_reset_depth,
    )

    # =========================================================
    # TEST 3
    #
    # ATTACK:
    #
    # Skip a delegation depth.
    #
    # Parent = 1
    # Child  = 3
    #
    # Expected child depth = 2.
    # =========================================================

    def attack_skip_depth():
        token = create_token(
            private_key=agent_b_private_key,
            issuer="https://aat-poc.local/agent-b",
            subject="paul",
            holder_public_key=tool_agent_jwk,
            capabilities=capabilities,
            del_depth=3,
            del_max_depth=3,
            parent=parent_hash,
        )

        verify_child_token(
            aat1_token,
            aat1_payload,
            token,
        )

    expect_rejected(
        "Skip from depth 1 to depth 3",
        attack_skip_depth,
    )

    # =========================================================
    # TEST 4
    #
    # ATTACK:
    #
    # Increase the maximum depth.
    #
    # Parent max = 3
    # Child max  = 10
    #
    # A downstream agent must not be able to extend the
    # delegation authority it received.
    # =========================================================

    def attack_increase_max_depth():
        token = create_token(
            private_key=agent_b_private_key,
            issuer="https://aat-poc.local/agent-b",
            subject="paul",
            holder_public_key=tool_agent_jwk,
            capabilities=capabilities,
            del_depth=2,
            del_max_depth=10,
            parent=parent_hash,
        )

        verify_child_token(
            aat1_token,
            aat1_payload,
            token,
        )

    expect_rejected(
        "Increase del_max_depth from 3 to 10",
        attack_increase_max_depth,
    )

    # =========================================================
    # TEST 5
    #
    # ATTACK:
    #
    # Child depth exceeds its own maximum.
    #
    # Child:
    #
    # depth = 2
    # max   = 1
    #
    # =========================================================

    def attack_exceed_max_depth():
        token = create_token(
            private_key=agent_b_private_key,
            issuer="https://aat-poc.local/agent-b",
            subject="paul",
            holder_public_key=tool_agent_jwk,
            capabilities=capabilities,
            del_depth=2,
            del_max_depth=1,
            parent=parent_hash,
        )

        verify_child_token(
            aat1_token,
            aat1_payload,
            token,
        )

    expect_rejected(
        "Child depth exceeds del_max_depth",
        attack_exceed_max_depth,
    )

    # =========================================================
    # TEST 6
    #
    # VALID ATTENUATION:
    #
    # A child is allowed to LOWER the maximum delegation depth.
    #
    # Parent:
    #
    # depth = 1
    # max   = 3
    #
    # Child:
    #
    # depth = 2
    # max   = 2
    #
    # This effectively says:
    #
    # "I can use this authority, but I cannot delegate it
    # any further."
    # =========================================================

    restricted_child = create_token(
        private_key=agent_b_private_key,
        issuer="https://aat-poc.local/agent-b",
        subject="paul",
        holder_public_key=tool_agent_jwk,
        capabilities=capabilities,
        del_depth=2,
        del_max_depth=2,
        parent=parent_hash,
    )

    try:
        verify_child_token(
            aat1_token,
            aat1_payload,
            restricted_child,
        )

        print_result(
            "Lower del_max_depth from 3 to 2",
            True,
            "allowed",
        )

    except Exception as exc:
        print_result(
            "Lower del_max_depth from 3 to 2",
            False,
            f"unexpected rejection ({exc})",
        )

    print()
    print("=" * 80)
    print("DEPTH TESTS COMPLETE")


if __name__ == "__main__":
    main()
