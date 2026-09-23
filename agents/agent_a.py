import base64
import json
import jwt

from aat.attenuation import hash_token
from aat.keys import load_private_key, load_public_key
from aat.token import create_token


def public_key_to_jwk(public_key):
    raw = public_key.public_bytes_raw()

    x = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": x,
    }


def main():
    # ---------------------------------------------------------
    # Agent A's identity
    # ---------------------------------------------------------

    agent_a_private_key = load_private_key("agent-a")

    # ---------------------------------------------------------
    # Agent B's identity
    # ---------------------------------------------------------

    agent_b_public_key = load_public_key("agent-b")
    agent_b_jwk = public_key_to_jwk(agent_b_public_key)

    # ---------------------------------------------------------
    # Load AAT₀
    # ---------------------------------------------------------

    with open("aat0.jwt") as f:
        parent_token = f.read().strip()

    print()
    print("AAT₀")
    print("=" * 80)
    print(parent_token)

    # ---------------------------------------------------------
    # Hash the parent token
    # ---------------------------------------------------------

    parent_hash = hash_token(parent_token)

    print()
    print("PARENT TOKEN HASH")
    print("=" * 80)
    print(parent_hash)

    # ---------------------------------------------------------
    # Agent A attenuates its authority
    #
    # Parent:
    #
    #   deploy
    #   read_cluster
    #
    # Child:
    #
    #   deploy
    #
    # ---------------------------------------------------------

    child_capabilities = {
        "deploy": {
            "namespace": "payments",
        }
    }

    # ---------------------------------------------------------
    # Agent A signs AAT₁
    #
    # The important difference is that the token is now
    # bound to Agent B's public key.
    # ---------------------------------------------------------

    child_token = create_token(
        private_key=agent_a_private_key,

        issuer="https://aat-poc.local/agent-a",

        subject="paul",

        holder_public_key=agent_b_jwk,

        capabilities=child_capabilities,

        del_depth=1,
        del_max_depth=3,

        parent=parent_hash,
    )

    # ---------------------------------------------------------
    # Save AAT₁
    # ---------------------------------------------------------

    with open("aat1.jwt", "w") as f:
        f.write(child_token)

    # ---------------------------------------------------------
    # Display AAT₁
    # ---------------------------------------------------------

    print()
    print("AAT₁")
    print("=" * 80)
    print(child_token)

    print()
    print("AAT₁ PAYLOAD")
    print("=" * 80)

    payload = jwt.decode(
        child_token,
        options={"verify_signature": False},
    )

    print(json.dumps(payload, indent=2))

    print()
    print("AAT₁ HOLDER")
    print("=" * 80)
    print(json.dumps(agent_b_jwk, indent=2))


if __name__ == "__main__":
    main()
