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
    # Agent B's identity
    # ---------------------------------------------------------

    agent_b_private_key = load_private_key("agent-b")

    # ---------------------------------------------------------
    # Tool Agent's identity
    # ---------------------------------------------------------

    tool_agent_public_key = load_public_key("tool-agent")
    tool_agent_jwk = public_key_to_jwk(tool_agent_public_key)

    # ---------------------------------------------------------
    # Load AAT₁
    # ---------------------------------------------------------

    with open("aat1.jwt") as f:
        parent_token = f.read().strip()

    print()
    print("AAT₁")
    print("=" * 80)
    print(parent_token)

    # ---------------------------------------------------------
    # Hash AAT₁
    # ---------------------------------------------------------

    parent_hash = hash_token(parent_token)

    print()
    print("PARENT TOKEN HASH")
    print("=" * 80)
    print(parent_hash)

    # ---------------------------------------------------------
    # Agent B attenuates the authority.
    #
    # AAT₁ already only has:
    #
    #     deploy
    #
    # AAT₂ therefore retains:
    #
    #     deploy
    #
    # ---------------------------------------------------------

    child_capabilities = {
        "deploy": {
            "namespace": "payments",
            "environment": "production",
        }
    }

    # ---------------------------------------------------------
    # Agent B signs AAT₂.
    #
    # The token is bound to the Tool Agent's public key.
    # ---------------------------------------------------------

    child_token = create_token(
        private_key=agent_b_private_key,

        issuer="https://aat-poc.local/agent-b",

        subject="paul",

        holder_public_key=tool_agent_jwk,

        capabilities=child_capabilities,

        del_depth=2,
        del_max_depth=3,

        parent=parent_hash,
    )

    # ---------------------------------------------------------
    # Save AAT₂
    # ---------------------------------------------------------

    with open("aat2.jwt", "w") as f:
        f.write(child_token)

    # ---------------------------------------------------------
    # Display AAT₂
    # ---------------------------------------------------------

    print()
    print("AAT₂")
    print("=" * 80)
    print(child_token)

    print()
    print("AAT₂ PAYLOAD")
    print("=" * 80)

    payload = jwt.decode(
        child_token,
        options={"verify_signature": False},
    )

    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
