import base64
import json

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
    # Load the persistent root issuer key
    issuer_private_key = load_private_key("issuer")
    issuer_public_key = load_public_key("issuer")

    # Load Agent A's persistent public key
    agent_a_public_key = load_public_key("agent-a")
    agent_a_jwk = public_key_to_jwk(agent_a_public_key)

    # Create the root AAT
    token = create_token(
        private_key=issuer_private_key,
        issuer="https://aat-poc.local/issuer",
        subject="paul",
        holder_public_key=agent_a_jwk,
        capabilities={
            "deploy": {
                "namespace": "*",
    },
            "read_cluster": {},
    },
    )

    print()
    print("ROOT AAT")
    print("=" * 80)
    print(token)
    with open("aat0.jwt", "w") as f:
        f.write(token)
    print()

    print("AGENT A PUBLIC JWK")
    print("=" * 80)
    print(json.dumps(agent_a_jwk, indent=2))


if __name__ == "__main__":
    main()
