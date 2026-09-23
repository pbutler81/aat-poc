import base64
import hashlib
import json
import time
import uuid

from cryptography.hazmat.primitives import serialization


def create_challenge():
    """
    Create a random challenge that a resource server
    can send to a token holder.
    """

    return {
        "challenge": str(uuid.uuid4()),
        "timestamp": int(time.time()),
    }


def canonicalize_challenge(challenge):
    """
    Convert the challenge into deterministic bytes.
    """

    return json.dumps(
        challenge,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sign_challenge(private_key, challenge):
    """
    Sign the resource server challenge using the
    holder's private key.
    """

    data = canonicalize_challenge(challenge)

    signature = private_key.sign(data)

    return base64.urlsafe_b64encode(
        signature
    ).rstrip(b"=").decode()


def verify_challenge(
    public_key,
    challenge,
    signature,
):
    """
    Verify a proof-of-possession signature.
    """

    padding = "=" * (-len(signature) % 4)

    signature_bytes = base64.urlsafe_b64decode(
        signature + padding
    )

    data = canonicalize_challenge(challenge)

    try:
        public_key.verify(
            signature_bytes,
            data,
        )

        return True

    except Exception:
        return False

def verify_token_proof(
    token_payload,
    challenge,
    signature,
):
    """
    Verify that the caller possesses the private key
    corresponding to the key bound to the AAT.
    """

    from aat.verify import jwk_to_public_key

    holder_jwk = token_payload["cnf"]["jwk"]

    holder_public_key = jwk_to_public_key(
        holder_jwk
    )

    return verify_challenge(
        holder_public_key,
        challenge,
        signature,
    )
