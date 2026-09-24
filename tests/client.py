import json
import urllib.request

from aat.keys import load_private_key
from aat.pop import decode_challenge, sign_challenge


BASE_URL = "http://localhost:8000"


def get_challenge():
    """
    Ask the resource server for a fresh PoP challenge.
    """

    request = urllib.request.Request(
        f"{BASE_URL}/challenge",
        method="GET",
    )

    with urllib.request.urlopen(request) as response:
        data = json.loads(
            response.read().decode()
        )

    return data["challenge"]


def deploy(encoded_challenge):
    """
    Sign the challenge with the private key bound
    to AAT₂ and send the authorization request.
    """

    challenge = decode_challenge(
        encoded_challenge
    )

    print()
    print("CHALLENGE")
    print("=" * 80)
    print(json.dumps(challenge, indent=2))

    tool_agent_private_key = load_private_key(
        "tool-agent"
    )

    proof = sign_challenge(
        tool_agent_private_key,
        challenge,
    )

    print()
    print("PROOF")
    print("=" * 80)
    print(proof)

    with open("aat2.jwt") as f:
        aat2 = f.read().strip()

    request_body = json.dumps(
        {
            "namespace": "payments",
            "environment": "production",
        }
    ).encode("utf-8")

    request = urllib.request.Request(
        f"{BASE_URL}/deploy",
        data=request_body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {aat2}",
            "X-AAT-Challenge": encoded_challenge,
            "X-AAT-Proof": proof,
        },
    )

    try:
        with urllib.request.urlopen(request) as response:
            response_body = response.read().decode()

            print()
            print("SERVER RESPONSE")
            print("=" * 80)
            print(response.status)
            print(response_body)

    except urllib.error.HTTPError as exc:
        response_body = exc.read().decode()

        print()
        print("SERVER ERROR")
        print("=" * 80)
        print(exc.code)
        print(response_body)


def main():

    encoded_challenge = get_challenge()

    print()
    print("ENCODED CHALLENGE")
    print("=" * 80)
    print(encoded_challenge)

    deploy(encoded_challenge)


if __name__ == "__main__":
    main()
