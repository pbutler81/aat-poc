import json
import urllib.error
import urllib.request

from aat.keys import load_private_key
from aat.pop import decode_challenge, sign_challenge


BASE_URL = "http://localhost:8000"


def get_challenge():
    request = urllib.request.Request(
        f"{BASE_URL}/challenge",
        method="GET",
    )

    with urllib.request.urlopen(request) as response:
        data = json.loads(response.read().decode())

    return data["challenge"]


def create_deploy_request(encoded_challenge, proof):
    with open("aat2.jwt") as f:
        aat2 = f.read().strip()

    body = json.dumps(
        {
            "namespace": "payments",
            "environment": "production",
        }
    ).encode("utf-8")

    return urllib.request.Request(
        f"{BASE_URL}/deploy",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {aat2}",
            "X-AAT-Challenge": encoded_challenge,
            "X-AAT-Proof": proof,
        },
    )


def send_deploy(encoded_challenge, proof):
    request = create_deploy_request(encoded_challenge, proof)

    try:
        with urllib.request.urlopen(request) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def main():
    # Get one fresh challenge and sign it once.
    encoded_challenge = get_challenge()
    challenge = decode_challenge(encoded_challenge)

    tool_agent_private_key = load_private_key("tool-agent")
    proof = sign_challenge(tool_agent_private_key, challenge)

    print()
    print("HTTP REPLAY PROTECTION TEST")
    print("=" * 80)

    # First request should succeed.
    first_status, first_body = send_deploy(
        encoded_challenge,
        proof,
    )

    print(f"First request:  HTTP {first_status}")
    print(first_body)

    if first_status != 200:
        raise SystemExit(
            "FAIL: The initial valid deployment request did not succeed."
        )

    # Reuse the exact same challenge and proof.
    second_status, second_body = send_deploy(
        encoded_challenge,
        proof,
    )

    print()
    print(f"Replay request: HTTP {second_status}")
    print(second_body)

    if second_status != 401:
        raise SystemExit(
            "FAIL: The replayed request was not rejected with HTTP 401."
        )

    print()
    print("PASS: The replayed request was rejected.")


if __name__ == "__main__":
    main()
