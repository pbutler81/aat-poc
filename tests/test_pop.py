import json

from aat.keys import load_private_key, load_public_key
from aat.pop import (
    create_challenge,
    sign_challenge,
    verify_challenge,
)


def main():

    # ---------------------------------------------------------
    # Tool Agent's key pair
    # ---------------------------------------------------------

    private_key = load_private_key("tool-agent")
    public_key = load_public_key("tool-agent")

    # ---------------------------------------------------------
    # Resource server creates a challenge
    # ---------------------------------------------------------

    challenge = create_challenge()

    print()
    print("RESOURCE SERVER CHALLENGE")
    print("=" * 80)
    print(json.dumps(challenge, indent=2))

    # ---------------------------------------------------------
    # Tool Agent signs the challenge
    # ---------------------------------------------------------

    signature = sign_challenge(
        private_key,
        challenge,
    )

    print()
    print("PROOF OF POSSESSION")
    print("=" * 80)
    print(signature)

    # ---------------------------------------------------------
    # Resource server verifies the proof
    # ---------------------------------------------------------

    valid = verify_challenge(
        public_key,
        challenge,
        signature,
    )

    print()
    print("VALID PROOF?")
    print("=" * 80)
    print(valid)


    # ---------------------------------------------------------
    # Attacker attempts to forge the proof
    # ---------------------------------------------------------

    fake_signature = sign_challenge(
        load_private_key("agent-b"),
        challenge,
    )

    forged = verify_challenge(
        public_key,
        challenge,
        fake_signature,
    )

    print()
    print("ATTACKER USING AGENT B KEY")
    print("=" * 80)
    print(forged)


    # ---------------------------------------------------------
    # Replay attack
    #
    # The signature was created for the original challenge.
    # Try using it against a new challenge.
    # ---------------------------------------------------------

    new_challenge = create_challenge()

    replay = verify_challenge(
        public_key,
        new_challenge,
        signature,
    )

    print()
    print("REPLAY ATTACK")
    print("=" * 80)
    print(replay)


if __name__ == "__main__":
    main()
