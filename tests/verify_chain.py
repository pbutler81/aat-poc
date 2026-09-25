import json

from aat.keys import load_public_key
from aat.verify import verify_chain


def load_token(filename):
    with open(filename) as f:
        return f.read().strip()


def main():

    # ---------------------------------------------------------
    # Load token chain
    # ---------------------------------------------------------

    tokens = [
        load_token("aat0.jwt"),
        load_token("aat1.jwt"),
        load_token("aat2.jwt"),
    ]

    # ---------------------------------------------------------
    # Root issuer public key
    # ---------------------------------------------------------

    issuer_public_key = load_public_key(
        "issuer"
    )

    # ---------------------------------------------------------
    # Verify complete chain
    # ---------------------------------------------------------

    payloads = verify_chain(
        tokens,
        issuer_public_key,
    )

    # ---------------------------------------------------------
    # Display verified tokens
    # ---------------------------------------------------------

    for index, payload in enumerate(payloads):

        print()

        print(
            f"AAT{index} VERIFIED"
        )

        print("=" * 80)

        print(
            json.dumps(
                payload,
                indent=2,
            )
        )

    print()
    print("=" * 80)

    print(
        f"CHAIN VERIFIED: {len(payloads)} tokens"
    )


if __name__ == "__main__":
    main()
