import json

from aat.keys import load_public_key
from aat.verify import verify_chain


def main():

    # ---------------------------------------------------------
    # Load tokens
    # ---------------------------------------------------------

    with open("aat0.jwt") as f:
        aat0 = f.read().strip()

    with open("aat1.jwt") as f:
        aat1 = f.read().strip()

    with open("aat2.jwt") as f:
        aat2 = f.read().strip()

    # ---------------------------------------------------------
    # Root issuer public key
    # ---------------------------------------------------------

    issuer_public_key = load_public_key("issuer")

    # ---------------------------------------------------------
    # Verify complete chain
    # ---------------------------------------------------------

    (
        aat0_payload,
        aat1_payload,
        aat2_payload,
    ) = verify_chain(
        aat0,
        aat1,
        aat2,
        issuer_public_key,
    )

    # ---------------------------------------------------------
    # Display results
    # ---------------------------------------------------------

    print()
    print("AAT₀ VERIFIED")
    print("=" * 80)
    print(json.dumps(aat0_payload, indent=2))

    print()
    print("AAT₁ VERIFIED")
    print("=" * 80)
    print(json.dumps(aat1_payload, indent=2))

    print()
    print("AAT₂ VERIFIED")
    print("=" * 80)
    print(json.dumps(aat2_payload, indent=2))


if __name__ == "__main__":
    main()
