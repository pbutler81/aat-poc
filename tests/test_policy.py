import json

from aat.keys import load_public_key
from aat.verify import verify_chain
from authz.policy import is_request_allowed


def main():

    with open("aat0.jwt") as f:
        aat0 = f.read().strip()

    with open("aat1.jwt") as f:
        aat1 = f.read().strip()

    with open("aat2.jwt") as f:
        aat2 = f.read().strip()

    issuer_public_key = load_public_key("issuer")

    (
        _,
        _,
        aat2_payload,
    ) = verify_chain(
        aat0,
        aat1,
        aat2,
        issuer_public_key,
    )

    print()
    print("AAT₂")
    print("=" * 80)
    print(json.dumps(aat2_payload, indent=2))

    tests = [
        (
            "VALID DEPLOY",
            "deploy",
            {
                "namespace": "payments",
                "environment": "production",
            },
        ),
        (
            "WRONG NAMESPACE",
            "deploy",
            {
                "namespace": "billing",
                "environment": "production",
            },
        ),
        (
            "WRONG ENVIRONMENT",
            "deploy",
            {
                "namespace": "payments",
                "environment": "development",
            },
        ),
        (
            "UNAUTHORISED TOOL",
            "read_cluster",
            {},
        ),
        (
            "MISSING ENVIRONMENT",
            "deploy",
            {
                "namespace": "payments",
            },
        ),
    ]

    for name, tool, constraints in tests:

        allowed = is_request_allowed(
            aat2_payload,
            tool,
            constraints,
        )

        print()
        print(name)
        print("-" * 80)
        print(f"Tool:        {tool}")
        print(f"Constraints: {constraints}")
        print(f"Decision:    {'ALLOW' if allowed else 'DENY'}")


if __name__ == "__main__":
    main()
