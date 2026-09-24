import json

import jwt

from authz.policy import is_request_allowed


def main():

    with open("aat2.jwt") as f:
        token = f.read().strip()

    payload = jwt.decode(
        token,
        options={"verify_signature": False},
    )

    print()
    print("AUTHORISATION TESTS")
    print("=" * 80)

    allowed = is_request_allowed(
        payload,
        "deploy",
        {
            "namespace": "payments",
            "environment": "production",
        },
    )

    print("DEPLOY PAYMENTS PRODUCTION:", allowed)

    denied_namespace = is_request_allowed(
        payload,
        "deploy",
        {
            "namespace": "billing",
            "environment": "production",
        },
    )

    print("DEPLOY BILLING PRODUCTION:", denied_namespace)

    denied_environment = is_request_allowed(
        payload,
        "deploy",
        {
            "namespace": "payments",
            "environment": "development",
        },
    )

    print("DEPLOY PAYMENTS DEVELOPMENT:", denied_environment)

    denied_action = is_request_allowed(
        payload,
        "read_cluster",
        {},
    )

    print("READ CLUSTER:", denied_action)


if __name__ == "__main__":
    main()
