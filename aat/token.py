import time
import uuid

import jwt


def create_token(
    private_key,
    issuer,
    subject,
    holder_public_key,
    capabilities,
    lifetime=3600,
    del_depth=0,
    del_max_depth=3,
    parent=None,
):
    now = int(time.time())

    payload = {
        "iss": issuer,
        "sub": subject,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + lifetime,

        "del_depth": del_depth,
        "del_max_depth": del_max_depth,

        "cnf": {
            "jwk": holder_public_key
        },

        "authorization_details": [
            {
                "type": "attenuating_agent_token",
                "tools": capabilities,
            }
        ],
    }
    
    if parent is not None:
        payload["parent"] = parent

    token = jwt.encode(
        payload,
        private_key,
        algorithm="EdDSA",
    )

    return token
