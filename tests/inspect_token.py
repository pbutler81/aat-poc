import sys
import jwt


token = sys.argv[1]

header = jwt.get_unverified_header(token)
payload = jwt.decode(
    token,
    options={
        "verify_signature": False
    },
)

print()
print("HEADER")
print("=" * 80)

for key, value in header.items():
    print(f"{key}: {value}")

print()
print("PAYLOAD")
print("=" * 80)

import json
print(json.dumps(payload, indent=2))
