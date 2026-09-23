from aat.attenuation import is_attenuation


def capability_payload(tools):
    return {
        "authorization_details": [
            {
                "type": "attenuating_agent_token",
                "tools": tools,
            }
        ]
    }


# ------------------------------------------------------------
# 1. Simple tool attenuation
# ------------------------------------------------------------

parent = capability_payload({
    "deploy": {},
    "read_cluster": {},
})

child = capability_payload({
    "deploy": {},
})

assert is_attenuation(parent, child)

print("PASS: simple tool attenuation")


# ------------------------------------------------------------
# 2. Unknown tool must fail
# ------------------------------------------------------------

child = capability_payload({
    "delete_cluster": {},
})

assert not is_attenuation(parent, child)

print("PASS: unknown tool rejected")


# ------------------------------------------------------------
# 3. Wildcard → specific value
# ------------------------------------------------------------

parent = capability_payload({
    "deploy": {
        "namespace": "*",
    },
})

child = capability_payload({
    "deploy": {
        "namespace": "payments",
    },
})

assert is_attenuation(parent, child)

print("PASS: wildcard narrowed to specific namespace")


# ------------------------------------------------------------
# 4. Specific → different specific value
# ------------------------------------------------------------

parent = capability_payload({
    "deploy": {
        "namespace": "payments",
    },
})

child = capability_payload({
    "deploy": {
        "namespace": "production",
    },
})

assert not is_attenuation(parent, child)

print("PASS: namespace escape rejected")


# ------------------------------------------------------------
# 5. Specific → wildcard
# ------------------------------------------------------------

parent = capability_payload({
    "deploy": {
        "namespace": "payments",
    },
})

child = capability_payload({
    "deploy": {
        "namespace": "*",
    },
})

assert not is_attenuation(parent, child)

print("PASS: wildcard expansion rejected")


# ------------------------------------------------------------
# 6. Child adds a restriction
# ------------------------------------------------------------

parent = capability_payload({
    "deploy": {
        "namespace": "payments",
    },
})

child = capability_payload({
    "deploy": {
        "namespace": "payments",
        "environment": "production",
    },
})

assert is_attenuation(parent, child)

print("PASS: additional child restriction accepted")


# ------------------------------------------------------------
# 7. Child removes a parent restriction
# ------------------------------------------------------------

parent = capability_payload({
    "deploy": {
        "namespace": "payments",
        "environment": "production",
    },
})

child = capability_payload({
    "deploy": {
        "namespace": "payments",
    },
})

assert not is_attenuation(parent, child)

print("PASS: removed restriction rejected")
