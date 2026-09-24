from aat.attenuation import extract_tools


def is_request_allowed(token_payload, action, constraints):
    """
    Check whether a request is allowed by the capabilities
    contained in the AAT.
    """

    tools = extract_tools(token_payload)

    if action not in tools:
        return False

    allowed_constraints = tools[action]

    for name, value in allowed_constraints.items():

        if name not in constraints:
            return False

        request_value = constraints[name]

        if value != "*" and value != request_value:
            return False

    return True
