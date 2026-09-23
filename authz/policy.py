from aat.attenuation import extract_tools


def is_request_allowed(token_payload, tool, request_constraints):
    """
    Determine whether a request is authorised by the AAT.

    The request must:
    - use a tool granted by the token
    - satisfy every constraint on that tool
    """

    tools = extract_tools(token_payload)

    if tool not in tools:
        return False

    token_constraints = tools[tool]

    for name, allowed_value in token_constraints.items():

        # Token requires this constraint, so the request
        # must provide it.
        if name not in request_constraints:
            return False

        requested_value = request_constraints[name]

        # '*' means any value is permitted.
        if allowed_value == "*":
            continue

        if requested_value != allowed_value:
            return False

    return True
