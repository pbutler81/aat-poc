import base64
import hashlib


def hash_token(token):
    digest = hashlib.sha256(
        token.encode("utf-8")
    ).digest()

    return base64.urlsafe_b64encode(
        digest
    ).rstrip(b"=").decode()


def extract_tools(payload):
    details = payload["authorization_details"]

    for detail in details:
        if detail["type"] == "attenuating_agent_token":
            return detail["tools"]

    return {}


def constraint_allows(parent_value, child_value):
    """
    Determine whether the child value is within the
    authority granted by the parent.

    '*' means the parent allows any value.
    """

    if parent_value == "*":
        return True

    return parent_value == child_value


def tool_is_attenuated(
    parent_constraints,
    child_constraints,
):
    """
    Determine whether the child's constraints are no
    broader than the parent's constraints.

    A child may introduce additional constraints.
    """

    for name, parent_value in parent_constraints.items():

        # If the parent restricts a particular argument,
        # the child must retain that restriction.
        if name in child_constraints:

            child_value = child_constraints[name]

            if not constraint_allows(
                parent_value,
                child_value,
            ):
                return False

        else:
            # The child omitted a constraint that the parent
            # explicitly restricted.
            #
            # That would remove the restriction, so it is
            # not allowed.
            return False

    return True


def is_attenuation(parent_payload, child_payload):
    parent_tools = extract_tools(parent_payload)
    child_tools = extract_tools(child_payload)

    # ---------------------------------------------------------
    # Every child tool must exist in the parent.
    # ---------------------------------------------------------

    for tool, child_constraints in child_tools.items():

        if tool not in parent_tools:
            return False

        parent_constraints = parent_tools[tool]

        # -----------------------------------------------------
        # Verify constraints.
        # -----------------------------------------------------

        if not tool_is_attenuated(
            parent_constraints,
            child_constraints,
        ):
            return False

    return True
