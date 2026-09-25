from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel

from aat.pop import (
    create_challenge,
    decode_challenge,
    encode_challenge,
)
from authz.decision import authorize


app = FastAPI(
    title="AAT Resource Server"
)


BASE_DIR = Path(__file__).resolve().parent.parent


class DeployRequest(BaseModel):
    namespace: str
    environment: str


def load_token(filename):
    path = BASE_DIR / filename

    with open(path) as f:
        return f.read().strip()


@app.get("/health")
def health():
    return {
        "status": "ok"
    }


@app.get("/challenge")
def challenge():
    """
    Generate a challenge that the token holder
    must sign to prove possession of the private
    key bound to the final AAT.

    NOTE:

    At this stage of the POC the challenge is
    cryptographically verified, but the server
    does not yet maintain server-side state to
    guarantee single-use.

    Single-use challenge tracking is the next
    security improvement.
    """

    challenge = create_challenge()

    return {
        "challenge": encode_challenge(
            challenge
        ),
        "expires_in": 300,
    }


@app.post("/deploy")
def deploy(
    request: DeployRequest,
    http_request: Request,
    authorization: str | None = Header(
        default=None
    ),
    x_aat_challenge: str | None = Header(
        default=None
    ),
):
    # ---------------------------------------------------------
    # Authorization token
    # ---------------------------------------------------------

    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Missing Authorization header",
        )

    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Invalid Authorization header",
        )

    # ---------------------------------------------------------
    # Challenge
    # ---------------------------------------------------------

    if not x_aat_challenge:
        raise HTTPException(
            status_code=401,
            detail="Missing X-AAT-Challenge header",
        )

    # ---------------------------------------------------------
    # Proof-of-possession signature
    # ---------------------------------------------------------

    proof = http_request.headers.get(
        "X-AAT-Proof"
    )

    if not proof:
        raise HTTPException(
            status_code=401,
            detail="Missing X-AAT-Proof header",
        )

    # ---------------------------------------------------------
    # Final delegated token supplied by caller
    # ---------------------------------------------------------

    final_token = authorization[7:]

    # ---------------------------------------------------------
    # Decode challenge
    # ---------------------------------------------------------

    try:
        challenge = decode_challenge(
            x_aat_challenge
        )

    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Invalid challenge",
        )

    # ---------------------------------------------------------
    # Build delegation chain
    #
    # For the current POC:
    #
    # AAT₀ and AAT₁ are known locally by the resource server.
    #
    # The caller supplies the final delegated token.
    #
    # Later we can improve this so the complete chain is
    # supplied or reconstructed dynamically.
    # ---------------------------------------------------------

    tokens = [
        load_token("aat0.jwt"),
        load_token("aat1.jwt"),
        final_token,
    ]

    # ---------------------------------------------------------
    # Complete authorization
    # ---------------------------------------------------------

    try:
        allowed = authorize(
            tokens,
            challenge,
            proof,
            "deploy",
            {
                "namespace": request.namespace,
                "environment": request.environment,
            },
        )

    except Exception as exc:
        raise HTTPException(
            status_code=401,
            detail=(
                "Token verification failed: "
                f"{exc}"
            ),
        )

    # ---------------------------------------------------------
    # Valid token but insufficient authority
    # ---------------------------------------------------------

    if not allowed:
        raise HTTPException(
            status_code=403,
            detail="Request not authorised",
        )

    # ---------------------------------------------------------
    # Authorized operation
    # ---------------------------------------------------------

    return {
        "status": "deployed",
        "namespace": request.namespace,
        "environment": request.environment,
    }
