from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel

from aat.pop import create_challenge, decode_challenge, encode_challenge
from authz.decision import authorize


app = FastAPI(title="AAT Resource Server")


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
    must sign to prove possession of the
    private key bound to the AAT.
    """

    challenge = create_challenge()

    return {
        "challenge": encode_challenge(challenge),
        "expires_in": 300,
    }


@app.post("/deploy")
def deploy(
    request: DeployRequest,
    http_request: Request,
    authorization: str | None = Header(default=None),
    x_aat_challenge: str | None = Header(default=None),
):
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

    if not x_aat_challenge:
        raise HTTPException(
            status_code=401,
            detail="Missing X-AAT-Challenge header",
        )

    proof = http_request.headers.get("X-AAT-Proof")

    if not proof:
        raise HTTPException(
            status_code=401,
            detail="Missing X-AAT-Proof header",
        )

    token = authorization[7:]

    try:
        challenge = decode_challenge(
            x_aat_challenge
        )

    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Invalid challenge",
        )

    aat0 = load_token("aat0.jwt")
    aat1 = load_token("aat1.jwt")

    try:
        allowed = authorize(
            aat0,
            aat1,
            token,
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
            detail=f"Token verification failed: {exc}",
        )

    if not allowed:
        raise HTTPException(
            status_code=403,
            detail="Request not authorised",
        )

    return {
        "status": "deployed",
        "namespace": request.namespace,
        "environment": request.environment,
    }
