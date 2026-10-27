from pathlib import Path
from threading import Lock
from time import monotonic

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

CHALLENGE_TTL_SECONDS = 300

# In-memory challenge store:
# encoded challenge -> monotonic expiry time
#
# Suitable for this single-process POC.
# Multi-worker deployments need shared storage.
_challenges: dict[str, float] = {}
_challenge_lock = Lock()


class DeployRequest(BaseModel):
    namespace: str
    environment: str


def load_token(filename):
    path = BASE_DIR / filename

    with open(path) as f:
        return f.read().strip()


def _remove_expired_challenges(now: float) -> None:
    """Remove expired challenges. Caller must hold the lock."""
    expired = [
        challenge
        for challenge, expiry in _challenges.items()
        if expiry <= now
    ]

    for challenge in expired:
        del _challenges[challenge]


def _challenge_is_valid(encoded_challenge: str) -> bool:
    """Check whether a challenge was issued and has not expired."""
    now = monotonic()

    with _challenge_lock:
        _remove_expired_challenges(now)

        expiry = _challenges.get(encoded_challenge)

        return expiry is not None and expiry > now


def _consume_challenge(encoded_challenge: str) -> bool:
    """
    Atomically consume a challenge.

    Returns False if it is unknown, expired or already consumed.
    """
    now = monotonic()

    with _challenge_lock:
        _remove_expired_challenges(now)

        expiry = _challenges.get(encoded_challenge)

        if expiry is None or expiry <= now:
            return False

        del _challenges[encoded_challenge]
        return True


@app.get("/health")
def health():
    return {
        "status": "ok"
    }


@app.get("/challenge")
def challenge():
    """
    Issue a challenge that must be signed by the final
    AAT holder.

    Challenges expire after five minutes and can be
    successfully consumed only once.
    """
    raw_challenge = create_challenge()
    encoded_challenge = encode_challenge(raw_challenge)

    now = monotonic()

    with _challenge_lock:
        _remove_expired_challenges(now)

        _challenges[encoded_challenge] = (
            now + CHALLENGE_TTL_SECONDS
        )

    return {
        "challenge": encoded_challenge,
        "expires_in": CHALLENGE_TTL_SECONDS,
    }


@app.post("/deploy")
def deploy(
    request: DeployRequest,
    http_request: Request,
    authorization: str | None = Header(default=None),
    x_aat_challenge: str | None = Header(default=None),
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

    final_token = authorization[7:].strip()

    if not final_token:
        raise HTTPException(
            status_code=401,
            detail="Missing bearer token",
        )

    # ---------------------------------------------------------
    # Challenge
    # ---------------------------------------------------------

    if not x_aat_challenge:
        raise HTTPException(
            status_code=401,
            detail="Missing X-AAT-Challenge header",
        )

    try:
        challenge = decode_challenge(x_aat_challenge)
    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Invalid challenge",
        )

    if not _challenge_is_valid(x_aat_challenge):
        raise HTTPException(
            status_code=401,
            detail="Unknown, expired or already-used challenge",
        )

    # ---------------------------------------------------------
    # Proof-of-possession signature
    # ---------------------------------------------------------

    proof = http_request.headers.get("X-AAT-Proof")

    if not proof:
        raise HTTPException(
            status_code=401,
            detail="Missing X-AAT-Proof header",
        )

    # ---------------------------------------------------------
    # Build delegation chain
    #
    # Current POC:
    # AAT₀ and AAT₁ are loaded locally.
    # The caller supplies AAT₂.
    # ---------------------------------------------------------

    try:
        tokens = [
            load_token("aat0.jwt"),
            load_token("aat1.jwt"),
            final_token,
        ]
    except OSError:
        raise HTTPException(
            status_code=500,
            detail="Unable to load delegation chain",
        )

    # ---------------------------------------------------------
    # Verify chain, proof-of-possession and authorization
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
    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Token verification failed",
        )

    if not allowed:
        raise HTTPException(
            status_code=403,
            detail="Request not authorised",
        )

    # ---------------------------------------------------------
    # Atomically consume the challenge
    #
    # Only one concurrent request can consume it successfully.
    # ---------------------------------------------------------

    if not _consume_challenge(x_aat_challenge):
        raise HTTPException(
            status_code=401,
            detail="Unknown, expired or already-used challenge",
        )

    # ---------------------------------------------------------
    # Authorized operation (simulated by this POC)
    # ---------------------------------------------------------

    return {
        "status": "deployed",
        "namespace": request.namespace,
        "environment": request.environment,
    }