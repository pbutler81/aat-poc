# Attenuating Authorization Tokens (AAT) Proof of Concept

A hands-on Python proof of concept exploring **Attenuating Authorization Tokens (AATs)** for secure delegation between users, agents, tools, and resource servers.

The project is based on the IETF Internet-Draft:

> OAuth Attenuating Agent Tokens
> `draft-niyikiza-oauth-attenuating-agent-tokens-01`

The goal is to understand and demonstrate how authorization can be passed through a chain of agents while ensuring that **each delegation can only reduce the authority available to the next participant**.

The POC now includes:

* Ed25519-signed JWTs
* Holder binding using JWKs
* Parent-token references
* Capability attenuation
* Delegation-depth enforcement
* Arbitrary-length delegation-chain verification
* Proof-of-possession
* Authorization policy evaluation
* Automated security tests
* A FastAPI resource server
* A working end-to-end HTTP authorization flow

---

# 1. Overview

Traditional authorization generally looks like:

```text
User
  |
  v
Application
  |
  v
Resource Server
```

An agentic system introduces additional delegation:

```text
User
  |
  v
Agent A
  |
  v
Agent B
  |
  v
Tool
  |
  v
Resource Server
```

This creates an important security problem.

If Agent A delegates authority to Agent B, how can the resource server know that Agent B has not acquired more authority than the user originally granted?

This proof of concept explores a cryptographic delegation model where each child token:

1. Is cryptographically signed.
2. Identifies its parent token.
3. Is signed by the holder of the parent token.
4. Contains a restricted set of capabilities.
5. Is bound to the key of the next holder.
6. Can further restrict downstream delegation depth.
7. Requires proof-of-possession of the final holder key.
8. Can be validated as part of the complete delegation chain.
9. Is evaluated against the actual resource request.

The fundamental security property is:

```text
Capabilities(AATₙ)
    ⊆
Capabilities(AATₙ₋₁)
    ⊆
...
    ⊆
Capabilities(AAT₁)
    ⊆
Capabilities(AAT₀)
```

A downstream agent can therefore **attenuate** authority but cannot expand it.

---

# 2. Project Goals

The project is deliberately being built incrementally.

The main goals are to understand:

* Public/private key cryptography
* Ed25519 signatures
* JWTs
* JSON Web Keys (JWKs)
* Holder binding
* Proof-of-possession
* Delegation chains
* Parent-token references
* Capability attenuation
* Delegation-depth attenuation
* Authorization decisions
* Agent-to-agent delegation
* HTTP resource-server enforcement
* Security attacks against delegated authorization

The eventual goal is to integrate the model with:

* OAuth
* Keycloak
* OAuth token exchange
* Real agent services
* LLM-based agents
* Real HTTP APIs
* Kubernetes/OpenShift

---

# 3. Current Architecture

The current demonstration uses:

```text
User
  |
  v
Root Issuer
  |
  | AAT₀
  v
Agent A
  |
  | AAT₁
  v
Agent B
  |
  | AAT₂
  v
Tool Agent / Client
  |
  | AAT₂
  | Challenge
  | Proof-of-Possession
  v
FastAPI Resource Server
  |
  | Verify delegation chain
  | Verify parent relationships
  | Verify attenuation
  | Verify delegation depth
  | Verify PoP
  | Evaluate policy
  v
ALLOW / DENY
```

Although the current demonstration generates three AATs, the **verification and authorization layers are no longer hard-coded to three tokens**.

Conceptually they can process:

```text
AAT₀
  |
  v
AAT₁
  |
  v
AAT₂
  |
  v
...
  |
  v
AATₙ
```

---

# 4. Key Architecture

Each participant has its own Ed25519 key pair.

```text
Root Issuer
    |
    +-- issuer private key
    +-- issuer public key

Agent A
    |
    +-- Agent A private key
    +-- Agent A public key

Agent B
    |
    +-- Agent B private key
    +-- Agent B public key

Tool Agent
    |
    +-- Tool Agent private key
    +-- Tool Agent public key
```

Private keys are never placed inside tokens.

The public key of the intended next holder is included in the token using the `cnf` claim.

---

# 5. Delegation Example

The current POC uses a deployment example.

## AAT₀

The Root Issuer grants:

```text
deploy(namespace=*)
read_cluster
```

AAT₀ is bound to Agent A.

```text
Root Issuer
     |
     | AAT₀
     | deploy(namespace=*)
     | read_cluster
     v
  Agent A
```

## AAT₁

Agent A delegates less authority to Agent B:

```text
deploy(namespace=payments)
```

The `read_cluster` capability is removed.

```text
AAT₀
deploy(namespace=*)
read_cluster
    |
    | attenuation
    v
AAT₁
deploy(namespace=payments)
```

This is valid because:

```text
deploy(payments) ⊆ deploy(*)
```

## AAT₂

Agent B further restricts the authority:

```text
deploy(
    namespace=payments,
    environment=production
)
```

The resulting chain is:

```text
AAT₀
deploy(namespace=*)
read_cluster
    |
    v
AAT₁
deploy(namespace=payments)
    |
    v
AAT₂
deploy(
    namespace=payments,
    environment=production
)
```

At every step the authority becomes narrower.

---

# 6. Core Security Property

The central property is:

```text
Child authority ⊆ Parent authority
```

A child may:

* Remove a capability.
* Add a restriction.
* Narrow an existing capability.
* Delegate to another holder.
* Reduce the maximum permitted delegation depth.

A child must not:

* Add a new capability.
* Remove an existing parent restriction.
* Broaden an existing constraint.
* Change its relationship to the supplied parent.
* Pretend to have been signed by another holder.
* Reset or skip delegation depth.
* Increase the maximum permitted delegation depth.

---

# 7. Cryptographic Model

The POC uses **Ed25519** asymmetric signatures.

```text
Private Key
    |
    | signs
    v
   JWT

Public Key
    |
    | verifies
    v
JWT signature
```

This allows each participant to create a child token using its own private key.

For example:

```text
issuer-private
      |
      | signs
      v
    AAT₀
      |
      | holder = Agent A
      v
   Agent A

agent-a-private
      |
      | signs
      v
    AAT₁
      |
      | holder = Agent B
      v
   Agent B

agent-b-private
      |
      | signs
      v
    AAT₂
      |
      | holder = Tool Agent
      v
 Tool Agent
```

Agent A never needs the Root Issuer's private key.

Agent B never needs Agent A's private key.

---

# 8. Key Files

The current keys are:

```text
keys/
├── issuer-private.pem
├── issuer-public.pem
├── agent-a-private.pem
├── agent-a-public.pem
├── agent-b-private.pem
├── agent-b-public.pem
├── tool-agent-private.pem
└── tool-agent-public.pem
```

Private keys must never be committed to Git.

Recommended `.gitignore` entries:

```gitignore
.venv/
keys/*-private.pem
__pycache__/
*.pyc
```

For a real implementation, private keys should use protected storage such as:

* HSM
* Cloud KMS
* Vault
* TPM
* Workload identity
* OS key stores

Local PEM files are used only for the POC.

---

# 9. Project Structure

The project is approximately:

```text
aat-poc/
│
├── aat/
│   ├── __init__.py
│   ├── keys.py
│   ├── token.py
│   ├── attenuation.py
│   ├── verify.py
│   └── pop.py
│
├── authz/
│   ├── __init__.py
│   ├── policy.py
│   └── decision.py
│
├── issuer/
│   └── issuer.py
│
├── agents/
│   ├── agent_a.py
│   └── agent_b.py
│
├── server/
│   ├── __init__.py
│   └── server.py
│
├── tests/
│   ├── generate_keys.py
│   ├── inspect_token.py
│   ├── test_attenuation.py
│   ├── test_pop.py
│   ├── test_aat_pop.py
│   ├── verify_chain.py
│   ├── test_policy.py
│   ├── test_authorization.py
│   ├── test_attacks.py
│   ├── test_depth.py
│   └── client.py
│
├── keys/
│
├── aat0.jwt
├── aat1.jwt
├── aat2.jwt
│
├── requirements.txt
└── README.md
```

The resource-server package is named `server` rather than `resource`.

This avoids a collision with Python's standard-library `resource` module.

---

# 10. Environment Setup

The project was developed on OpenSUSE Tumbleweed using Python.

Create a virtual environment:

```bash
cd ~/workspace/aat-poc

python3 -m venv .venv
```

Activate it:

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install cryptography PyJWT fastapi uvicorn
```

Save dependencies:

```bash
pip freeze > requirements.txt
```

For subsequent sessions:

```bash
cd ~/workspace/aat-poc
source .venv/bin/activate
```

The shell prompt should show:

```text
(.venv)
```

---

# 11. Python Import Path

The repository root is currently used as the Python module path.

Commands therefore use:

```bash
PYTHONPATH=. python ...
```

For example:

```bash
PYTHONPATH=. python tests/verify_chain.py
```

This allows imports such as:

```python
from aat.verify import verify_chain
```

to work correctly.

---

# 12. Generate Keys

Generate all key pairs:

```bash
PYTHONPATH=. python tests/generate_keys.py
```

Expected:

```text
Keys generated.
```

If keys are regenerated, all existing AATs must also be regenerated because their signatures were created using the previous keys.

Regenerate the chain using:

```bash
PYTHONPATH=. python issuer/issuer.py
PYTHONPATH=. python agents/agent_a.py
PYTHONPATH=. python agents/agent_b.py
```

---

# 13. Token Structure

Tokens contain claims including:

```text
iss
sub
jti
iat
exp
del_depth
del_max_depth
cnf
authorization_details
parent        # child tokens
```

The root authorization may look conceptually like:

```json
{
  "authorization_details": [
    {
      "type": "attenuating_agent_token",
      "tools": {
        "deploy": {
          "namespace": "*"
        },
        "read_cluster": {}
      }
    }
  ]
}
```

Holder binding uses:

```json
{
  "cnf": {
    "jwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "..."
    }
  }
}
```

---

# 14. JWT Verification

A JWT consists of:

```text
HEADER.PAYLOAD.SIGNATURE
```

A payload can be decoded without verifying its signature.

However:

> Decoding is not verification.

Only cryptographic signature verification establishes that a token was signed by the expected key.

---

# 15. Parent Token References

Every delegated child contains a reference to its parent.

The POC currently uses:

```text
SHA256(parent JWT)
```

Conceptually:

```text
parent JWT
    |
    | SHA-256
    v
parent hash
    |
    v
child.parent
```

When verifying a child, the verifier calculates:

```text
SHA256(actual supplied parent)
```

and compares it with:

```text
child.parent
```

A mismatch causes rejection.

This prevents a child from being detached from the token from which it was actually delegated.

---

# 16. Capability Attenuation

Capability attenuation is implemented in:

```text
aat/attenuation.py
```

The core invariant is:

```text
child ⊆ parent
```

For example:

Parent:

```json
{
  "deploy": {
    "namespace": "*"
  }
}
```

Child:

```json
{
  "deploy": {
    "namespace": "payments"
  }
}
```

This is valid.

A further child may add another restriction:

```json
{
  "deploy": {
    "namespace": "payments",
    "environment": "production"
  }
}
```

This is also valid because the authority has become narrower.

---

# 17. Removing Capabilities

Removing capabilities is allowed.

Parent:

```json
{
  "deploy": {},
  "read_cluster": {}
}
```

Child:

```json
{
  "deploy": {}
}
```

This satisfies:

```text
Child ⊆ Parent
```

---

# 18. Adding Capabilities

Adding a capability is not allowed.

Parent:

```json
{
  "deploy": {}
}
```

Invalid child:

```json
{
  "deploy": {},
  "delete_cluster": {}
}
```

The child cannot invent authority that the parent did not possess.

---

# 19. Current Constraint Model

The POC deliberately uses a simple constraint model.

Current rules are:

1. `*` means any value.
2. A specific parent value must be retained by the child.
3. A child may add additional restrictions.
4. A child may remove capabilities.
5. A child cannot add new capabilities.
6. A child cannot broaden an existing constraint.

For example:

```text
namespace=*
      |
      v
namespace=payments
```

is valid.

But:

```text
namespace=payments
      |
      v
namespace=*
```

is invalid.

This is a teaching implementation rather than a complete general-purpose constraint language.

---

# 20. Delegation Depth

Tokens contain delegation-depth controls:

```json
{
  "del_depth": 0,
  "del_max_depth": 3
}
```

The current demonstration uses:

```text
AAT₀ → del_depth = 0
AAT₁ → del_depth = 1
AAT₂ → del_depth = 2
```

Delegation depth is now **actively enforced during chain verification**.

For every child:

```text
child.del_depth = parent.del_depth + 1
```

This prevents a child from resetting or skipping its position in the chain.

For example, if the parent contains:

```text
del_depth = 1
del_max_depth = 3
```

the next valid child depth is:

```text
del_depth = 2
```

The following is rejected:

```text
del_depth = 0
```

because it attempts to reset delegation depth.

The following is also rejected:

```text
del_depth = 3
```

because it attempts to skip a delegation level.

---

# 21. Maximum Delegation Depth

A child cannot increase `del_max_depth`.

For example:

```text
Parent:

del_depth = 1
del_max_depth = 3
```

This child is invalid:

```text
Child:

del_depth = 2
del_max_depth = 10
```

A downstream agent must not be able to increase the delegation authority it received.

However, a child **may lower** `del_max_depth`.

For example:

```text
Parent:

del_depth = 1
del_max_depth = 3
```

may delegate:

```text
Child:

del_depth = 2
del_max_depth = 2
```

This means the child may use the delegated authority but cannot delegate it any further.

Delegation depth is therefore itself attenuable.

The verifier enforces:

```text
1. del_depth must be valid.

2. del_max_depth must be valid.

3. The root must begin at del_depth = 0.

4. A child increments del_depth by exactly one.

5. A child cannot increase del_max_depth.

6. A child cannot exceed del_max_depth.

7. A child may lower del_max_depth.
```

---

# 22. Delegation Depth Security Tests

Depth enforcement is tested using:

```bash
PYTHONPATH=. python tests/test_depth.py
```

The current results are:

```text
AAT DELEGATION DEPTH SECURITY TESTS
================================================================================

AAT₁: depth=1 max=3

✅ Legitimate depth 1 -> 2: allowed
✅ Reset delegation depth to 0: blocked
✅ Skip from depth 1 to depth 3: blocked
✅ Increase del_max_depth from 3 to 10: blocked
✅ Child depth exceeds del_max_depth: blocked
✅ Lower del_max_depth from 3 to 2: allowed

================================================================================
DEPTH TESTS COMPLETE
```

This demonstrates both:

```text
CAPABILITY ATTENUATION

deploy(*)
   |
   v
deploy(payments)
   |
   v
deploy(payments, production)
```

and:

```text
DELEGATION ATTENUATION

max_depth = 3
   |
   v
max_depth = 3
   |
   v
max_depth = 2
```

---

# 23. Arbitrary-Length Chain Verification

The chain verifier lives in:

```text
aat/verify.py
```

It is no longer hard-coded to:

```text
AAT₀ → AAT₁ → AAT₂
```

Instead, it accepts a token chain.

Conceptually:

```python
tokens = [
    aat0,
    aat1,
    aat2,
]
```

The verifier:

1. Verifies the root token using the trusted Root Issuer public key.
2. Walks each remaining token in order.
3. Verifies each child using the holder key from its parent.
4. Verifies the parent reference.
5. Verifies capability attenuation.
6. Verifies delegation-depth rules.
7. Returns the verified payloads.

Conceptually:

```text
tokens
  |
  v
AAT₀
  |
  | verify root
  v
AAT₁
  |
  | verify child
  v
AAT₂
  |
  | verify child
  v
...
  |
  v
AATₙ
```

This means the verification engine can support:

```text
AAT₀
```

or:

```text
AAT₀ → AAT₁
```

or:

```text
AAT₀ → AAT₁ → AAT₂
```

or longer chains:

```text
AAT₀ → AAT₁ → AAT₂ → ... → AATₙ
```

subject to the delegation-depth restrictions.

---

# 24. Complete Chain Verification

Run:

```bash
PYTHONPATH=. python tests/verify_chain.py
```

For every child, verification establishes:

```text
Parent holder key
       |
       v
Verify child signature
       |
       v
Verify parent reference
       |
       v
Verify capability attenuation
       |
       v
Verify delegation depth
       |
       v
Next child
```

A token is therefore not trusted simply because its individual JWT signature is valid.

Its place in the delegation chain must also be valid.

---

# 25. Holder Binding

AATs bind authorization to a holder key.

For example:

```text
AAT₂
  |
  +-- cnf.jwk
        |
        +-- Tool Agent public key
```

The Tool Agent must possess the corresponding private key.

This turns the final token into more than a simple bearer credential.

---

# 26. Proof-of-Possession

The resource server generates a challenge:

```json
{
  "challenge": "random-value",
  "timestamp": 1234567890
}
```

The holder signs the challenge using its private key.

```text
Resource Server
       |
       | challenge
       v
   Tool Agent
       |
       | sign using private key
       v
Resource Server
       |
       | verify against cnf.jwk
       v
   VALID / INVALID
```

The public key used for verification comes from the **final verified AAT**.

---

# 27. Proof-of-Possession Tests

Run:

```bash
PYTHONPATH=. python tests/test_pop.py
```

The tests demonstrate:

* Correct private key succeeds.
* Wrong private key fails.
* A proof generated for another challenge fails.

Token-bound PoP can also be tested using:

```bash
PYTHONPATH=. python tests/test_aat_pop.py
```

The important question is not simply:

```text
Do you possess the token?
```

It is:

```text
Can you prove possession of the private key
bound to the final token?
```

---

# 28. Authorization Policy

Cryptographic verification answers:

```text
Is this token authentic?
```

Delegation verification answers:

```text
Was this token legitimately delegated?
```

Attenuation answers:

```text
Did the child remain within the parent's authority?
```

Delegation-depth verification answers:

```text
Was this delegation permitted to continue?
```

Proof-of-possession answers:

```text
Does the caller possess the final holder's private key?
```

Policy answers:

```text
Is this particular operation permitted?
```

These are separate security decisions.

---

# 29. Authorization Decision Layer

The authorization logic lives in:

```text
authz/decision.py
```

Authorization now accepts the delegation chain rather than three individually named AAT arguments.

Conceptually:

```python
authorize(
    tokens,
    challenge,
    proof,
    action,
    constraints,
)
```

The authorization flow is:

```text
Token chain
    |
    v
verify_chain(tokens)
    |
    v
verified payloads
    |
    v
final_payload = payloads[-1]
    |
    +-------------------+
    |                   |
    v                   v
Verify PoP         Evaluate policy
    |                   |
    +---------+---------+
              |
              v
         ALLOW / DENY
```

This removes the fixed assumption that authorization always ends at `AAT₂`.

Authorization is performed against the **final verified token in the supplied chain**.

---

# 30. Policy Example

Suppose the final token grants:

```text
deploy:
  namespace: payments
  environment: production
```

This request is allowed:

```json
{
  "action": "deploy",
  "namespace": "payments",
  "environment": "production"
}
```

This request is denied:

```json
{
  "action": "deploy",
  "namespace": "billing",
  "environment": "production"
}
```

This is also denied:

```json
{
  "action": "deploy",
  "namespace": "payments",
  "environment": "development"
}
```

And:

```json
{
  "action": "read_cluster"
}
```

is denied because `read_cluster` was removed earlier in the delegation chain.

---

# 31. Security Attack Tests

Run:

```bash
PYTHONPATH=. python tests/test_attacks.py
```

The current suite demonstrates:

```text
AAT SECURITY TESTS
================================================================================
✅ Tamper with AAT₂: blocked
✅ Add read_cluster capability: blocked
✅ Broaden namespace to *: blocked
✅ Change parent reference: blocked
✅ Sign AAT₂ with Agent A key: blocked
✅ Proof signed with wrong key: blocked
✅ Replay proof against new challenge: blocked
```

These tests turn the intended security properties into executable checks.

---

# 32. Attack — Token Tampering

If an attacker changes:

```text
namespace=payments
```

to:

```text
namespace=*
```

without generating a legitimate new signature, JWT signature verification fails.

Result:

```text
DENY
```

---

# 33. Attack — Capability Expansion

If the parent grants:

```text
deploy
```

and the child attempts to add:

```text
read_cluster
```

the attenuation check rejects the child.

A downstream participant cannot invent a capability.

---

# 34. Attack — Constraint Broadening

Parent:

```text
namespace=payments
```

Invalid child:

```text
namespace=*
```

This increases authority and is rejected.

---

# 35. Attack — Parent Substitution

A child contains:

```text
parent = SHA256(actual parent JWT)
```

If a different parent is supplied, the calculated hash does not match.

Result:

```text
DENY
```

---

# 36. Attack — Wrong Delegation Key

AAT₂ must be signed by the holder of AAT₁.

If Agent A signs a token that should have been signed by Agent B, verification uses Agent B's public key and the signature fails.

Result:

```text
DENY
```

---

# 37. Attack — Wrong PoP Key

The final AAT is bound to the Tool Agent's public key.

If another private key signs the challenge, verification against the final token's `cnf.jwk` fails.

Result:

```text
DENY
```

---

# 38. Attack — Different Challenge Replay

Suppose a proof is created for:

```text
Challenge A
```

and presented against:

```text
Challenge B
```

The signed data differs, so verification fails.

Result:

```text
DENY
```

This protects against using a proof with a different challenge.

However, **reusing the exact same valid challenge and proof is not yet prevented server-side**.

That is the next major security improvement.

---

# 39. FastAPI Resource Server

The POC includes a FastAPI resource server:

```text
server/server.py
```

Start it with:

```bash
PYTHONPATH=. uvicorn server.server:app --host 0.0.0.0 --port 8000
```

The server exposes:

```text
GET /health
GET /challenge
POST /deploy
```

---

# 40. Challenge Endpoint

Request a challenge:

```bash
curl http://localhost:8000/challenge
```

The response contains an encoded challenge:

```json
{
  "challenge": "eyJjaGFsbGVuZ2UiOi...",
  "expires_in": 300
}
```

The encoded value represents the exact challenge object that the client must sign.

Conceptually:

```json
{
  "challenge": "d4a7ba6e-b64c-436a-943c-1726a76a4b26",
  "timestamp": 1790242631
}
```

Encoding the complete object avoids the client and server independently reconstructing the data to be signed.

---

# 41. Current Challenge Limitation

The challenge response advertises:

```text
expires_in = 300
```

The intended challenge properties are:

```text
fresh
+
unpredictable
+
short-lived
+
bound to the proof
+
single-use
```

The current implementation cryptographically binds a proof to its challenge.

However, the resource server does **not yet maintain server-side challenge state**.

Therefore:

```text
Proof for Challenge A
        |
        X
Challenge B
```

is blocked.

But:

```text
Challenge A + valid proof
```

could currently be replayed using that exact same challenge/proof pair.

The next security improvement is to track challenge issuance and consumption server-side.

---

# 42. HTTP Proof-of-Possession Flow

The current HTTP flow is:

```text
Tool Agent
    |
    | GET /challenge
    v
Resource Server
    |
    | encoded challenge
    v
Tool Agent
    |
    | decode challenge
    |
    | sign challenge
    | using tool-agent-private.pem
    v
POST /deploy
    |
    | Authorization: Bearer <final AAT>
    | X-AAT-Challenge: <challenge>
    | X-AAT-Proof: <signature>
    v
Resource Server
```

---

# 43. Deploy Endpoint

The resource server exposes:

```text
POST /deploy
```

The request contains:

```text
Authorization: Bearer <final AAT>
X-AAT-Challenge: <encoded challenge>
X-AAT-Proof: <signature>
```

with a body such as:

```json
{
  "namespace": "payments",
  "environment": "production"
}
```

---

# 44. Resource-Server Authorization Flow

Conceptually:

```text
Incoming request
      |
      v
Construct token chain
      |
      v
Verify complete chain
      |
      +------------------+
      |                  |
    valid             invalid
      |                  |
      v                  v
Verify PoP              DENY
      |
      +------------------+
      |                  |
    valid             invalid
      |                  |
      v                  v
Evaluate policy         DENY
      |
      +------------------+
      |                  |
    allow               deny
      |                  |
      v                  v
     200                403
```

---

# 45. Current Server Chain Resolution

The verification and authorization layers support arbitrary chain lengths.

However, the current HTTP demonstration still obtains the chain in a simplified way.

The server locally loads:

```text
aat0.jwt
aat1.jwt
```

while the client supplies the final token.

Conceptually:

```text
Server filesystem
    |
    +-- AAT₀
    +-- AAT₁

HTTP request
    |
    +-- AAT₂
```

The server builds:

```python
tokens = [
    load_token("aat0.jwt"),
    load_token("aat1.jwt"),
    final_token,
]
```

and passes that list to the generic authorization layer.

Therefore there are two separate concepts:

```text
CHAIN VERIFICATION

Arbitrary length
      |
      v
Implemented
```

versus:

```text
HTTP CHAIN DISCOVERY / TRANSPORT

Currently simplified
      |
      v
Still to improve
```

A future implementation should dynamically transport or resolve the complete delegation chain.

---

# 46. End-to-End HTTP Client

The POC includes:

```text
tests/client.py
```

Run it while the server is running:

```bash
PYTHONPATH=. python tests/client.py
```

The client:

1. Requests a challenge.
2. Receives the encoded challenge.
3. Decodes it.
4. Signs it using the Tool Agent private key.
5. Loads the final AAT.
6. Sends the token, challenge, proof and requested deployment.
7. Displays the response.

---

# 47. Successful End-to-End Test

A successful run produces:

```text
SERVER RESPONSE
================================================================================
200
{"status":"deployed","namespace":"payments","environment":"production"}
```

This means:

```text
Root token valid
        +
delegation chain valid
        +
parent references valid
        +
capability attenuation valid
        +
delegation depth valid
        +
holder binding valid
        +
proof-of-possession valid
        +
requested capability exists
        +
namespace = payments
        +
environment = production
        =
ALLOW
```

The current endpoint simulates deployment.

It does not yet perform a real Kubernetes/OpenShift operation.

---

# 48. Token Expiry

Tokens contain:

```text
iat
exp
```

PyJWT validates token expiry.

An expired token produces:

```text
jwt.exceptions.ExpiredSignatureError
```

During development this occurred when an older chain was reused after its one-hour lifetime had elapsed.

Regenerate the chain using:

```bash
PYTHONPATH=. python issuer/issuer.py
PYTHONPATH=. python agents/agent_a.py
PYTHONPATH=. python agents/agent_b.py
```

Expired tokens being rejected is expected security behaviour.

---

# 49. Current Run Sequence

Activate the environment:

```bash
cd ~/workspace/aat-poc
source .venv/bin/activate
```

Generate keys if required:

```bash
PYTHONPATH=. python tests/generate_keys.py
```

Generate the token chain:

```bash
PYTHONPATH=. python issuer/issuer.py
PYTHONPATH=. python agents/agent_a.py
PYTHONPATH=. python agents/agent_b.py
```

Verify the chain:

```bash
PYTHONPATH=. python tests/verify_chain.py
```

Run policy tests:

```bash
PYTHONPATH=. python tests/test_policy.py
```

Run authorization tests:

```bash
PYTHONPATH=. python tests/test_authorization.py
```

Run PoP tests:

```bash
PYTHONPATH=. python tests/test_pop.py
PYTHONPATH=. python tests/test_aat_pop.py
```

Run attack tests:

```bash
PYTHONPATH=. python tests/test_attacks.py
```

Run delegation-depth tests:

```bash
PYTHONPATH=. python tests/test_depth.py
```

Start the server:

```bash
PYTHONPATH=. uvicorn server.server:app --host 0.0.0.0 --port 8000
```

In another terminal:

```bash
cd ~/workspace/aat-poc
source .venv/bin/activate
PYTHONPATH=. python tests/client.py
```

---

# 50. Security Boundary

The resource server is the final authorization enforcement point.

It does not blindly trust:

```text
Agent A
Agent B
Tool Agent
```

Instead it independently verifies:

```text
AAT chain
    +
signatures
    +
parent relationships
    +
capability attenuation
    +
delegation depth
    +
holder binding
    +
proof-of-possession
    +
request policy
```

---

# 51. Threat Model

The POC assumes downstream participants may be compromised.

For example:

```text
Root Issuer
     |
     v
  Agent A
     |
     v
Compromised Agent B
     |
     v
Resource Server
```

The key security question is:

> What damage can a compromised downstream agent cause?

The intended answer is:

```text
No more than the authority delegated to it.
```

If Agent B receives:

```text
deploy(namespace=payments)
```

it must not be able to create:

```text
deploy(namespace=billing)
```

or:

```text
read_cluster
```

or:

```text
delete_cluster
```

It must also not be able to extend the permitted delegation depth.

---

# 52. Least Privilege

Without attenuation:

```text
User
  |
  | full authority
  v
Agent A
  |
  | full authority
  v
Agent B
  |
  | full authority
  v
Tool
```

With attenuation:

```text
User
  |
  | deploy(*)
  | read_cluster
  v
Agent A
  |
  | deploy(payments)
  v
Agent B
  |
  | deploy(payments, production)
  v
Tool
```

Authority narrows as the task becomes more specific.

---

# 53. Why Delegation Depth Matters

Capability attenuation limits:

```text
WHAT an agent can do.
```

Delegation-depth attenuation limits:

```text
HOW FAR that authority can be delegated.
```

These are complementary controls.

For example:

```text
Agent B authority:

deploy(
    namespace=payments,
    environment=production
)

del_depth = 2
del_max_depth = 2
```

means:

```text
Agent B / Tool may perform the permitted action

BUT

the authority cannot be delegated again.
```

This is particularly useful in agentic systems where agents may dynamically decide to delegate work to other agents.

---

# 54. Current Security Invariants

The implementation currently aims to enforce:

```text
Invariant 1:
A token must have a valid signature.

Invariant 2:
A child must be signed by the holder of its parent.

Invariant 3:
A child must reference its actual parent.

Invariant 4:
A child cannot have more capability authority than its parent.

Invariant 5:
The root delegation depth must begin at 0.

Invariant 6:
A child must increment delegation depth by exactly one.

Invariant 7:
A child cannot increase del_max_depth.

Invariant 8:
A child cannot exceed del_max_depth.

Invariant 9:
A child may lower del_max_depth.

Invariant 10:
The final holder must prove possession of its private key.

Invariant 11:
A proof must correspond to the supplied challenge.

Invariant 12:
Expired tokens cannot be used.

Invariant 13:
The requested action must be permitted by the final token.

Invariant 14:
The resource server makes the final authorization decision.
```

---

# 55. Current Implementation Checklist

## Core Cryptography

* [x] Ed25519 key generation
* [x] Private/public key loading
* [x] JWT signing
* [x] JWT verification
* [x] Public-key JWK representation

## AAT

* [x] Root AAT
* [x] Holder binding
* [x] Authorization details
* [x] Parent token hashing
* [x] Agent A delegation
* [x] Agent B delegation
* [x] Capability attenuation
* [x] Delegation-depth claims
* [x] Maximum delegation-depth attenuation

## Verification

* [x] Root signature verification
* [x] Child signature verification
* [x] Parent-reference verification
* [x] Capability attenuation verification
* [x] Token expiry verification
* [x] Delegation-depth verification
* [x] Prevent depth reset
* [x] Prevent depth skipping
* [x] Prevent increasing `del_max_depth`
* [x] Prevent exceeding `del_max_depth`
* [x] Allow lowering `del_max_depth`
* [x] Arbitrary-length chain verification

## Proof-of-Possession

* [x] Challenge generation
* [x] Challenge encoding
* [x] Challenge decoding
* [x] Challenge signing
* [x] Signature verification
* [x] Token-bound holder verification
* [x] Wrong-key rejection
* [x] Different-challenge rejection
* [x] HTTP challenge/proof flow

## Authorization

* [x] Capability lookup
* [x] Constraint checking
* [x] Authorization decision layer
* [x] Resource-server enforcement
* [x] Token-list based authorization
* [x] Authorization using final verified payload
* [x] Chain-length-agnostic authorization layer

## HTTP

* [x] FastAPI resource server
* [x] `/health`
* [x] `/challenge`
* [x] `/deploy`
* [x] Bearer AAT handling
* [x] Challenge transport
* [x] PoP transport
* [x] End-to-end HTTP client
* [x] Successful authorized deployment response

## Security Tests

* [x] JWT tampering
* [x] Capability escalation
* [x] Constraint broadening
* [x] Parent substitution
* [x] Wrong child signing key
* [x] Wrong PoP key
* [x] Proof against different challenge
* [x] Delegation-depth reset
* [x] Delegation-depth skipping
* [x] Maximum-depth escalation
* [x] Maximum-depth exceedance
* [x] Maximum-depth attenuation

---

# 56. Current Limitations

This remains an educational proof of concept.

## Challenge Replay

The server does not yet track issued and consumed challenges.

A proof cannot be reused with a different challenge, but the exact same valid challenge/proof pair is not yet guaranteed to be single-use.

## Challenge Expiry

The HTTP response advertises a 300-second lifetime, but server-side challenge-state enforcement still needs to be strengthened.

## Constraint Semantics

The capability model currently supports simple wildcard/equality semantics.

It is not a complete authorization constraint language.

## Parent References

The POC currently uses:

```text
SHA256(parent JWT)
```

This is useful for demonstrating parent binding but may need to evolve to align more closely with the relevant specification semantics.

## HTTP Chain Discovery

The verification engine supports arbitrary chain lengths.

However, the current HTTP server still locally loads earlier tokens and receives the final token from the client.

Dynamic chain discovery or transport has not yet been implemented.

## Local Key Storage

Private keys are stored as PEM files.

This is appropriate only for the local POC.

## No OAuth Yet

The AAT mechanics are currently demonstrated independently from OAuth.

## No Keycloak Integration Yet

Keycloak integration is deliberately being left until the underlying AAT mechanics are understood.

## No Real Agent Yet

The current agents are deterministic Python programs rather than autonomous or LLM-based agents.

## No Real Deployment Yet

The `/deploy` endpoint simulates a deployment.

It does not currently modify Kubernetes or OpenShift resources.

---

# 57. Next Security Step — Single-Use Challenges

The immediate next security improvement is server-side challenge tracking.

The desired behaviour is:

```text
GET /challenge
      |
      v
Server generates Challenge A
      |
      v
Server records Challenge A as UNUSED
      |
      v
Client signs Challenge A
      |
      v
POST /deploy
      |
      v
Server verifies Challenge A
      |
      v
Server atomically marks Challenge A as USED
      |
      v
Request succeeds
```

If the same request is replayed:

```text
Challenge A
+
same valid proof
      |
      v
Server checks state
      |
      v
Challenge already USED
      |
      v
DENY
```

The desired test is:

```text
First request:
200 OK

Replay same challenge + proof:
401 Unauthorized
```

Challenges should eventually be:

```text
fresh
+
unpredictable
+
short-lived
+
single-use
```

---

# 58. Remaining Work

Completed during the current security-hardening phase:

* [x] Enforce delegation depth
* [x] Prevent delegation-depth reset
* [x] Prevent delegation-depth skipping
* [x] Prevent increasing `del_max_depth`
* [x] Allow attenuation of `del_max_depth`
* [x] Support arbitrary delegation-chain lengths
* [x] Make `verify_chain()` chain-length agnostic
* [x] Make authorization accept a token chain
* [x] Authorize using the final verified payload
* [x] Add delegation-depth security tests

Remaining:

* [ ] Add server-side single-use challenge state
* [ ] Reject reuse of an already consumed challenge
* [ ] Enforce challenge expiration server-side
* [ ] Add replay-cache behaviour
* [ ] Improve constraint semantics
* [ ] Improve parent-reference semantics
* [ ] Strengthen malformed-token validation
* [ ] Add skipped-parent tests
* [ ] Add holder-substitution tests
* [ ] Add more expired-token tests
* [ ] Add issuer validation hardening
* [ ] Add audience validation
* [ ] Add key IDs (`kid`)
* [ ] Add JWKS
* [ ] Add key rotation
* [ ] Add revocation
* [ ] Replace static token files
* [ ] Replace local private-key storage
* [ ] Add structured security logging
* [ ] OAuth integration
* [ ] Keycloak integration
* [ ] OAuth token exchange
* [ ] Real agent services
* [ ] LLM agent
* [ ] Real tool/API integration
* [ ] Kubernetes integration
* [ ] OpenShift integration

---

# 59. Roadmap

```text
Phase 1
Basic signed token
    |
    v
COMPLETE

Phase 2
Capabilities
    |
    v
COMPLETE

Phase 3
Capability attenuation
    |
    v
COMPLETE

Phase 4
Delegation chain
    |
    v
COMPLETE

Phase 5
Offline chain verification
    |
    v
COMPLETE

Phase 6
Proof-of-possession
    |
    v
COMPLETE

Phase 7
Authorization policy
    |
    v
COMPLETE

Phase 8
Attack/security tests
    |
    v
COMPLETE

Phase 9
FastAPI resource server
    |
    v
COMPLETE

Phase 10
HTTP proof-of-possession
    |
    v
COMPLETE

Phase 11
End-to-end HTTP authorization
    |
    v
COMPLETE

Phase 12
Delegation-depth enforcement
    |
    v
COMPLETE

Phase 13
Arbitrary-length chain verification
    |
    v
COMPLETE

Phase 14
Single-use challenge / replay protection
    |
    v
NEXT

Phase 15
Further security hardening
    |
    v
PLANNED

Phase 16
OAuth integration
    |
    v
PLANNED

Phase 17
Keycloak integration
    |
    v
PLANNED

Phase 18
Real agent workflow
    |
    v
PLANNED

Phase 19
LLM agent
    |
    v
PLANNED

Phase 20
Real tool / OpenShift integration
    |
    v
PLANNED
```

---

# 60. Future OAuth Integration

The eventual architecture could introduce an OAuth Authorization Server:

```text
User
  |
  v
OAuth Authorization Server
  |
  | initial authorization
  v
Agent A
  |
  | attenuated delegation
  v
Agent B
  |
  | attenuated delegation
  v
Tool
  |
  v
Resource Server
```

Areas to investigate include:

* OAuth authorization
* Token exchange
* Sender-constrained tokens
* Proof-of-possession
* Client authentication
* Audience restrictions
* Token lifetime
* Revocation

---

# 61. Future Keycloak Integration

Keycloak is deliberately not being introduced until the AAT security model is understood independently.

The eventual architecture may resemble:

```text
                 Keycloak
                    |
                    | OAuth
                    v
                 Agent A
                    |
                    | AAT
                    v
                 Agent B
                    |
                    | AAT
                    v
               Tool Agent
                    |
                    | PoP
                    v
             Resource Server
```

Potential areas to explore include:

* Keycloak clients
* OAuth token exchange
* JWT signing
* Custom claims
* Protocol mappers
* Authorization services
* Client authentication
* Sender-constrained tokens
* Custom protocol extensions

---

# 62. Future Agent Workflow

The deterministic Python agents can eventually be replaced or augmented with real agent services.

For example:

```text
User:
"Deploy the payments application."
        |
        v
Planning Agent
        |
        | deploy(namespace=payments)
        v
Deployment Agent
        |
        | deploy(
        |   namespace=payments,
        |   environment=production
        | )
        v
Deployment Tool
        |
        v
Resource Server
```

Each delegation creates a new, more narrowly scoped authorization artifact.

---

# 63. Future LLM Agent

An LLM could eventually participate in the delegation chain.

For example:

```text
User
  |
  v
LLM Planning Agent
  |
  | attenuated AAT
  v
Execution Agent
  |
  | attenuated AAT
  v
Deployment Tool
```

The important principle is:

> The LLM should not be the authorization enforcement point.

The LLM may decide:

```text
"I want to deploy this application."
```

But the resource server independently decides:

```text
"Is this request actually authorized?"
```

Security enforcement therefore remains deterministic and outside the probabilistic model.

---

# 64. Future OpenShift/Kubernetes Integration

A useful real-world target is Kubernetes or OpenShift.

Root authority:

```text
deploy(namespace=*)
```

Agent A:

```text
deploy(namespace=payments)
```

Agent B:

```text
deploy(
    namespace=payments,
    environment=production
)
```

The resource server could map this to a real cluster operation only after the authorization chain has been successfully verified.

Conceptually:

```text
POST /api/deploy
      |
      v
Verify AAT chain
      |
      v
Verify PoP
      |
      v
Evaluate policy
      |
      v
Kubernetes / OpenShift API
```

---

# 65. Potential Final Architecture

```text
                         USER
                          |
                          v
                       KEYCLOAK
                          |
                          | OAuth authorization
                          v
                   LLM / AGENT A
                          |
                          | attenuated AAT
                          v
                       AGENT B
                          |
                          | further attenuation
                          v
                     TOOL AGENT
                          |
                          | proof-of-possession
                          v
                 AAT RESOURCE SERVER
                          |
                          | verify chain
                          | verify attenuation
                          | verify delegation depth
                          | verify PoP
                          | evaluate policy
                          v
                 KUBERNETES / OPENSHIFT
```

---

# 66. Key Lessons

## Delegation Is Not Token Forwarding

A downstream agent should not simply receive the original user's unrestricted credential.

It should receive deliberately restricted authority.

## Signatures Are Not Enough

A valid JWT signature proves that a particular key signed the token.

The verifier must also establish:

```text
Was that key authorized to create this child?
```

## Parent Relationships Matter

A child must be cryptographically tied to the authorization from which it was derived.

## Attenuation Is the Core Property

Every delegation must satisfy:

```text
child <= parent
```

## Delegation Depth Is Also Authority

The ability to delegate further is itself a form of authority.

Therefore:

```text
del_max_depth
```

must not be expandable by a child.

## Holder Binding Reduces Bearer-Token Risk

Possession of the JWT alone should not be sufficient.

The caller must also possess the private key corresponding to the final token's:

```text
cnf.jwk
```

## PoP and Authorization Are Different

PoP establishes:

```text
You possess the correct private key.
```

It does not establish:

```text
You are allowed to perform this operation.
```

Policy makes that decision.

## The Resource Server Is the Enforcement Point

Agents request actions.

They do not make the final security decision.

---

# 67. Quick Start

Enter the repository:

```bash
cd ~/workspace/aat-poc
```

Activate the environment:

```bash
source .venv/bin/activate
```

Install dependencies if required:

```bash
pip install -r requirements.txt
```

Generate keys:

```bash
PYTHONPATH=. python tests/generate_keys.py
```

Generate the chain:

```bash
PYTHONPATH=. python issuer/issuer.py
PYTHONPATH=. python agents/agent_a.py
PYTHONPATH=. python agents/agent_b.py
```

Verify the chain:

```bash
PYTHONPATH=. python tests/verify_chain.py
```

Run authorization tests:

```bash
PYTHONPATH=. python tests/test_authorization.py
```

Run security tests:

```bash
PYTHONPATH=. python tests/test_attacks.py
PYTHONPATH=. python tests/test_depth.py
```

Start the resource server:

```bash
PYTHONPATH=. uvicorn server.server:app --host 0.0.0.0 --port 8000
```

In another terminal:

```bash
cd ~/workspace/aat-poc
source .venv/bin/activate
PYTHONPATH=. python tests/client.py
```

Expected final response:

```text
SERVER RESPONSE
================================================================================
200
{"status":"deployed","namespace":"payments","environment":"production"}
```

---

# 68. Current Status

The POC currently demonstrates:

```text
Root Issuer
     |
     | AAT₀
     | broad authority
     v
Agent A
     |
     | attenuate capability
     | AAT₁
     v
Agent B
     |
     | attenuate capability
     | enforce delegation depth
     | AAT₂
     v
Tool Agent
     |
     | request challenge
     | prove possession
     v
FastAPI Resource Server
     |
     | verify arbitrary-length chain
     | verify signatures
     | verify parent references
     | verify capability attenuation
     | verify delegation depth
     | verify PoP
     | evaluate policy
     v
ALLOW / DENY
```

The major security properties currently demonstrated are:

```text
A downstream agent cannot:

- invent a capability
- broaden an existing constraint
- substitute a parent
- use the wrong delegation signing key
- prove possession using the wrong key
- use a proof against another challenge
- reset delegation depth
- skip delegation depth
- increase maximum delegation depth
- delegate beyond maximum depth
```

A downstream agent **can** further restrict:

```text
capabilities
+
constraints
+
maximum delegation depth
```

---

# 69. Disclaimer

This project is an educational proof of concept.

It is intended to explore attenuating authorization and secure agent delegation.

It is **not a production-ready authorization system**.

The current implementation deliberately simplifies or does not yet implement:

* Rich constraint semantics
* Dynamic chain discovery
* Production parent-reference semantics
* Production key storage
* Server-side single-use challenge management
* Complete replay prevention
* Key IDs
* JWKS
* Key rotation
* Revocation
* Full issuer/audience policy
* OAuth integration
* Keycloak integration
* Real agent infrastructure
* Real Kubernetes/OpenShift deployment behaviour

Delegation-depth enforcement itself is now implemented; it is no longer a future limitation.

Any production implementation would require substantial additional design, standards review, threat modelling and security testing.

---

# 70. Summary

The central idea of the project is:

```text
Delegation must never create more authority
than the delegator already possesses.
```

Capability authority must satisfy:

```text
Capabilities(AATₙ)
    ⊆
Capabilities(AATₙ₋₁)
    ⊆
...
    ⊆
Capabilities(AAT₀)
```

Delegation authority must also satisfy:

```text
child.del_depth
    =
parent.del_depth + 1
```

and:

```text
child.del_max_depth
    <=
parent.del_max_depth
```

The POC now combines:

```text
Cryptographic signatures
        +
Parent references
        +
Capability attenuation
        +
Delegation-depth enforcement
        +
Arbitrary-length chain verification
        +
Holder binding
        +
Proof-of-possession
        +
Request authorization
        +
HTTP resource-server enforcement
```

The project has progressed from simple signed-token experiments to a working end-to-end authorization demonstration:

```text
Root Issuer
     |
     | broad authority
     v
Agent A
     |
     | attenuate
     v
Agent B
     |
     | attenuate
     v
Tool Agent
     |
     | prove possession
     v
Resource Server
     |
     | independently verify everything
     v
ALLOW / DENY
```

The immediate next step is:

```text
Server-side challenge state
        +
Challenge expiration enforcement
        +
Single-use challenge consumption
        =
Replay-resistant HTTP PoP
```

After that, the project can continue toward:

```text
OAuth
   +
Keycloak
   +
Attenuating Agent Tokens
   +
Real Agent Delegation
   +
LLM Agents
   +
Resource APIs
   +
OpenShift / Kubernetes
```

while preserving the fundamental invariant:

```text
A delegated agent can only act within
the authority that was delegated to it.
```
