# Attenuating Authorization Tokens (AAT) Proof of Concept

A hands-on Python proof of concept exploring **Attenuating Authorization Tokens (AATs)** for secure delegation between users, agents, tools, and resource servers.

The project is based on the IETF Internet-Draft:

> OAuth Attenuating Agent Tokens  
> `draft-niyikiza-oauth-attenuating-agent-tokens-01`

The goal is to understand and demonstrate how authorization can be passed through a chain of agents while ensuring that **each delegation can only reduce the authority available to the next participant**.

The project now includes a working end-to-end HTTP flow where a client obtains a challenge from a FastAPI resource server, proves possession of the private key bound to the final AAT, and performs an authorized deployment request.

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
6. Requires proof-of-possession of that key at the resource server.
7. Can be validated as part of the complete delegation chain.
8. Is evaluated against the actual resource request.

The fundamental security property is:

```text
Capabilities(AAT₂) ⊆ Capabilities(AAT₁) ⊆ Capabilities(AAT₀)
```

A downstream agent can therefore **attenuate** authority, but cannot expand it.

---

# 2. Project Goals

The project is deliberately being built incrementally.

The main goals are to understand:

- Public/private key cryptography
- Ed25519 signatures
- JWTs
- JSON Web Keys (JWKs)
- Holder binding
- Proof-of-possession
- Delegation chains
- Parent-token references
- Capability attenuation
- Authorization decisions
- Agent-to-agent delegation
- HTTP resource-server enforcement
- Security attacks against delegated authorization

The eventual goal is to integrate the model with:

- OAuth
- Keycloak
- OAuth token exchange
- Real agent services
- LLM-based agents
- Real HTTP APIs
- Kubernetes/OpenShift

---

# 3. Current Architecture

The current architecture is:

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
  | Verify chain
  | Verify attenuation
  | Verify PoP
  | Evaluate policy
  v
ALLOW / DENY
```

Each participant has its own cryptographic key pair.

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

Only the corresponding public key is included as the holder binding.

---

# 4. Delegation Example

The proof of concept uses a deployment example.

## AAT₀

The root issuer grants authority to:

- Deploy to any namespace
- Read the cluster

Conceptually:

```text
deploy:
  namespace: "*"

read_cluster: {}
```

The token is bound to Agent A.

```text
Root Issuer
     |
     | AAT₀
     | deploy(namespace=*)
     | read_cluster
     v
  Agent A
```

---

## AAT₁

Agent A delegates to Agent B.

Agent A reduces the deployment authority to:

```text
deploy:
  namespace: payments
```

The `read_cluster` capability is removed entirely.

```text
Agent A
     |
     | AAT₁
     | deploy(namespace=payments)
     v
  Agent B
```

This is valid because:

```text
deploy(payments) ⊆ deploy(*)
```

---

## AAT₂

Agent B delegates to the Tool Agent.

Agent B adds another restriction:

```text
deploy:
  namespace: payments
  environment: production
```

The chain therefore becomes:

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

# 5. Core Security Property

The central property being demonstrated is:

```text
Child authority ⊆ Parent authority
```

or:

```text
Capabilities(AAT₂)
    ⊆
Capabilities(AAT₁)
    ⊆
Capabilities(AAT₀)
```

A child may:

- Remove a capability.
- Add a restriction.
- Narrow an existing capability.
- Delegate to another holder.

A child must not:

- Add a new capability.
- Remove an existing parent restriction.
- Broaden an existing constraint.
- Change its relationship to the supplied parent.
- Pretend to have been signed by another holder.

---

# 6. Cryptographic Model

The proof of concept uses **Ed25519** keys.

Each participant has:

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

Ed25519 provides:

- Public/private key signatures
- Small keys
- Fast signing
- Fast verification
- Support in Python's `cryptography` library
- Support through PyJWT's EdDSA implementation

The project uses asymmetric signatures rather than a shared secret.

This is important for delegation.

Agent A does not need the Root Issuer's private key.

Instead, Agent A signs its child token with Agent A's own private key.

---

# 7. Key Architecture

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

The signing relationship is:

```text
issuer-private
      |
      | signs
      v
    AAT₀
      |
      | holder = Agent A public key
      v
   Agent A

agent-a-private
      |
      | signs
      v
    AAT₁
      |
      | holder = Agent B public key
      v
   Agent B

agent-b-private
      |
      | signs
      v
    AAT₂
      |
      | holder = Tool Agent public key
      v
 Tool Agent
```

The Tool Agent private key is then used to prove possession of the holder key bound to AAT₂.

---

# 8. Important Key Security Rule

Private keys must never be committed to Git.

Recommended `.gitignore` entries:

```gitignore
.venv/
keys/*-private.pem
__pycache__/
*.pyc
```

If a private key is exposed, it should be considered compromised.

For a real implementation, private keys would normally be protected by mechanisms such as:

- Hardware-backed keys
- Cloud KMS
- HSM
- Vault
- OS key stores
- Workload identity
- TPM-backed credentials

PEM files are being used only because this is a local proof of concept.

---

# 9. Project Structure

The current project is structured approximately as follows:

```text
aat-poc/
│
├── .venv/
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

The resource-server package is called `server` rather than `resource`.

This avoids a collision with Python's standard-library `resource` module.

---

# 10. Environment Setup

The project was developed on OpenSUSE Tumbleweed using Python.

Create the project directories:

```bash
mkdir -p ~/workspace/aat-poc/{aat,issuer,agents,server,tests,authz,keys}
cd ~/workspace/aat-poc
```

Create a virtual environment:

```bash
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

---

# 11. Python Import Path

The project currently uses the repository root as the Python module path.

Run scripts using:

```bash
PYTHONPATH=. python tests/generate_keys.py
```

This allows imports such as:

```python
from aat.keys import load_private_key
```

to work correctly.

---

# 12. Generate Keys

Generate all four key pairs:

```bash
PYTHONPATH=. python tests/generate_keys.py
```

Expected output:

```text
Keys generated.
```

This creates:

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

---

# 13. Key Regeneration Warning

Regenerating the keys invalidates previously generated tokens.

For example:

```text
old AAT₀
    |
    | signed by old issuer key
    X
new issuer public key
```

After regenerating keys, regenerate the complete token chain:

```bash
PYTHONPATH=. python issuer/issuer.py
PYTHONPATH=. python agents/agent_a.py
PYTHONPATH=. python agents/agent_b.py
```

---

# 14. Root Token — AAT₀

The Root Issuer creates the first authorization token.

The token contains claims including:

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
```

The important authorization information is conceptually:

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

The holder is represented using `cnf`:

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

This binds the token to Agent A's public key.

---

# 15. Create AAT₀

Run:

```bash
PYTHONPATH=. python issuer/issuer.py
```

This creates:

```text
aat0.jwt
```

The Root Issuer signs the token using:

```text
issuer-private.pem
```

The token is intended for Agent A.

The holder binding contains Agent A's public key in JWK form.

---

# 16. JWT Structure

A JWT consists of:

```text
HEADER.PAYLOAD.SIGNATURE
```

The payload can be decoded for inspection without verifying the signature.

However:

> Decoding is not verification.

An attacker can construct or modify JWT payload data.

Only cryptographic signature verification establishes that the token was signed by the expected key.

---

# 17. AAT₁ — Agent A Delegation

Agent A receives:

```text
AAT₀
```

Agent A creates:

```text
AAT₁
```

The new token is signed with:

```text
agent-a-private.pem
```

The holder is changed to:

```text
agent-b-public.pem
```

The capability is reduced to:

```text
deploy:
  namespace: payments
```

The `read_cluster` capability is not delegated.

The relationship is:

```text
AAT₀
  |
  | holder = Agent A
  v
Agent A
  |
  | signs AAT₁
  v
AAT₁
  |
  | holder = Agent B
  v
Agent B
```

---

# 18. Create AAT₁

Run:

```bash
PYTHONPATH=. python agents/agent_a.py
```

This creates:

```text
aat1.jwt
```

Agent A's private key signs the child token.

---

# 19. Parent Token Reference

A child token contains a reference to its parent.

The current proof of concept uses a SHA-256 hash of the complete parent JWT.

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

This cryptographically links the child to the exact parent token from which it was derived.

---

# 20. Why Hash the Parent?

Suppose an attacker supplies AAT₁ with a different AAT₀.

The verifier calculates:

```text
SHA256(supplied_parent)
```

and compares it with:

```text
AAT₁.parent
```

If they do not match:

```text
REJECT
```

This prevents a child token from being detached from the parent token it claims to derive from.

---

# 21. AAT₂ — Agent B Delegation

Agent B receives:

```text
AAT₁
```

and creates:

```text
AAT₂
```

Agent B signs it using:

```text
agent-b-private.pem
```

The holder becomes:

```text
tool-agent-public.pem
```

The capability becomes:

```text
deploy:
  namespace: payments
  environment: production
```

This further restricts the authority.

---

# 22. Create AAT₂

Run:

```bash
PYTHONPATH=. python agents/agent_b.py
```

This creates:

```text
aat2.jwt
```

The resulting chain is:

```text
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
 Tool Agent
```

---

# 23. Complete Token Chain

The complete chain is:

```text
AAT₀
│
├── issuer = Root Issuer
├── holder = Agent A
└── capabilities:
      deploy(namespace=*)
      read_cluster
        │
        │ signed by Agent A
        v
AAT₁
│
├── issuer = Agent A
├── holder = Agent B
├── parent = hash(AAT₀)
└── capabilities:
      deploy(namespace=payments)
        │
        │ signed by Agent B
        v
AAT₂
│
├── issuer = Agent B
├── holder = Tool Agent
├── parent = hash(AAT₁)
└── capabilities:
      deploy(
        namespace=payments,
        environment=production
      )
```

---

# 24. Delegation Depth

Tokens contain:

```json
{
  "del_depth": 0,
  "del_max_depth": 3
}
```

The intended progression is:

```text
AAT₀ → del_depth = 0
AAT₁ → del_depth = 1
AAT₂ → del_depth = 2
```

The maximum permitted delegation depth is represented by:

```text
del_max_depth = 3
```

The fields are currently present in the POC, but full delegation-depth enforcement remains a hardening task.

---

# 25. Capability Attenuation

The attenuation implementation lives in:

```text
aat/attenuation.py
```

The key logic determines whether the child capabilities are no broader than the parent capabilities.

The basic invariant is:

```text
child ⊆ parent
```

---

# 26. Wildcard Example

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

This is allowed because:

```text
*
|
+-- payments
```

The child has less authority.

---

# 27. Restricted Parent

If the parent contains:

```json
{
  "deploy": {
    "namespace": "payments"
  }
}
```

then this child is valid:

```json
{
  "deploy": {
    "namespace": "payments"
  }
}
```

but this is invalid:

```json
{
  "deploy": {
    "namespace": "billing"
  }
}
```

because the child cannot change an existing restricted value.

---

# 28. Adding Restrictions

A child may add a new restriction.

Parent:

```json
{
  "deploy": {
    "namespace": "payments"
  }
}
```

Child:

```json
{
  "deploy": {
    "namespace": "payments",
    "environment": "production"
  }
}
```

This is allowed by the current POC.

The child has introduced an additional restriction rather than broadening the existing authority.

---

# 29. Removing Capabilities

Removing a capability is allowed.

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

The child has less authority.

Therefore:

```text
Child ⊆ Parent
```

still holds.

---

# 30. Adding Capabilities

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

The child cannot invent `delete_cluster` because the parent did not delegate it.

---

# 31. Current Constraint Model

The proof of concept deliberately uses a simple constraint model.

Current rules:

1. `*` means any value.
2. A specific parent value must be retained by the child.
3. A child may add additional restrictions.
4. A child may remove capabilities.
5. A child cannot add new capabilities.
6. A child cannot broaden an existing constraint.

This is intended as a teaching implementation rather than a complete general-purpose authorization language.

---

# 32. Delegation Chain Verification

The chain verifier lives in:

```text
aat/verify.py
```

For AAT₀:

```text
Verify signature using Root Issuer public key
```

For AAT₁:

```text
Read AAT₀ holder key
        |
        v
Verify AAT₁ signature
        |
        v
Verify parent hash
        |
        v
Verify attenuation
```

For AAT₂:

```text
Read AAT₁ holder key
        |
        v
Verify AAT₂ signature
        |
        v
Verify parent hash
        |
        v
Verify attenuation
```

---

# 33. Verify the Complete Chain

Run:

```bash
PYTHONPATH=. python tests/verify_chain.py
```

A successful verification means:

```text
Root signature valid
        +
AAT₁ signed by AAT₀ holder
        +
AAT₁ references AAT₀
        +
AAT₁ attenuates AAT₀
        +
AAT₂ signed by AAT₁ holder
        +
AAT₂ references AAT₁
        +
AAT₂ attenuates AAT₁
```

---

# 34. Holder Binding

AATs are not only about signatures.

They also bind a token to a specific holder key.

The binding is represented by:

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

For example:

```text
AAT₂
  |
  +-- cnf.jwk
        |
        +-- Tool Agent public key
```

The Tool Agent must demonstrate possession of the corresponding private key.

---

# 35. Proof-of-Possession

A bearer token can potentially be used by anyone who obtains it.

Proof-of-possession changes this model.

The resource server creates a challenge.

Conceptually:

```json
{
  "challenge": "random-value",
  "timestamp": 1234567890
}
```

The legitimate token holder signs the challenge using its private key.

The resource server verifies the signature using the public key contained in:

```text
AAT₂.cnf.jwk
```

The flow becomes:

```text
Resource Server
       |
       | challenge
       v
   Tool Agent
       |
       | sign challenge
       v
Resource Server
       |
       | verify using AAT₂ cnf key
       v
     ALLOW
```

---

# 36. Local Proof-of-Possession Tests

Run:

```bash
PYTHONPATH=. python tests/test_pop.py
```

The tests demonstrate:

- Correct private key succeeds.
- Wrong private key fails.
- A proof generated for a different challenge fails.

This proves that simply possessing the JWT is not enough to generate a valid proof.

---

# 37. Token-Bound Proof-of-Possession

Run:

```bash
PYTHONPATH=. python tests/test_aat_pop.py
```

The test:

1. Loads AAT₂.
2. Verifies its signature.
3. Extracts the holder key from `cnf`.
4. Creates a challenge.
5. Signs the challenge using the Tool Agent private key.
6. Verifies the proof against the public key contained in AAT₂.

The important question is no longer simply:

```text
Do you possess AAT₂?
```

Instead:

```text
Can you prove that you possess the private key
corresponding to the public key bound to AAT₂?
```

---

# 38. Authorization Is a Separate Layer

Cryptographic verification answers:

```text
Is this token authentic?
```

Attenuation verification answers:

```text
Is this delegated authority within the parent's authority?
```

Proof-of-possession answers:

```text
Does the caller possess the private key bound to the token?
```

Policy evaluation answers:

```text
Is this specific requested operation permitted?
```

These are different security decisions.

---

# 39. Authorization Policy

The policy layer lives in:

```text
authz/policy.py
```

Suppose the final token grants:

```text
deploy:
  namespace: payments
  environment: production
```

The request:

```json
{
  "action": "deploy",
  "namespace": "payments",
  "environment": "production"
}
```

is allowed.

A request for:

```json
{
  "action": "deploy",
  "namespace": "billing",
  "environment": "production"
}
```

is denied.

A request for:

```json
{
  "action": "deploy",
  "namespace": "payments",
  "environment": "development"
}
```

is denied.

A request for:

```json
{
  "action": "read_cluster"
}
```

is also denied because that capability was removed earlier in the delegation chain.

---

# 40. Authorization Decision Layer

The higher-level authorization logic lives in:

```text
authz/decision.py
```

The authorization decision combines:

```text
Chain verification
       +
Attenuation verification
       +
Proof-of-possession
       +
Request policy
       =
Authorization decision
```

The resource server therefore does not rely on any single check.

---

# 41. Attack Tests

Automated attack testing is implemented in:

```text
tests/test_attacks.py
```

The current security tests successfully block:

```text
AAT SECURITY TESTS
================================================================================
✅ Tamper with AAT₂: blocked (InvalidSignatureError)
✅ Add read_cluster capability: blocked (ValueError)
✅ Broaden namespace to *: blocked (ValueError)
✅ Change parent reference: blocked (ValueError)
✅ Sign AAT₂ with Agent A key: blocked (InvalidSignatureError)
✅ Proof signed with wrong key: blocked
✅ Replay proof against new challenge: blocked
```

These tests turn the intended security properties into executable checks.

---

# 42. Attack — Modify AAT₂

An attacker modifies the payload of AAT₂.

For example:

```text
namespace=payments
```

becomes:

```text
namespace=*
```

The JWT payload changes.

The existing signature no longer matches.

Result:

```text
InvalidSignatureError
```

The request is rejected.

---

# 43. Attack — Add a Capability

AAT₁ contains:

```json
{
  "deploy": {
    "namespace": "payments"
  }
}
```

An attacker attempts to create a child containing:

```json
{
  "deploy": {
    "namespace": "payments"
  },
  "read_cluster": {}
}
```

The child capability does not exist in the parent.

The attenuation check rejects the token.

---

# 44. Attack — Broaden Namespace

Parent:

```text
namespace=payments
```

Attacker attempts:

```text
namespace=*
```

This changes a specific constraint into a wildcard.

That would increase authority.

The attenuation check rejects it.

---

# 45. Attack — Change Parent Reference

Suppose AAT₂ was created from AAT₁.

An attacker attempts to modify the parent reference.

The verifier calculates:

```text
SHA256(actual AAT₁)
```

and compares it with:

```text
AAT₂.parent
```

A mismatch results in rejection.

---

# 46. Attack — Wrong Delegation Signing Key

AAT₂ must be signed by Agent B because AAT₁ is bound to Agent B.

An attacker signs AAT₂ using Agent A's private key.

The verifier extracts Agent B's public key from AAT₁ and attempts verification.

The Agent A signature does not verify against Agent B's public key.

Result:

```text
InvalidSignatureError
```

---

# 47. Attack — Wrong PoP Key

AAT₂ is bound to the Tool Agent's public key.

An attacker attempts to generate the proof using another private key.

The resource server verifies the signature against:

```text
AAT₂.cnf.jwk
```

The proof fails.

Result:

```text
DENY
```

---

# 48. Attack — Proof Against a Different Challenge

A proof is generated for:

```text
Challenge A
```

The attacker attempts to use that proof with:

```text
Challenge B
```

Because the signed data is different, signature verification fails.

This demonstrates that the proof is cryptographically bound to the challenge.

---

# 49. FastAPI Resource Server

The POC now includes a real HTTP resource server implemented using FastAPI.

The server lives in:

```text
server/server.py
```

Start it with:

```bash
PYTHONPATH=. uvicorn server.server:app --host 0.0.0.0 --port 8000
```

The server runs on:

```text
http://localhost:8000
```

---

# 50. Why the Package Is Called `server`

The resource-server code was originally placed under a package called:

```text
resource
```

This caused:

```text
ModuleNotFoundError:
No module named 'resource.policy';
'resource' is not a package
```

because Python already has a standard-library module called `resource`.

The package was therefore renamed to:

```text
server
```

The FastAPI application is started using:

```bash
PYTHONPATH=. uvicorn server.server:app --host 0.0.0.0 --port 8000
```

---

# 51. FastAPI Dependency

FastAPI and Uvicorn must be installed inside the project's virtual environment.

Activate the environment:

```bash
source .venv/bin/activate
```

Then install:

```bash
pip install fastapi uvicorn
```

The shell prompt should show something similar to:

```text
(.venv)
```

before starting the application.

---

# 52. Challenge Endpoint

The resource server exposes:

```text
GET /challenge
```

Test it using:

```bash
curl http://localhost:8000/challenge
```

The response now looks like:

```json
{
  "challenge": "eyJjaGFsbGVuZ2UiOiIzNTdjNjU1Ny00YjQ0LTQyZjEtYjdlYi01ZTlhNDliNGNjYzkiLCJ0aW1lc3RhbXAiOjE3OTAyNDI1NjF9",
  "expires_in": 300
}
```

The challenge value is a transport-safe encoded representation of the challenge object.

---

# 53. Why the Challenge Was Changed

An earlier version returned:

```json
{
  "challenge": "3e711a70-b199-45af-9bac-3e9a8cf20cbc",
  "timestamp": 1790242465
}
```

The HTTP PoP flow was improved so that the exact object being signed can be transported without the client and server independently reconstructing it.

The challenge now contains an encoded representation of data such as:

```json
{
  "challenge": "d4a7ba6e-b64c-436a-943c-1726a76a4b26",
  "timestamp": 1790242631
}
```

This reduces the risk of the client and server signing/verifying slightly different serialized data.

---

# 54. Challenge Lifetime

The challenge response includes:

```json
{
  "expires_in": 300
}
```

This represents a five-minute challenge lifetime.

The challenge should be:

- Short-lived
- Unpredictable
- Bound to the proof
- Ideally single-use

The current POC demonstrates challenge binding.

A production implementation should additionally maintain server-side challenge state to guarantee that a successfully used challenge cannot be replayed.

---

# 55. HTTP Proof-of-Possession Flow

The complete HTTP PoP flow is:

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
    | sign exact challenge
    | using tool-agent-private.pem
    v
HTTP Request
    |
    | Authorization: Bearer AAT₂
    | X-AAT-Challenge: <challenge>
    | X-AAT-Proof: <signature>
    v
Resource Server
```

The server extracts the Tool Agent public key from:

```text
AAT₂.cnf.jwk
```

and verifies the proof.

---

# 56. Deploy Endpoint

The resource server exposes:

```text
POST /deploy
```

The intended request contains:

```text
Authorization: Bearer <AAT₂>
X-AAT-Challenge: <encoded challenge>
X-AAT-Proof: <signature>
```

and a JSON body describing the requested deployment.

For example:

```json
{
  "namespace": "payments",
  "environment": "production"
}
```

---

# 57. Resource-Server Authorization Flow

The `/deploy` request is processed conceptually as:

```text
Incoming request
      |
      v
Extract AAT₂
      |
      v
Verify AAT chain
      |
      +--------------------+
      |                    |
    valid                invalid
      |                    |
      v                    v
Verify challenge          DENY
and PoP
      |
      +--------------------+
      |                    |
    valid                invalid
      |                    |
      v                    v
Evaluate policy           DENY
      |
      +--------------------+
      |                    |
    allow                 deny
      |                    |
      v                    v
    200                  DENY
```

---

# 58. End-to-End HTTP Client

The project includes:

```text
tests/client.py
```

Run it while the FastAPI server is running:

```bash
PYTHONPATH=. python tests/client.py
```

The client:

1. Requests a challenge.
2. Receives the encoded challenge.
3. Decodes the challenge.
4. Signs the challenge using the Tool Agent private key.
5. Loads AAT₂.
6. Sends the token, challenge, proof and deployment request to the server.
7. Displays the response.

---

# 59. Successful End-to-End Test

A successful client run currently looks like:

```text
ENCODED CHALLENGE
================================================================================
eyJjaGFsbGVuZ2UiOiJkNGE3YmE2ZS1iNjRjLTQzNmEtOTQzYy0xNzI2YTc2YTRiMjYiLCJ0aW1lc3RhbXAiOjE3OTAyNDI2MzF9

CHALLENGE
================================================================================
{
  "challenge": "d4a7ba6e-b64c-436a-943c-1726a76a4b26",
  "timestamp": 1790242631
}

PROOF
================================================================================
3tQPT5bPU93XH3D-nO9DOMAsu_pgMQ0Cxe8KzuFpkxyQsn3nEfwHnOn2tiE9IfMsONk5PbRoczp7QvCkSWBNDQ

SERVER RESPONSE
================================================================================
200
{"status":"deployed","namespace":"payments","environment":"production"}
```

This demonstrates the first complete HTTP authorization flow in the POC.

---

# 60. What the Successful HTTP Test Proves

The `200` response means the request passed multiple security checks.

Conceptually:

```text
AAT₀ valid
   +
AAT₁ valid
   +
AAT₂ valid
   +
parent chain valid
   +
attenuation valid
   +
Tool Agent proves possession
   +
deploy capability exists
   +
namespace = payments
   +
environment = production
   =
ALLOW
```

The server then returns:

```json
{
  "status": "deployed",
  "namespace": "payments",
  "environment": "production"
}
```

The current endpoint simulates the deployment action.

It does not yet perform a real Kubernetes/OpenShift deployment.

---

# 61. Current Resource-Server Token Resolution

The current resource server is intentionally simplified.

The server has access to the earlier chain members:

```text
aat0.jwt
aat1.jwt
```

while the final token is supplied by the client:

```text
AAT₂
```

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

The server then reconstructs and verifies:

```text
AAT₀ → AAT₁ → AAT₂
```

This is appropriate for demonstrating the security model, but a future implementation should dynamically resolve or transport the delegation chain.

---

# 62. Expiry Handling

Tokens contain:

```text
iat
exp
```

PyJWT validates token expiry.

If a token has expired:

```text
jwt.exceptions.ExpiredSignatureError
```

is raised.

During development, this occurred when an older AAT chain was reused after its one-hour token lifetime had elapsed.

The fix is to regenerate the token chain:

```bash
PYTHONPATH=. python issuer/issuer.py
PYTHONPATH=. python agents/agent_a.py
PYTHONPATH=. python agents/agent_b.py
```

Expired tokens being rejected is expected security behaviour.

---

# 63. Current Run Sequence

Activate the virtual environment:

```bash
cd ~/workspace/aat-poc
source .venv/bin/activate
```

Generate keys if required:

```bash
PYTHONPATH=. python tests/generate_keys.py
```

Generate AAT₀:

```bash
PYTHONPATH=. python issuer/issuer.py
```

Generate AAT₁:

```bash
PYTHONPATH=. python agents/agent_a.py
```

Generate AAT₂:

```bash
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
```

Run token-bound PoP tests:

```bash
PYTHONPATH=. python tests/test_aat_pop.py
```

Run attack tests:

```bash
PYTHONPATH=. python tests/test_attacks.py
```

Start the HTTP server:

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

# 64. Complete Current End-to-End Flow

The current working system can be represented as:

```text
                         USER
                           |
                           v
                     ROOT ISSUER
                           |
                           | signs
                           |
                           v
                         AAT₀
                           |
                           | holder = Agent A
                           v
                       AGENT A
                           |
                           | attenuates
                           | signs
                           v
                         AAT₁
                           |
                           | holder = Agent B
                           v
                       AGENT B
                           |
                           | attenuates
                           | signs
                           v
                         AAT₂
                           |
                           | holder = Tool Agent
                           v
                     TOOL AGENT
                           |
                           | GET /challenge
                           v
                  FASTAPI RESOURCE SERVER
                           |
                           | encoded challenge
                           v
                     TOOL AGENT
                           |
                           | signs challenge
                           | using private key
                           |
                           | POST /deploy
                           | AAT₂
                           | challenge
                           | proof
                           v
                  FASTAPI RESOURCE SERVER
                           |
                           | verify AAT₀
                           | verify AAT₁
                           | verify AAT₂
                           | verify parent hashes
                           | verify attenuation
                           | verify PoP
                           | evaluate policy
                           v
                       ALLOW / DENY
```

---

# 65. Security Boundary

The resource server is responsible for the final authorization decision.

It does not blindly trust:

```text
Agent A
```

or:

```text
Agent B
```

or:

```text
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
attenuation
    +
holder binding
    +
proof-of-possession
    +
request policy
```

This makes the resource server the enforcement point.

---

# 66. Separation of Security Responsibilities

The project demonstrates several separate security questions.

## Authentication / Signature Verification

```text
Who signed this token?
```

Answered using:

```text
Ed25519 signature verification
```

## Delegation

```text
Who delegated this authority?
```

Answered using:

```text
parent relationship
+
parent holder key
```

## Attenuation

```text
Did the child gain more authority?
```

Answered using:

```text
capability comparison
```

## Holder Binding

```text
Who is this token intended for?
```

Answered using:

```text
cnf.jwk
```

## Proof-of-Possession

```text
Does the caller possess the corresponding private key?
```

Answered using:

```text
challenge
+
signature
```

## Authorization

```text
Is this particular operation permitted?
```

Answered using:

```text
policy evaluation
```

These checks should not be collapsed into a single decision.

---

# 67. Threat Model

The proof of concept assumes that downstream participants may be compromised or malicious.

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

The important question is:

> What damage can a compromised downstream agent cause?

The intended answer is:

```text
No more than the authority that was delegated to it.
```

If Agent B receives:

```text
deploy(namespace=payments)
```

it should not be able to create:

```text
deploy(namespace=billing)
```

or:

```text
delete_cluster
```

or:

```text
read_cluster
```

unless those capabilities were legitimately delegated.

---

# 68. Why Attenuation Matters for Agents

Without attenuation:

```text
User
 |
 v
Agent A
 |
 | full user authority
 v
Agent B
 |
 | full user authority
 v
Agent C
```

Every downstream component effectively inherits the same power.

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

Authority becomes narrower as the task becomes more specific.

---

# 69. Least Privilege

The model naturally supports least privilege.

Instead of giving Agent B everything the user can do, Agent A gives Agent B only the authority required for its task.

For example:

```text
User:
    deploy anywhere
    read cluster

Agent A:
    deploy payments

Agent B:
    deploy payments in production

Tool:
    execute deployment
```

This is much closer to the actual operation being performed.

---

# 70. Current Security Invariants

The implementation is intended to enforce invariants such as:

```text
Invariant 1:
A token must have a valid signature.

Invariant 2:
A child must be signed by the holder of its parent.

Invariant 3:
A child must reference its actual parent.

Invariant 4:
A child cannot have more authority than its parent.

Invariant 5:
A token can only be exercised by its bound holder.

Invariant 6:
Proof-of-possession must be tied to the challenge.

Invariant 7:
Expired tokens cannot be used.

Invariant 8:
The requested action must be permitted by the final token.

Invariant 9:
The resource server makes the final authorization decision.
```

A further target invariant is:

```text
Invariant 10:
Delegation depth cannot exceed the permitted maximum.
```

Full depth enforcement remains future work.

---

# 71. Current Limitations

This is a proof of concept and intentionally simplifies several areas.

## Simplified Constraint Model

The current implementation supports relatively simple wildcard and equality semantics.

It is not a complete general-purpose authorization constraint language.

## Fixed Chain Shape

The current implementation is built around:

```text
AAT₀ → AAT₁ → AAT₂
```

A future implementation should support arbitrary chain lengths.

## Delegation Depth

`del_depth` and `del_max_depth` exist, but stronger enforcement remains to be implemented.

## Parent Reference

The parent is currently represented using:

```text
SHA-256(parent JWT)
```

This is useful for demonstrating the concept but should eventually be reviewed against the exact semantics required by the AAT draft.

## Local PEM Keys

Private keys currently exist as local PEM files.

This is not appropriate for production.

## Static Chain Files

Earlier tokens are currently stored locally and loaded by the resource server.

A real distributed system requires a better chain transport/resolution mechanism.

## Challenge State

The current challenge mechanism demonstrates proof binding and freshness information.

A production implementation should track challenge issuance and consumption server-side to guarantee single-use behaviour.

## No OAuth Yet

The current POC deliberately implements the core delegation mechanics before adding OAuth.

## No Keycloak Yet

Keycloak integration is a later phase.

## No Real LLM Agent Yet

The current agents are Python programs.

## No Real Cluster Deployment Yet

The `/deploy` endpoint currently simulates successful deployment.

---

# 72. Why OAuth and Keycloak Come Later

The project deliberately separates:

```text
AAT cryptographic/delegation model
```

from:

```text
OAuth / Identity Provider infrastructure
```

The current system makes it possible to understand:

```text
signatures
+
delegation
+
attenuation
+
holder binding
+
proof-of-possession
+
authorization
```

before introducing the additional complexity of:

```text
OAuth clients
authorization grants
token exchange
Keycloak realms
client authentication
protocol mappers
JWKS
OAuth access tokens
```

---

# 73. Future OAuth Integration

The eventual architecture could become:

```text
User
 |
 v
OAuth Authorization Server
 |
 | Root authorization
 v
Agent A
 |
 | attenuated delegation
 v
Agent B
 |
 | attenuated delegation
 v
Resource Server
```

Areas to investigate include:

- OAuth access tokens
- Rich Authorization Requests
- Token exchange
- Sender-constrained tokens
- Proof-of-possession
- Agent delegation
- Resource indicators
- Audience restrictions

---

# 74. Future Keycloak Integration

Keycloak can eventually provide the OAuth and identity infrastructure around the AAT model.

Potential architecture:

```text
                   Keycloak
                      |
                      | OAuth
                      v
                   Agent A
                      |
                      | AAT₁
                      v
                   Agent B
                      |
                      | AAT₂
                      v
                Resource API
```

Potential areas to investigate:

- Keycloak clients
- OAuth token exchange
- JWT signing
- Custom claims
- Protocol mappers
- Authorization services
- Client authentication
- JWKS
- Sender-constrained tokens
- Custom protocol extensions

---

# 75. Future Real Agent Workflow

The current `agent_a.py` and `agent_b.py` scripts conceptually represent agents.

A future stage could turn them into actual services.

For example:

```text
User:
    "Deploy the payments application."
        |
        v
Agent A:
    determines deployment is required
        |
        | delegates:
        | deploy(namespace=payments)
        v
Agent B:
    deployment specialist
        |
        | delegates:
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

# 76. Future LLM Agent

An LLM can eventually be introduced into the agent chain.

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

This keeps security enforcement outside the probabilistic agent.

---

# 77. Future OpenShift/Kubernetes Integration

A useful real-world target is Kubernetes or OpenShift.

The root authority might allow:

```text
deploy(namespace=*)
```

Agent A delegates:

```text
deploy(namespace=payments)
```

Agent B delegates:

```text
deploy(
    namespace=payments,
    environment=production
)
```

The resource server could then map the authorization to a real cluster operation.

For example:

```text
POST /api/deploy
```

The resource server would verify the AAT chain before interacting with the Kubernetes/OpenShift API.

---

# 78. Potential Final Architecture

The eventual target could look like:

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
                          | AAT₁
                          | attenuated authority
                          v
                       AGENT B
                          |
                          | AAT₂
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
                          | verify PoP
                          | evaluate policy
                          v
                KUBERNETES / OPENSHIFT
```

---

# 79. Future Security Hardening

Important future security work includes:

- Enforce delegation depth.
- Generalize chain verification to arbitrary depth.
- Improve constraint semantics.
- Add stronger replay protection.
- Track challenge issuance and consumption.
- Add `kid` support.
- Add JWKS support.
- Add key rotation.
- Add revocation.
- Improve issuer/audience validation.
- Improve token validation rules.
- Remove reliance on local token files.
- Replace PEM private keys with protected key storage.
- Add structured security logging.
- Add more negative HTTP tests.

---

# 80. Future Security Tests

The test suite should eventually include:

```text
test_valid_chain()

test_modified_root_token()

test_modified_child_token()

test_invalid_signature()

test_wrong_signing_key()

test_wrong_parent_hash()

test_capability_expansion()

test_new_capability()

test_namespace_expansion()

test_environment_expansion()

test_invalid_holder()

test_invalid_pop()

test_replayed_pop()

test_reused_challenge()

test_expired_challenge()

test_expired_token()

test_delegation_depth()

test_skipped_parent()

test_unknown_tool()

test_wrong_issuer()

test_wrong_audience()
```

The objective is to turn each security property into an executable regression test.

---

# 81. Current Implementation Checklist

## Core Cryptography

- [x] Ed25519 key generation
- [x] Private/public key loading
- [x] JWT signing
- [x] JWT verification
- [x] Public-key JWK representation

## AAT

- [x] Root AAT
- [x] Holder binding
- [x] Authorization details
- [x] Parent token hash
- [x] Agent A child token
- [x] Agent B child token
- [x] Delegation chain
- [x] Capability attenuation

## Verification

- [x] Root signature verification
- [x] Child signature verification
- [x] Parent-reference verification
- [x] Capability attenuation verification
- [x] Token expiry verification
- [x] Complete AAT₀ → AAT₁ → AAT₂ verification

## Proof-of-Possession

- [x] Challenge generation
- [x] Challenge encoding
- [x] Challenge decoding
- [x] Challenge signing
- [x] Signature verification
- [x] Token-bound holder verification
- [x] Wrong-key rejection
- [x] Different-challenge rejection
- [x] HTTP challenge/proof flow

## Authorization

- [x] Capability lookup
- [x] Constraint checking
- [x] Authorization decision layer
- [x] Resource-server enforcement

## HTTP

- [x] FastAPI resource server
- [x] `/challenge`
- [x] `/deploy`
- [x] Bearer AAT handling
- [x] Challenge transport
- [x] PoP transport
- [x] End-to-end HTTP client
- [x] Successful authorized deployment response

## Security Tests

- [x] JWT tampering
- [x] Capability escalation
- [x] Constraint broadening
- [x] Parent substitution
- [x] Wrong child signing key
- [x] Wrong PoP key
- [x] Proof against different challenge

---

# 82. Remaining Work

- [ ] Enforce delegation depth
- [ ] Support arbitrary delegation-chain length
- [ ] Improve constraint semantics
- [ ] Improve token validation structure
- [ ] Improve verification API naming
- [ ] Add server-side single-use challenge state
- [ ] Add replay cache
- [ ] Add key IDs (`kid`)
- [ ] Add JWKS
- [ ] Add key rotation
- [ ] Add revocation
- [ ] Add audience validation
- [ ] Replace static token files
- [ ] Replace local private-key storage
- [ ] OAuth integration
- [ ] Keycloak integration
- [ ] OAuth token exchange
- [ ] Real agent services
- [ ] LLM agent
- [ ] Real tool/API integration
- [ ] Kubernetes integration
- [ ] OpenShift integration

---

# 83. Roadmap

The project has progressed through the following phases:

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
Attenuation
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
Security hardening
    |
    v
NEXT

Phase 13
OAuth integration
    |
    v
PLANNED

Phase 14
Keycloak integration
    |
    v
PLANNED

Phase 15
Real agent workflow
    |
    v
PLANNED

Phase 16
LLM agent
    |
    v
PLANNED

Phase 17
Real tool / OpenShift integration
```

---

# 84. What the POC Currently Demonstrates

The project can now demonstrate:

```text
1. A root issuer grants broad authority.

2. Agent A receives that authority.

3. Agent A delegates less authority to Agent B.

4. Agent B delegates even less authority to a Tool Agent.

5. Every token is cryptographically signed.

6. Every child references its parent.

7. Every child is verified against its parent's holder key.

8. Every delegation is checked for attenuation.

9. The final token is bound to the Tool Agent's public key.

10. The Tool Agent obtains a fresh challenge.

11. The Tool Agent signs the challenge.

12. The resource server verifies possession of the bound private key.

13. The resource server evaluates the requested operation.

14. A valid deployment request is allowed.

15. Tampering and privilege-expansion attempts are rejected.
```

---

# 85. Example Security Story

The user starts with:

```text
deploy(namespace=*)
read_cluster
```

Agent A receives:

```text
deploy(namespace=*)
read_cluster
```

but delegates only:

```text
deploy(namespace=payments)
```

Agent B receives that authority and delegates:

```text
deploy(
    namespace=payments,
    environment=production
)
```

The Tool Agent requests:

```text
deploy(
    namespace=payments,
    environment=production
)
```

and proves possession of the private key bound to AAT₂.

Result:

```text
ALLOW
```

If it requests:

```text
deploy(namespace=billing)
```

result:

```text
DENY
```

If it requests:

```text
read_cluster
```

result:

```text
DENY
```

If it modifies AAT₂:

```text
DENY
```

If it presents a proof signed by the wrong private key:

```text
DENY
```

If it attempts to broaden:

```text
namespace=payments
```

to:

```text
namespace=*
```

result:

```text
DENY
```

---

# 86. Key Lessons

Several important ideas have emerged from the POC.

## Delegation Is Not Token Forwarding

A downstream agent should not simply receive the original user's credential.

Instead it should receive a deliberately restricted authorization.

## Signatures Are Not Enough

A valid JWT signature only proves that a particular key signed a token.

The verifier must also establish:

```text
Was that key authorized to create this child?
```

That is why parent holder binding matters.

## Parent Relationships Matter

A child must be tied to the exact authorization from which it was derived.

## Attenuation Is the Core Authorization Property

Every delegation must satisfy:

```text
child <= parent
```

## Holder Binding Reduces Bearer-Token Risk

Possession of AAT₂ alone should not be enough.

The caller must also possess the private key corresponding to:

```text
AAT₂.cnf.jwk
```

## PoP and Authorization Are Different

Proof-of-possession establishes:

```text
You possess the correct private key.
```

It does not establish:

```text
You are allowed to deploy to billing.
```

That is the policy layer's job.

## The Resource Server Is the Enforcement Point

Agents can request actions.

They do not make the final security decision.

---

# 87. Design Philosophy

The project intentionally follows this progression:

```text
Cryptography
     |
     v
Signed Tokens
     |
     v
Capabilities
     |
     v
Attenuation
     |
     v
Delegation Chain
     |
     v
Holder Binding
     |
     v
Proof-of-Possession
     |
     v
Authorization Policy
     |
     v
HTTP Resource Server
     |
     v
Security Hardening
     |
     v
OAuth
     |
     v
Keycloak
     |
     v
Real Agents
     |
     v
LLM Agents
     |
     v
Real Tools
     |
     v
OpenShift / Kubernetes
```

Each layer is added only after the previous layer can be demonstrated independently.

---

# 88. Quick Start

Clone or enter the repository:

```bash
cd ~/workspace/aat-poc
```

Activate the virtual environment:

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

Verify it:

```bash
PYTHONPATH=. python tests/verify_chain.py
```

Run security tests:

```bash
PYTHONPATH=. python tests/test_attacks.py
```

Start the resource server:

```bash
PYTHONPATH=. uvicorn server.server:app --host 0.0.0.0 --port 8000
```

Open another terminal:

```bash
cd ~/workspace/aat-poc
source .venv/bin/activate
```

Run the HTTP client:

```bash
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

# 89. Disclaimer

This project is an educational proof of concept.

It is intended to explore the concepts behind attenuating authorization and agentic delegation.

It is **not a production-ready authorization system**.

In particular, the current implementation deliberately simplifies:

- Constraint semantics
- Chain discovery
- Parent references
- Key storage
- Challenge management
- Replay prevention
- Delegation-depth enforcement
- Key rotation
- Revocation
- OAuth integration
- Resource-server deployment behaviour

Any production implementation would require substantial additional design, standards review, threat modelling and security testing.

---

# 90. Summary

The central idea of this project can be reduced to one principle:

```text
Delegation must never create more authority
than the delegator already possesses.
```

The chain:

```text
AAT₀
  |
  | attenuation
  v
AAT₁
  |
  | attenuation
  v
AAT₂
```

must always satisfy:

```text
Capabilities(AAT₂)
    ⊆
Capabilities(AAT₁)
    ⊆
Capabilities(AAT₀)
```

The current POC combines:

```text
Cryptographic signatures
        +
Parent references
        +
Capability attenuation
        +
Holder binding
        +
Proof-of-possession
        +
Request authorization
        +
HTTP resource-server enforcement
```

The project has now progressed from offline token experiments to a working end-to-end HTTP demonstration:

```text
Root Issuer
     |
     | AAT₀
     v
Agent A
     |
     | attenuate
     | AAT₁
     v
Agent B
     |
     | attenuate
     | AAT₂
     v
Tool Agent
     |
     | request challenge
     | prove possession
     v
FastAPI Resource Server
     |
     | verify complete chain
     | verify attenuation
     | verify PoP
     | evaluate policy
     v
ALLOW / DENY
```

The next major phase is to harden the current security model before introducing OAuth and Keycloak.

The eventual objective is:

```text
OAuth
   +
Keycloak
   +
Attenuating Agent Tokens
   +
Agent Delegation
   +
Proof-of-Possession
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