# Attenuating Authorization Tokens (AAT) Proof of Concept

A hands-on Python proof of concept exploring **Attenuating Authorization Tokens (AATs)** for secure delegation between users, agents, and tools.

The project is based on the IETF Internet-Draft:

> OAuth Attenuating Agent Tokens
> `draft-niyikiza-oauth-attenuating-agent-tokens-01`

The goal is to understand and demonstrate how an authorization token can be passed through a chain of agents while ensuring that **each delegation can only reduce the authority available to the next participant**.

---

## 1. Overview

Traditional authorization generally looks like:

```
User
  |
  v
Application
  |
  v
Resource Server
```

An agentic system introduces additional delegation:

```
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
Resource
```

This creates an important security problem.

If Agent A delegates authority to Agent B, how can the resource server know that Agent B has not acquired more authority than the user originally granted?

This proof of concept explores a cryptographic delegation model where each child token:

1. Is cryptographically signed.
2. Identifies its parent token.
3. Is signed by the holder of the parent token.
4. Contains a restricted set of capabilities.
5. Is bound to the key of the next holder.
6. Can require proof-of-possession of that key.
7. Can be validated as part of the complete delegation chain.

The fundamental security property is:

```
Capabilities(AAT₂) ⊆ Capabilities(AAT₁) ⊆ Capabilities(AAT₀)
```

A downstream agent can therefore **attenuate** authority, but cannot expand it.

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
* Authorization decisions
* Agent-to-agent delegation
* Security attacks against delegated authorization

The eventual goal is to integrate the model with:

* OAuth
* Keycloak
* A resource server
* Real HTTP APIs
* Actual agent workflows
* Potentially an LLM-based agent

---

# 3. Conceptual Architecture

The current architecture is:

```
User
  |
  | AAT₀
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
Tool / Resource Server
```

Each participant has its own cryptographic key pair.

```
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

The proof of concept uses the following example.

## AAT₀

The root issuer gives Paul authority to:

* Deploy to any namespace
* Read the cluster

Conceptually:

```
deploy:
  namespace: "*"

read_cluster: {}
```

The token is held by Agent A.

```
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

Agent A reduces the deployment authority:

```
deploy(namespace=payments)
```

The `read_cluster` capability is removed entirely.

```
Agent A
     |
     | AAT₁
     | deploy(namespace=payments)
     v
  Agent B
```

This is valid because:

```
deploy(payments) ⊆ deploy(*)
```

The `read_cluster` capability has not been delegated.

---

## AAT₂

Agent B delegates to the tool agent.

Agent B adds another restriction:

```
deploy(
    namespace=payments,
    environment=production
)
```

The resulting authority is:

```
deploy(
    namespace=payments,
    environment=production
)
```

The chain therefore becomes:

```
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

# 5. The Core Security Property

The central property being demonstrated is:

```
Child authority ⊆ Parent authority
```

or:

```
Capabilities(AAT₂)
    ⊆
Capabilities(AAT₁)
    ⊆
Capabilities(AAT₀)
```

A child may:

* Remove a capability.
* Add a restriction.
* Narrow an existing capability.
* Delegate to another holder.

A child must not:

* Add a new capability.
* Remove an existing parent restriction.
* Broaden an existing constraint.
* Change the parent reference.
* Pretend to have been signed by another holder.

---

# 6. Cryptographic Model

The proof of concept uses **Ed25519** keys.

Each participant has:

```
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

Ed25519 is being used because it provides:

* Public/private key signatures
* Small keys
* Fast signing
* Fast verification
* Good support in Python's `cryptography` library
* Native support through PyJWT's EdDSA handling

The project is using asymmetric signatures rather than a shared secret.

This is important for delegation.

Agent A does not need the root issuer's private key.

Instead, Agent A signs a new token with its own private key.

---

# 7. Key Architecture

The current keys are:

```
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

The relationship is:

```
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

The private key is used to sign.

The public key is used to verify.

---

# 8. Important Key Security Rule

The private keys must never be committed to Git.

The `.gitignore` contains:

```
.venv/
keys/*-private.pem
__pycache__/
*.pyc
```

If a private key is exposed, it should be considered compromised.

For a real implementation, private keys would normally be protected by something such as:

* Hardware-backed keys
* Cloud KMS
* HSM
* Vault
* OS key stores
* Workload identity
* TPM-backed credentials

The PEM files are only being used because this is a local proof of concept.

---

# 9. Project Structure

The project is structured approximately as follows:

```
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
├── resource/
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
│   └── test_attacks.py
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

Some of the later components are part of the planned implementation and will be added as the proof of concept develops.

---

# 10. Environment Setup

The project was developed on OpenSUSE Tumbleweed using Python.

Create the project:

```
mkdir -p ~/workspace/aat-poc/{aat,issuer,agents,resource,tests,authz,keys}

cd ~/workspace/aat-poc
```

Create a virtual environment:

```
python3 -m venv .venv
```

Activate it:

```
source .venv/bin/activate
```

Install the required packages:

```
pip install cryptography PyJWT fastapi uvicorn
```

Save the dependencies:

```
pip freeze > requirements.txt
```

For subsequent sessions:

```
cd ~/workspace/aat-poc
source .venv/bin/activate
```

---

# 11. Python Import Path

The project currently uses the repository root as the Python module path.

Run scripts using:

```
PYTHONPATH=. python tests/generate_keys.py
```

rather than:

```
python tests/generate_keys.py
```

This allows imports such as:

```
from aat.keys import load_private_key
```

to work correctly.

---

# 12. Generate Keys

Generate all four key pairs:

```
PYTHONPATH=. python tests/generate_keys.py
```

Expected output:

```
Keys generated.
```

This creates:

```
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

# 13. Important Key Regeneration Warning

Regenerating the keys invalidates previously generated tokens.

For example:

```
old AAT₀
    |
    | signed by old issuer key
    X
new issuer key
```

Therefore, after regenerating keys, regenerate the complete token chain:

```
PYTHONPATH=. python issuer/issuer.py
PYTHONPATH=. python agents/agent_a.py
PYTHONPATH=. python agents/agent_b.py
```

---

# 14. Root Token - AAT₀

The root issuer creates the first authorization token.

The token contains:

```
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

The important authorization information is:

```
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
```

The holder is represented using `cnf`:

```
"cnf": {
  "jwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "..."
  }
}
```

This means that the token is bound to Agent A's public key.

---

# 15. Create AAT₀

Run:

```
PYTHONPATH=. python issuer/issuer.py
```

This creates:

```
aat0.jwt
```

The issuer signs the token with:

```
issuer-private.pem
```

The token is intended for Agent A.

The holder binding contains:

```
agent-a-public.pem
```

in JWK form.

---

# 16. JWT Structure

A JWT consists conceptually of:

```
HEADER.PAYLOAD.SIGNATURE
```

For example:

```
eyJhbGciOiJFZERTQSJ9
.
eyJpc3MiOiJodHRwczovL2FhdC1wb2MubG9j...
.
signature
```

The payload can be decoded for inspection without verifying the signature.

However, decoding is not verification.

This is important.

An attacker can modify an unsigned JWT payload.

Only signature verification establishes that the payload was signed by the expected key.

---

# 17. AAT₁ - Agent A Delegation

Agent A receives:

```
AAT₀
```

Agent A creates:

```
AAT₁
```

The new token is signed with:

```
agent-a-private.pem
```

The holder is changed to:

```
agent-b-public.pem
```

The capability is reduced to:

```
deploy:
  namespace: payments
```

The `read_cluster` capability is not delegated.

The important relationship is:

```
AAT₀
  |
  | holder = Agent A
  |
  v
Agent A
  |
  | signs AAT₁
  |
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

```
PYTHONPATH=. python agents/agent_a.py
```

This creates:

```
aat1.jwt
```

Agent A's private key signs the child token.

---

# 19. Parent Token Reference

A child token contains a reference to its parent.

The current proof of concept uses a SHA-256 hash of the complete parent JWT.

Conceptually:

```
parent_token
      |
      | SHA-256
      v
parent_hash
      |
      v
AAT₁.parent
```

For example:

```
{
  "parent": "qJ7..."
}
```

This provides a simple cryptographic link between:

```
AAT₀
```

and:

```
AAT₁
```

---

# 20. Why Hash the Parent?

The parent hash provides an important property.

Suppose an attacker sends:

```
AAT₁
```

with a different parent.

The verifier calculates:

```
SHA256(supplied_parent)
```

and compares it with:

```
AAT₁.parent
```

If they do not match:

```
REJECT
```

This prevents the child token from being detached from the parent token it claims to derive from.

---

# 21. AAT₂ - Agent B Delegation

Agent B receives:

```
AAT₁
```

Agent B creates:

```
AAT₂
```

Agent B signs it with:

```
agent-b-private.pem
```

The holder becomes:

```
tool-agent-public.pem
```

The capability becomes:

```
deploy:
  namespace: payments
  environment: production
```

This further restricts the authority.

---

# 22. Create AAT₂

Run:

```
PYTHONPATH=. python agents/agent_b.py
```

This creates:

```
aat2.jwt
```

The resulting chain is:

```
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

```
AAT₀
│
├── issuer = Root Issuer
├── holder = Agent A
└── capabilities:
      deploy(namespace=*)
      read_cluster

        │
        │ signed by Agent A
        │
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
        │
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

The tokens also contain:

```
"del_depth": 0,
"del_max_depth": 3
```

The intended meaning is:

```
AAT₀
del_depth = 0

AAT₁
del_depth = 1

AAT₂
del_depth = 2
```

The maximum permitted delegation depth is:

```
del_max_depth = 3
```

This provides another mechanism for limiting delegation chains.

A future implementation should enforce the depth limit during delegation.

---

# 25. Capability Attenuation

The attenuation implementation lives in:

```
aat/attenuation.py
```

The key function is:

```
is_attenuation(parent_payload, child_payload)
```

It checks whether the child capabilities are no broader than the parent capabilities.

---

# 26. Capability Example

Parent:

```
{
  "deploy": {
    "namespace": "*"
  }
}
```

Child:

```
{
  "deploy": {
    "namespace": "payments"
  }
}
```

This is allowed because:

```
*
 |
 +-- payments
```

The child has less authority.

---

# 27. Restricted Parent

If the parent contains:

```
{
  "deploy": {
    "namespace": "payments"
  }
}
```

then this child is valid:

```
{
  "deploy": {
    "namespace": "payments"
  }
}
```

But this is invalid:

```
{
  "deploy": {
    "namespace": "billing"
  }
}
```

because:

```
payments != billing
```

The child cannot change the parent's restriction.

---

# 28. Adding Restrictions

A child may add a new restriction.

Parent:

```
{
  "deploy": {
    "namespace": "payments"
  }
}
```

Child:

```
{
  "deploy": {
    "namespace": "payments",
    "environment": "production"
  }
}
```

This is allowed.

The child has introduced an additional restriction rather than broadening the authority.

---

# 29. Removing Capabilities

Removing a capability is allowed.

Parent:

```
{
  "deploy": {},
  "read_cluster": {}
}
```

Child:

```
{
  "deploy": {}
}
```

The child has less authority.

Therefore:

```
Child ⊆ Parent
```

still holds.

---

# 30. Adding Capabilities

Adding a capability is not allowed.

Parent:

```
{
  "deploy": {}
}
```

Child:

```
{
  "deploy": {},
  "delete_cluster": {}
}
```

This must be rejected.

The child cannot invent:

```
delete_cluster
```

because it was not granted by the parent.

---

# 31. Current Constraint Model

The current proof of concept deliberately uses a simple constraint model.

The current rules are:

1. `*` means any value.
2. A specific parent value must be retained by the child.
3. A child may add additional restrictions.
4. A child may remove capabilities.
5. A child cannot add new capabilities.

This is intended as a teaching implementation rather than a complete implementation of all possible AAT/RAR constraint semantics.

---

# 32. Delegation Chain Verification

The chain verifier lives in:

```
aat/verify.py
```

The verifier performs several checks.

For AAT₀:

```
Verify signature using Root Issuer public key
```

For AAT₁:

```
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

```
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

```
PYTHONPATH=. python tests/verify_chain.py
```

Expected result:

```
AAT₀ VERIFIED
================================================================================

...

AAT₁ VERIFIED
================================================================================

...

AAT₂ VERIFIED
================================================================================

...
```

A successful verification means:

```
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

AATs are not only about signing.

They also bind the token to a specific key.

The binding is represented by:

```
"cnf": {
  "jwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "..."
  }
}
```

The `cnf` value identifies the public key of the intended holder.

For example:

```
AAT₂
  |
  +-- cnf
       |
       +-- Tool Agent public key
```

The tool agent must therefore demonstrate possession of the corresponding private key.

---

# 35. Proof of Possession

A bearer token can potentially be used by anyone who obtains it.

Proof-of-possession changes this model.

The resource server generates a challenge:

```
{
  "challenge": "random-value",
  "timestamp": 1234567890
}
```

The legitimate token holder signs the challenge with its private key.

The resource server then verifies the signature using the public key contained in:

```
AAT₂.cnf.jwk
```

The flow becomes:

```
Resource Server
       |
       | challenge
       v
   Tool Agent
       |
       | sign(challenge)
       v
Resource Server
       |
       | verify using cnf public key
       v
     ALLOW
```

---

# 36. Proof-of-Possession Test

Run:

```
PYTHONPATH=. python tests/test_pop.py
```

The expected results are:

```
VALID PROOF?
================================================================================
True

ATTACKER USING AGENT B KEY
================================================================================
False

REPLAY ATTACK
================================================================================
False
```

This demonstrates three important properties.

### Correct private key

```
Tool Agent private key
        |
        v
valid signature
```

Result:

```
True
```

### Wrong private key

```
Agent B private key
        |
        v
invalid signature for Tool Agent key
```

Result:

```
False
```

### Replay

A signature generated for one challenge is not valid for a different challenge.

Result:

```
False
```

---

# 37. Token-Bound Proof of Possession

The next test demonstrates PoP directly against the key contained in the AAT.

Run:

```
PYTHONPATH=. python tests/test_aat_pop.py
```

The test:

1. Loads AAT₂.
2. Verifies its signature.
3. Extracts the holder key from `cnf`.
4. Creates a challenge.
5. Signs the challenge using the Tool Agent private key.
6. Verifies the proof against the key contained in the token.

Expected result:

```
AAT₂ PROOF OF POSSESSION
================================================================================
True
```

This is an important distinction.

The resource server does not simply ask:

```
"Do you have AAT₂?"
```

It can ask:

```
"Can you prove that you possess the private key bound to AAT₂?"
```

---

# 38. Authorization Policy

The authorization layer is separate from cryptographic verification.

Cryptographic verification answers:

```
Is this token authentic?
```

Attenuation verification answers:

```
Is this delegated authority within the parent's authority?
```

Proof-of-possession answers:

```
Does the caller possess the bound key?
```

Policy answers:

```
Is this particular request permitted?
```

These are different security decisions.

---

# 39. Example Resource Request

Suppose the resource receives:

```
{
  "action": "deploy",
  "namespace": "payments",
  "environment": "production"
}
```

AAT₂ grants:

```
{
  "deploy": {
    "namespace": "payments",
    "environment": "production"
  }
}
```

The request matches the token.

Therefore the policy engine can return:

```
ALLOW
```

---

# 40. Denied Namespace

Suppose the request is:

```
{
  "action": "deploy",
  "namespace": "billing",
  "environment": "production"
}
```

AAT₂ only permits:

```
namespace=payments
```

Therefore:

```
billing != payments
```

and the request must be denied.

```
DENY
```

---

# 41. Denied Environment

Suppose the request is:

```
{
  "action": "deploy",
  "namespace": "payments",
  "environment": "development"
}
```

AAT₂ requires:

```
environment=production
```

Therefore:

```
development != production
```

and the request must be denied.

---

# 42. Denied Capability

Suppose the request is:

```
{
  "action": "read_cluster"
}
```

Although AAT₀ originally contained:

```
read_cluster
```

AAT₁ did not delegate it.

Therefore AAT₂ does not contain it.

The request must be denied.

This demonstrates why the complete delegation chain matters.

The resource server must not simply look at what the original user was allowed to do.

It must determine what the **current holder** was delegated.

---

# 43. End-to-End Authorization

The eventual resource-server authorization flow should look like:

```
Request
   |
   v
Resource Server
   |
   v
Verify AAT chain
   |
   +------------------+
   |                  |
 valid              invalid
   |                  |
   v                  v
Verify PoP           DENY
   |
   +-------------+
   |             |
 valid        invalid
   |             |
   v             v
Evaluate       DENY
 policy
   |
   +-------+
   |       |
 ALLOW    DENY
```

This separation is important.

---

# 44. The Security Boundary

The resource server should ultimately be responsible for the final authorization decision.

The resource server should not blindly trust:

```
Agent A
```

or:

```
Agent B
```

Instead it should independently verify:

```
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
proof of possession
+
request policy
```

---

# 45. Attack Scenarios

One of the main purposes of the proof of concept is to demonstrate attacks.

The planned security test suite includes:

1. Modify token payload
2. Forge token signature
3. Use wrong signing key
4. Replace parent token
5. Expand capabilities
6. Add a new tool
7. Remove a parent restriction
8. Change namespace
9. Change environment
10. Replay PoP
11. Use wrong PoP key
12. Skip a delegation level
13. Exceed delegation depth
14. Substitute a different holder
15. Use an expired token

---

# 46. Attack: Modify JWT Payload

Suppose an attacker changes:

```
namespace=payments
```

to:

```
namespace=*
```

The JWT payload changes.

However, the signature no longer matches.

Verification must therefore fail.

```
Modified payload
       |
       v
Signature mismatch
       |
       v
      DENY
```

---

# 47. Attack: Add a Capability

Original:

```
{
  "deploy": {
    "namespace": "payments"
  }
}
```

Attacker attempts:

```
{
  "deploy": {
    "namespace": "payments"
  },
  "delete_cluster": {}
}
```

The child capability does not exist in the parent.

The attenuation check must reject it.

---

# 48. Attack: Broaden a Restriction

Parent:

```
{
  "deploy": {
    "namespace": "payments"
  }
}
```

Attacker attempts:

```
{
  "deploy": {
    "namespace": "*"
  }
}
```

This attempts to broaden:

```
payments
```

into:

```
*
```

The child is therefore outside the parent's authority.

Result:

```
DENY
```

---

# 49. Attack: Change the Parent

Suppose AAT₁ was generated from AAT₀.

An attacker attempts to claim:

```
AAT₁.parent = hash(attacker-controlled-token)
```

The verifier calculates:

```
hash(actual supplied parent)
```

and compares it to the token's `parent`.

The mismatch causes rejection.

---

# 50. Attack: Use the Wrong Signing Key

Suppose AAT₂ should be signed by Agent B.

An attacker signs AAT₂ with Agent A's private key.

The verifier obtains the expected signer from:

```
AAT₁.cnf
```

which identifies Agent B.

The Agent A signature does not verify against Agent B's public key.

Result:

```
DENY
```

---

# 51. Attack: Steal the Token

AAT₂ is copied by an attacker.

Without proof-of-possession, the attacker might be able to present the token as a bearer credential.

With holder binding:

```
AAT₂
  |
  +-- cnf = Tool Agent public key
```

the resource server can require the attacker to prove possession of the corresponding private key.

The attacker does not have it.

Therefore:

```
DENY
```

---

# 52. Attack: Replay a PoP

An attacker captures:

```
challenge
+
signature
```

The resource server generates a new challenge.

The old signature does not verify against the new challenge.

Therefore:

```
DENY
```

This is why the challenge must be unpredictable and preferably single-use.

---

# 53. Attack: Skip Delegation

Suppose:

```
AAT₀
  |
  v
AAT₁
  |
  v
AAT₂
```

An attacker attempts to present AAT₂ without the expected parent chain.

The verifier should reconstruct the chain and validate every link.

A token should not be considered valid simply because its own JWT signature is valid.

The delegation relationship matters.

---

# 54. Attack: Exceed Delegation Depth

The tokens contain:

```
del_depth
del_max_depth
```

For example:

```
AAT₀ = depth 0
AAT₁ = depth 1
AAT₂ = depth 2
```

If:

```
del_max_depth = 3
```

then additional delegation beyond the permitted depth should be rejected.

This enforcement will be strengthened as the POC develops.

---

# 55. Current Limitations

This is a proof of concept and intentionally simplifies several areas.

## Simplified constraint model

The current implementation only supports simple equality and wildcard semantics.

For example:

```
namespace=*
```

and:

```
namespace=payments
```

It does not yet implement a comprehensive constraint language.

---

## Simplified parent reference

The parent is currently represented by:

```
SHA-256(parent JWT)
```

This is useful for demonstrating the concept but should eventually be aligned more closely with the exact AAT specification semantics.

---

## Local PEM keys

Private keys currently exist as local PEM files.

This is not appropriate for production.

---

## No OAuth yet

The current POC is deliberately independent of OAuth and Keycloak.

OAuth/Keycloak integration is a later phase.

---

## No real resource server yet

The current authorization logic is being developed independently before introducing FastAPI.

---

## No real LLM agent yet

The current "agents" are Python programs.

They represent the delegation model without introducing the additional complexity of an LLM.

---

# 56. Threat Model

The proof of concept assumes that some participants may be compromised or malicious.

For example:

```
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

The intended security property is:

```
No more authority than it was delegated.
```

If Agent B receives:

```
deploy(namespace=payments)
```

it should not be able to create:

```
deploy(namespace=billing)
```

or:

```
delete_cluster
```

or:

```
read_cluster
```

unless those capabilities were legitimately delegated to it.

---

# 57. Why Attenuation Matters for Agents

Agentic systems introduce a particularly interesting delegation problem.

An agent may decide:

```
"I need another agent to perform this task."
```

It may then delegate authority to another agent.

Without attenuation, this creates a risk:

```
User
  |
  v
Agent A
  |
  | full authority
  v
Agent B
  |
  | full authority
  v
Agent C
```

Every agent effectively receives the same power.

With attenuation:

```
User
  |
  | deploy(*)
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

# 58. Least Privilege

The model naturally supports least privilege.

Instead of giving Agent B:

```
everything the user can do
```

Agent A can give it only:

```
the specific authority required for its task
```

For example:

```
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

This is much closer to the actual task being performed.

---

# 59. Separation of Authentication and Authorization

The project demonstrates that several different questions must be answered.

### Authentication

Who signed this?

```
JWT signature
```

### Delegation

Who delegated this authority?

```
parent
+
signer
```

### Attenuation

Is the delegated authority narrower than the parent's?

```
capability comparison
```

### Holder binding

Who is the token intended for?

```
cnf
```

### Proof of possession

Does the caller actually possess the holder's private key?

```
challenge/response
```

### Authorization

Can this specific request be performed?

```
policy evaluation
```

These should not be collapsed into one check.

---

# 60. Current Run Sequence

After generating keys, the complete current flow is:

## 1. Generate keys

```
PYTHONPATH=. python tests/generate_keys.py
```

## 2. Issue AAT₀

```
PYTHONPATH=. python issuer/issuer.py
```

## 3. Agent A creates AAT₁

```
PYTHONPATH=. python agents/agent_a.py
```

## 4. Agent B creates AAT₂

```
PYTHONPATH=. python agents/agent_b.py
```

## 5. Verify the chain

```
PYTHONPATH=. python tests/verify_chain.py
```

## 6. Test proof-of-possession

```
PYTHONPATH=. python tests/test_pop.py
```

## 7. Test token-bound proof-of-possession

```
PYTHONPATH=. python tests/test_aat_pop.py
```

Additional policy and attack tests will be added as the implementation progresses.

---

# 61. Complete End-to-End Flow

The complete conceptual flow is:

```
                   USER
                    |
                    |
                    v
              Root Issuer
                    |
                    | AAT₀
                    | deploy(*)
                    | read_cluster
                    v
                Agent A
                    |
                    | AAT₁
                    | deploy(payments)
                    v
                Agent B
                    |
                    | AAT₂
                    | deploy(payments,
                    |        production)
                    v
               Tool Agent
                    |
                    | PoP
                    v
             Resource Server
                    |
                    | verify chain
                    | verify PoP
                    | evaluate policy
                    v
              ALLOW / DENY
```

---

# 62. Future FastAPI Resource Server

The next major stage is to introduce a real HTTP resource server.

For example:

```
POST /deploy
```

with:

```
{
  "namespace": "payments",
  "environment": "production"
}
```

The request could contain:

```
Authorization: Bearer <AAT₂>
```

plus a proof-of-possession mechanism.

The resource server would then:

1. Parse token
2. Verify JWT
3. Build delegation chain
4. Verify parent relationships
5. Verify attenuation
6. Check expiry
7. Extract `cnf`
8. Verify proof-of-possession
9. Evaluate requested action
10. Return ALLOW/DENY

---

# 63. Future OAuth Integration

Once the core cryptographic model is understood, the next step is to introduce OAuth.

The eventual architecture could become:

```
User
  |
  v
OAuth Authorization Server
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
Resource Server
```

The POC will then explore how the AAT concepts fit into a conventional OAuth deployment.

---

# 64. Future Keycloak Integration

Keycloak is deliberately not the first component being used.

The reason is to separate two problems:

```
AAT cryptographic model
```

from:

```
Identity Provider / OAuth implementation
```

Once the core model is understood, Keycloak can provide the identity and OAuth infrastructure around it.

The eventual setup could include:

```
                   Keycloak
                       |
                       |
                  OAuth tokens
                       |
                       v
                    Agent A
                       |
                     AAT₁
                       |
                       v
                    Agent B
                       |
                     AAT₂
                       |
                       v
                  Resource API
```

Potential areas to investigate include:

* Keycloak clients
* OAuth token exchange
* JWT signing
* Custom claims
* Token mappers
* Authorization services
* Client authentication
* Proof-of-possession
* Sender-constrained tokens
* Custom protocol extensions

---

# 65. Future Real Agentic Workflow

After the cryptographic and HTTP components are working, the Python "agents" can be replaced or augmented with actual agent workflows.

For example:

```
User:
    "Deploy the payments application."

        |
        v

Agent A:
    determines deployment is required

        |
        | delegates restricted authority
        v

Agent B:
    deployment specialist

        |
        | delegates restricted authority
        v

Deployment Tool:
    performs actual deployment

        |
        v

Kubernetes / OpenShift
```

The important point is that the agents do not simply pass around an unrestricted user credential.

Instead, each delegation produces a more narrowly scoped authorization artifact.

---

# 66. Potential OpenShift Example

A useful future test case is an OpenShift deployment.

The root authority might conceptually allow:

```
deploy(namespace=*)
```

Agent A delegates:

```
deploy(namespace=payments)
```

Agent B delegates:

```
deploy(
    namespace=payments,
    environment=production
)
```

The resource server could then map this to an actual OpenShift action.

For example:

```
POST /api/deploy
```

with:

```
{
  "namespace": "payments",
  "environment": "production"
}
```

The authorization layer verifies that the request is within the delegated authority before interacting with the cluster.

---

# 67. Future Security Tests

The attack test suite should eventually automate tests such as:

```
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

test_expired_token()

test_delegation_depth()

test_skipped_parent()

test_unknown_tool()
```

The objective is to turn the security properties into executable tests.

---

# 68. Desired Security Invariants

The final implementation should enforce invariants such as:

```
Invariant 1:
A token must have a valid signature.

Invariant 2:
A child must be signed by the holder of its parent.

Invariant 3:
A child must reference its actual parent.

Invariant 4:
A child cannot have more authority than its parent.

Invariant 5:
A token can only be used by its bound holder.

Invariant 6:
Proof-of-possession must be tied to a fresh challenge.

Invariant 7:
Expired tokens cannot be used.

Invariant 8:
Delegation depth cannot exceed the permitted maximum.

Invariant 9:
The requested action must be allowed by the final token.

Invariant 10:
The resource server makes the final authorization decision.
```

---

# 69. Current Status

The proof of concept currently demonstrates:

* [x] Python project structure
* [x] Ed25519 key generation
* [x] JWT creation
* [x] Root authorization token
* [x] Holder public-key binding
* [x] Agent A delegation
* [x] Agent B delegation
* [x] Parent token hashing
* [x] Capability attenuation
* [x] Delegation-chain verification
* [x] Proof-of-possession
* [x] Token-bound proof-of-possession
* [x] Basic authorization policy concepts

Next stages:

* [ ] Complete authorization decision layer
* [ ] Build FastAPI resource server
* [ ] Implement HTTP-based PoP
* [ ] Build automated attack tests
* [ ] Enforce delegation depth
* [ ] Improve constraint semantics
* [ ] Improve token/chain validation structure
* [ ] Integrate OAuth
* [ ] Integrate Keycloak
* [ ] Explore token exchange
* [ ] Introduce real agent workflows
* [ ] Introduce an LLM-based agent
* [ ] Integrate with a real tool/API
* [ ] Integrate with OpenShift/Kubernetes

---

# 70. Roadmap

The intended development sequence is:

```
Phase 1
Basic signed token
        |
        v
Phase 2
Capabilities
        |
        v
Phase 3
Attenuation
        |
        v
Phase 4
Delegation chain
        |
        v
Phase 5
Offline chain verification
        |
        v
Phase 6
Proof of possession
        |
        v
Phase 7
Argument constraints
        |
        v
Phase 8
Attack/security tests
        |
        v
Phase 9
FastAPI resource server
        |
        v
Phase 10
OAuth integration
        |
        v
Phase 11
Keycloak integration
        |
        v
Phase 12
Real agentic workflow
        |
        v
Phase 13
LLM + tools + OpenShift
```

---

# 71. What This POC Is Intended to Demonstrate

At the end of the project, the desired demonstration is something like:

```
User
  |
  | "Deploy payments application"
  |
  v
Agent A
  |
  | receives broad authorization
  |
  | delegates:
  | deploy(namespace=payments)
  v
Agent B
  |
  | delegates:
  | deploy(namespace=payments,
  |        environment=production)
  v
Tool Agent
  |
  | proves possession of bound key
  v
Resource Server
  |
  | verifies complete AAT chain
  |
  | verifies attenuation
  |
  | verifies proof-of-possession
  |
  | evaluates request
  v
OpenShift / Kubernetes
```

If an attacker attempts:

```
deploy(namespace=billing)
```

the request is rejected.

If an attacker attempts:

```
delete_cluster
```

the request is rejected.

If an attacker copies AAT₂ but does not possess the Tool Agent private key:

```
DENY
```

If an attacker modifies the token:

```
DENY
```

If an attacker attempts to broaden a delegated capability:

```
DENY
```

This is the core security story the proof of concept is intended to demonstrate.

---

# 72. Disclaimer

This project is an educational proof of concept.

It is intended to explore the concepts behind attenuating authorization and agentic delegation.

It is not currently a production-ready authorization system.

In particular, the current implementation contains deliberately simplified:

* Constraint semantics
* Parent references
* Key storage
* Proof-of-possession
* Token validation
* Delegation-depth enforcement
* OAuth integration
* Resource-server implementation

Before using any of these mechanisms in a production environment, they should be reviewed against the relevant standards and security requirements.

---

# 73. Summary

The central idea of this project can be reduced to one principle:

```
Delegation must never create more authority than the
delegator already possesses.
```

The chain:

```
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

```
Capabilities(AAT₂)
    ⊆
Capabilities(AAT₁)
    ⊆
Capabilities(AAT₀)
```

Combined with:

```
Cryptographic signatures
        +
Parent references
        +
Capability attenuation
        +
Holder binding
        +
Proof of possession
        +
Request authorization
```

this provides a foundation for exploring secure delegation in multi-agent systems.

The eventual objective is to move from this local Python demonstration to:

```
OAuth
  +
Keycloak
  +
Agent delegation
  +
Proof of possession
  +
Resource APIs
  +
LLM agents
  +
OpenShift/Kubernetes
```

while preserving the same fundamental security invariant:

```
A delegated agent can only act within the authority
that was delegated to it.
```

