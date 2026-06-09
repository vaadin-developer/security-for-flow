# Playbook — Hashing Algorithm Compromise

Status: draft — V00.71.00
CWE: CWE-327 (Use of a Broken or Risky Cryptographic Algorithm),
CWE-693 (Protection Mechanism Failure)

## Trigger

- A vendor advisory or NIST notice retires the password-hashing
  algorithm currently in use (PBKDF2-HMAC-SHA-256 minimum cost,
  Argon2id, bcrypt or scrypt).
- A practical attack against the algorithm is published.
- An audit identifies that the deployment's configured parameters
  fall below the current recommendation.

## Pre-conditions

- `jSentinel-core` is at V00.71.00 or later (envelope carries
  `alg=`, `prov=` and `pol=` markers).
- The deployment runs verifications regularly enough that a
  transparent rehash window of weeks-to-months is acceptable. If
  faster turnaround is required, see step 3.

## Response

### 1. Decide the replacement

- Identify the new algorithm and parameters: PBKDF2 with higher
  iteration count, Argon2id with larger {m,t,p}, or a switch
  between PBKDF2 / Argon2id / bcrypt / scrypt.
- If the replacement requires `jSentinel-crypto-bc` and the module
  is not yet on the classpath, plan the dependency change.

### 2. Update the policy

- Increment `PasswordHashPolicy.policyVersion`.
- Mark the old algorithm-id or old parameter set as deprecated in
  the policy. The `RehashDecisionEngine` emits
  `RehashDecision.Required(RehashReason.ALGORITHM_DEPRECATED)`
  or `RehashReason.PARAMETERS_OUTDATED` accordingly.
- Deploy the updated policy.

### 3. Re-encode

The framework rehashes transparently on every successful
verification. Two acceleration paths exist:

- **Wait-and-decay** — every successful login pulls the user into
  the new policy. Acceptable when the user base is highly active.
- **Force rotation** — mark every credential as
  `MUST_CHANGE` via the mass-status-change helper. Use this when
  the previous algorithm was actively broken (CWE-327) rather
  than merely deprecated.

### 4. Validate

- Audit query: count `CredentialVerificationSucceeded` events
  carrying `algorithm = <new>` and `algorithm = <old>` over time.
- The post-rotation acceptance criterion is "no successful
  verification under the old algorithm for {N} days".

### 5. Decommission

- Drop the deprecated algorithm from the policy entirely.
- Any envelope still using it will fail verification cleanly and
  fall to the dummy KDF path, preserving observational
  equivalence with unknown-user lookups (CWE-203).

## Rollback boundary

You can roll back the policy version *upgrade* — the old
algorithm classes remain present and can verify legacy envelopes.
You **cannot** roll back individual envelopes once a verification
has rehashed them.

## Operator checklist

- [ ] Decide new algorithm + parameters.
- [ ] Increment `policyVersion`; mark old algorithm deprecated.
- [ ] Deploy the new policy.
- [ ] Optionally force `MUST_CHANGE` via the mass helper, with
      `EmergencyPolicyOverride.Reason.ALGORITHM_COMPROMISE`.
- [ ] Track the rehash audit stream until the old-algorithm count
      reaches zero.
- [ ] Drop the deprecated algorithm class from the policy.
- [ ] Post-incident review.

## What the framework does not do

- It does **not** decide when an algorithm is unsafe — that is an
  operator / NIST / vendor judgement.
- It does **not** publish notices.
- It does **not** auto-upgrade parameters on its own — the
  `Pbkdf2ParameterCalibrator` is an opt-in operator tool.
