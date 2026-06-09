# Playbook — Cryptographic Provider Compromise

Status: draft — V00.71.00
CWE: CWE-937 (Use of Components with Known Vulnerabilities),
CWE-693 (Protection Mechanism Failure), CWE-320 (Key Management
Errors)

## Trigger

- A CVE is published against a JCA provider or against the
  BouncyCastle library used by `jSentinel-crypto-bc`.
- A vendor advisory retracts a provider (revoked certification,
  validation revoked, etc.).
- A supply-chain incident affects the provider artefact (account
  takeover at the upstream repository, malicious release, etc.).

## Pre-conditions

- SBOM for the affected release is archived per
  `../standards/sbom-and-provenance.md`.
- Audit retention covers the suspected exposure window.

## Response

### 1. Identify scope (minutes)

- Locate the affected provider in the SBOM:
  - `bcprov-jdk18on` → `jSentinel-crypto-bc`
  - JDK security provider → all credential operations
- Decide whether the compromise affects integrity (output is
  wrong), confidentiality (output is leakable) or availability
  (provider crashes / hangs).

### 2. Contain (minutes — hours)

- For BouncyCastle CVEs:
  - Pin the unaffected version in the consuming project's POM and
    redeploy.
  - If no fixed version is available, temporarily remove
    `jSentinel-crypto-bc` from the classpath. The core falls back
    to PBKDF2 (JDK-only). Existing Argon2id / bcrypt / scrypt
    envelopes will fail verification cleanly — fall back to the
    reset flow (see `../../playbooks/reset-abuse.md` for guidance
    on the volume that triggers).
- For JDK security provider CVEs:
  - Upgrade the JDK to a fixed build. Some CVEs require a JCA
    provider order change — make that change **in the JDK
    configuration**, not in framework code (the framework never
    rewrites provider order).

### 3. Detect tampering

- Compare the SBOM of the deployed release with the SBOM of the
  build artefact in the release archive. Differences require
  investigation.
- Re-verify the PGP / Sigstore signature of every framework jar
  in the deployment.

### 4. Decide on re-encoding

If the compromise affects the integrity of stored hashes
(e.g. a CVE makes the provider produce predictable salts), treat
the incident as an algorithm compromise as well — see
`algorithm-compromise.md`.

If the compromise affects only availability or confidentiality
of *future* operations, no re-encoding is needed; the patched
provider verifies existing envelopes normally.

## Rollback boundary

- Upgrading or replacing a provider is generally reversible
  (depinpoint the previous version).
- Re-encoding decisions made on top of a provider compromise are
  not — see `algorithm-compromise.md`.

## Operator checklist

- [ ] Identify the provider in the deployment SBOM.
- [ ] Decide containment: pin, remove, or upgrade.
- [ ] Re-verify framework artefact signatures.
- [ ] Decide whether re-encoding is required.
- [ ] Update the operator checklist in
      `../standards/fips-profile.md` if the FIPS profile is now
      invalid.
- [ ] Post-incident review.

## What the framework does not do

- It does **not** scan the deployment for CVEs.
- It does **not** automatically upgrade dependencies.
- It does **not** verify the SBOM at runtime.
