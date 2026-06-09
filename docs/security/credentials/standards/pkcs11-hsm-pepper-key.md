# PKCS#11 / HSM as Pepper Key Source

Status: draft — V00.71.00 — integration guidance only, no integration
code in this release
CWE: CWE-320 (Key Management Errors), CWE-522 (Insufficiently
Protected Credentials)

## Why this matters

The `PepperService` SPI in `jSentinel-core` exposes a pepper key as a
`PepperReference` and an `HmacSHA256` operation. The default
`InMemoryPepperService` holds the key bytes in a `byte[]` inside the
JVM heap, which is appropriate for development and small-scale
production but unacceptable for deployments where pepper compromise
is the threat model — see `../playbooks/pepper-compromise.md`.

## Recommended boundary

```
+-------------------+        +---------------------+        +-----+
| PasswordHashing   |  ----> |  PepperService SPI  |  ----> | HSM |
| Service           |        |  (PKCS#11 adapter)  |        |     |
+-------------------+        +---------------------+        +-----+
                                       ^
                                       |   never leaves the HSM
                                  pepper key bytes
```

- The pepper key is generated **inside** the HSM (`C_GenerateKey`) and
  is never exported.
- The application JVM holds a **handle / key id**, not the bytes.
- HMAC-SHA-256 (`CKM_SHA256_HMAC`) is executed **on** the HSM —
  inputs are sent in, the 32-byte tag is returned.

## Building a PKCS#11-backed PepperService

Two production paths are common:

### Option A — Sun JCE PKCS#11 provider (JDK-bundled)

```java
PepperService pkcs11Pepper = new PepperService() {
    private final Provider sunPkcs11 =
        Security.getProvider("SunPKCS11").configure(
            "name=corp-hsm\nlibrary=/usr/lib/libsofthsm2.so\nslot=0");
    @Override public PepperReference activeReference() { ... }
    @Override public byte[] applyHmac(PepperReference ref, byte[] input) {
        Mac mac = Mac.getInstance("HmacSHA256", sunPkcs11);
        mac.init(loadKey(ref));            // SecretKey backed by HSM handle
        return mac.doFinal(input);
    }
};
```

The Sun PKCS#11 provider is part of the JDK; no extra dependency
is required. It does **not** affect the global JCA provider order —
the explicit `Mac.getInstance(..., sunPkcs11)` form scopes the
provider per call.

### Option B — Vendor SDK (Thales, Utimaco, AWS CloudHSM, etc.)

These vendors ship a JCA provider and / or a native client. Wire
them the same way Option A wires `SunPKCS11`. Pinning to a vendor
SDK is **operator choice** — the framework deliberately ships no
adapter for any specific HSM.

## Rotation

Both options support rotation via the existing
`PepperReference` / `PasswordHashingService` rehash mechanics — when
the active key id changes, verified envelopes are tagged with
`RehashReason.PEPPER_KEY_ROTATED` and transparently re-encoded under
the new key.

## What the framework guarantees

- The `PepperService` SPI is stable across all deployments.
- A custom HSM-backed implementation can be swapped in by writing a
  single class.
- `applyHmac` is invoked inside a try-with-resources around a
  `SecretValue` so the input buffer is wiped on every call —
  see `Konzept-V00.71.00.md` §6.
- Pepper key bytes are **never** logged, persisted by the
  framework, included in `toString()`, or accepted as input to
  `AuditEvent` types — that holds whether the key lives in heap or
  in an HSM.

## What the framework does **not** ship

- No PKCS#11 connector code.
- No vendor-specific HSM driver wrapper.
- No automatic key-generation procedure.
- No FIPS-mode bridging — see `fips-profile.md`.

These are integration-time decisions and stay in the consumer
project.

## Maintenance

When a future release adds an officially supported HSM connector
module (e.g. `security-credentials-hsm-pkcs11`), this document is
demoted to "historic" and the new module's README becomes the
reference.
