---
name: jcustos-rest-hardening
description: Layer-3 follow-up to `jcustos-rest` (and optionally `jcustos-rest-persistence`) — wires the V00.71 production-hardening features for REST: modern password hashing via Argon2id (`BouncyCastleHashingServices.modern()`), optional HIBP password-leak check, and Phase-4c JCustos-version drift detection via `RestJCustosVersionFilter` so revoking a role mid-session forces the affected user back to /api/auth/login on the next request (the existing token starts returning 401). Prerequisite: a project that already ran `jcustos-rest`. Use PROACTIVELY when the user mentions Argon2id REST, modern crypto REST, HIBP REST, drift detection REST, `RestJCustosVersionFilter`, "kick REST client out on role revoke", "production-ready REST jCustos", "REST V00.71 features". Adds 2 dependencies (`jCustos-crypto-bc`, `jCustos-credentials-hibp`), 4 new templates (`PasswordPreflight`, `VersionBumper`, `SubjectIdResolverImpl`, `DriftDetection` wiring), 2 replacement templates (`RestServer` swaps hashing + wires `.sessions(.securityVersion(...))` + integrates the `RestJCustosVersionFilter` ahead of every protected handler, `UsersHandler` calls `VersionBumper.bump(user)` after role mutations), 2 new META-INF/services entries.
---

# jCustos REST hardening — layer 3

REST-side equivalent of `jcustos-vaadin-hardening`. Replaces
PBKDF2 with Argon2id, adds an optional HIBP leak check, and wires
the V00.71 `RestJCustosVersionFilter` so an admin revoking a role
forces every open Bearer token for that user to start returning 401
on the next request — no logout-and-relogin needed.

## Slots

| Slot | Default |
|---|---|
| `{{HIBP_ENABLED}}` | `false` |

## Templates

| Template | Target | Source |
|---|---|---|
| `pom-snippet.xml.tmpl` | merge | shared with vaadin-hardening |
| `SubjectIdResolverImpl.java.tmpl` | `security/services/` | shared |
| `VersionBumper.java.tmpl` | `security/services/` | shared |
| `PasswordPreflight.java.tmpl` | `security/services/` | shared |
| `RestServer.java.tmpl` | OVERWRITE | NEW (Argon2id + securityVersion + filter wired) |
| `UsersHandler.java.tmpl` | OVERWRITE | NEW (VersionBumper.bump after role mutations) |
| `services-JCustosVersionStore.tmpl` | META-INF/services | shared |
| `services-SubjectIdResolver.tmpl` | META-INF/services | shared |

## Drift flow

```
Admin POST /api/users/{id}/roles/{role}
  → UsersHandler.assignRole → directory.assignRole(...) → VersionBumper.bump(user)
    → InMemoryJCustosVersionStore.increment(key) → +1
User makes any request
  → RestJCustosVersionFilter compares snapshot vs current
    → mismatch → 401 + audit SessionStale event
```

## Pitfall

The `RestJCustosVersionFilter` reads the snapshot from the token
metadata. Layer-1's in-memory `TokenStore` records the snapshot at
login time — that wiring is already in the layer-1 `RestServer`
output (via `RestSecurity.bootstrap().sessions(...)`). Layer 3 adds
the per-request check.
