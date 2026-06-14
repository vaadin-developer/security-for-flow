---
name: jsentinel-vaadin-hardening
description: Layer-3 follow-up to `jsentinel-vaadin` (and optionally `jsentinel-vaadin-persistence`) — wires the V00.71 production-hardening features: modern password hashing via Argon2id (`BouncyCastleHashingServices.modern()` from `jSentinel-crypto-bc`), optional HIBP password-leak check (`HaveIBeenPwnedCompromisedPasswordChecker` from `jSentinel-credentials-hibp`), and Phase-4c JSentinel-version drift detection (`JSentinelVersionStore` + `JSentinelVersionEnforcerListener`) so revoking a role mid-session forces the affected user back to the login view on the next navigation. Prerequisite: a project that already ran `jsentinel-vaadin`. Use PROACTIVELY when the user mentions Argon2id, modern crypto, bcrypt, scrypt, BouncyCastle hashing, password upgrade, compromised password, HIBP, k-anonymity, "production crypto", "swap PBKDF2 for Argon2id", drift detection, `JSentinelVersion`, session invalidation on role change, "revoke session immediately", `JSentinelVersionEnforcer`, `JSentinelVersionEnforcerListener`, "kick user out on role revoke", "stale subject", compliance hardening, "production-ready jSentinel", "V00.71 features". File-level signals: an existing `JSentinelBootstrapInitListener.java` with `.credentials(c -> c.hashing(PasswordHashingServices.defaults()))` (PBKDF2 default that this skill replaces); an `AdminRolesView` that mutates roles but doesn't bump version (this skill adds the call); absence of `JSentinelVersionInitListener` / `META-INF/services/com.svenruppert.jsentinel.session.JSentinelVersionStore`. Adds 2 dependencies (`jSentinel-crypto-bc`, `jSentinel-credentials-hibp`), 4 new templates (`PasswordPreflight`, `VersionBumper`, `JSentinelVersionInitListener`, `SubjectIdResolverImpl`), 1 replacement template (`AdminRolesView` calls `VersionBumper.bump(user)` after every role mutation). The bootstrap chain is extended via the layer-1 `BootstrapExtension` SPI — no overwrite of `JSentinelBootstrapInitListener.java`. Order with `jsentinel-vaadin-persistence` is irrelevant, 2 new META-INF/services entries (`JSentinelVersionStore`, `SubjectIdResolver`). Does NOT cover token-based first-admin bootstrap or storage persistence — those are the layer-2 `jsentinel-vaadin-persistence` skill; does NOT cover API keys / refresh tokens / rate limiting — those are roadmap V00.74+ and reach beyond the V00.71 surface.
---

# jSentinel hardening — layer 3

Additive layer on top of `jsentinel-vaadin` (and optionally on top of
`jsentinel-vaadin-persistence`). Lifts the security stack from "demo-grade
defaults" to "V00.71 production hardening" in three concerns:

1. **Modern password hashing** — PBKDF2 → Argon2id. Stored hashes
   created under the old profile auto-migrate on next successful
   login (`RehashDecisionEngine` flags them as
   `ALGORITHM_DEPRECATED`).
2. **HIBP password-leak check (opt-in at setup / password change)**
   — k-anonymity range API call. Plain password never leaves the
   JVM; only the first 5 SHA-1 hex chars are transmitted.
3. **Phase-4c drift detection** — when an admin revokes or grants a
   role, the affected user's next navigation reroutes to
   `{{SUBJECT_PREFIX}}LoginView`. No more "this user keeps using a
   role we just revoked until they log out."

## How to use this skill

1. **Verify the prerequisite** — `jsentinel-vaadin` is present
   (`JSentinelBootstrapInitListener.java`, `AdminRolesView.java`
   exist).
2. **Apply the POM patch** — adds 2 dependencies.
3. **Add 4 new templates** under their target paths.
4. **Replace 1 existing template** (only `AdminRolesView` now — bootstrap goes through the additive Extension SPI) — `JSentinelBootstrapInitListener`
   gets new bootstrap calls, `AdminRolesView` calls the bumper.
5. **Add 2 META-INF/services entries** — `JSentinelVersionStore` and
   `SubjectIdResolver`.
6. **Verify**: compile, run, log in as admin, revoke a role on
   another logged-in user → that user's next click reroutes to
   `/login`.

## Reading the brief — slots

| Slot | Example | Default if missing |
|---|---|---|
| `{{HIBP_ENABLED}}` | `true`, `false` | `false` (opt-in: requires network egress to `api.pwnedpasswords.com`) |

`{{BASE_PACKAGE}}`, `{{SUBJECT_TYPE}}`, `{{SUBJECT_PREFIX}}` are
inherited from the previous skill output.

## What changes from `jsentinel-vaadin`

| File | Change |
|---|---|
| `pom.xml` | + `jSentinel-crypto-bc` + (if HIBP) `jSentinel-credentials-hibp` |
| `security/bootstrap/HardeningBootstrapExtension.java` (NEW) | implements `BootstrapExtension` SPI from layer 1; `contributeCredentials(c)` calls `c.hashing(BouncyCastleHashingServices.modern())`; `contributeSessions(s)` wires `securityVersion` + `subjectIdResolver` via `JSentinelServiceResolver.find...`. Picked up by `BootstrapBuilder.apply(...)` at runtime — **no overwrite of the layer-1 listener.** |
| `security/services/SubjectIdResolverImpl.java` | **NEW** — implements `SubjectIdResolver<{{SUBJECT_TYPE}}>`; returns `SubjectId.of(user.id().toString())` |
| `security/services/VersionBumper.java` | **NEW** — `VersionBumper.bump(user)` increments the per-subject version on role change |
| `security/services/PasswordPreflight.java` | **NEW** — local blocklist + (optional) HIBP check; called from `SetupView` / role-add dialog |
| `security/bootstrap/JSentinelVersionInitListener.java` | **NEW** — `VaadinServiceInitListener` registering `JSentinelVersionEnforcerListener` on every UI |
| `views/admin/AdminRolesView.java` | `assignRole / revokeRole / deleteUser` now call `VersionBumper.bump(user)` after the mutation |
| `META-INF/services/com.svenruppert.jsentinel.session.JSentinelVersionStore` | **NEW** — `com.svenruppert.jsentinel.session.InMemoryJSentinelVersionStore` |
| `META-INF/services/com.svenruppert.jsentinel.authorization.api.SubjectIdResolver` | **NEW** — points at `SubjectIdResolverImpl` |
| `META-INF/services/com.vaadin.flow.server.VaadinServiceInitListener` | append `JSentinelVersionInitListener` |

## POM patch

```xml
<dependency>
    <groupId>com.svenruppert.jsentinel</groupId>
    <artifactId>jSentinel-crypto-bc</artifactId>
    <version>${jsentinel.version}</version>
</dependency>
<!-- only if {{HIBP_ENABLED}} = true -->
<dependency>
    <groupId>com.svenruppert.jsentinel</groupId>
    <artifactId>jSentinel-credentials-hibp</artifactId>
    <version>${jsentinel.version}</version>
</dependency>
```

## Rendering templates

| Template | Target |
|---|---|
| `pom-snippet.xml.tmpl` | merge into `pom.xml` (skip the HIBP block if `{{HIBP_ENABLED}}=false`) |
| `SubjectIdResolverImpl.java.tmpl` | `src/main/java/{{BASE_PATH}}/security/services/SubjectIdResolverImpl.java` |
| `VersionBumper.java.tmpl` | `src/main/java/{{BASE_PATH}}/security/services/VersionBumper.java` |
| `PasswordPreflight.java.tmpl` | `src/main/java/{{BASE_PATH}}/security/services/PasswordPreflight.java` |
| `JSentinelVersionInitListener.java.tmpl` | `src/main/java/{{BASE_PATH}}/security/bootstrap/JSentinelVersionInitListener.java` |
| `HardeningBootstrapExtension.java.tmpl` | `src/main/java/{{BASE_PATH}}/security/bootstrap/HardeningBootstrapExtension.java` |
| `services-BootstrapExtension.tmpl` | **APPEND** lines to `src/main/resources/META-INF/services/{{BASE_PACKAGE}}.security.bootstrap.BootstrapExtension` (deduplicated union with existing content) |
| `AdminRolesView.java.tmpl` | OVERWRITE existing |
| `services-JSentinelVersionStore.tmpl` | `src/main/resources/META-INF/services/com.svenruppert.jsentinel.session.JSentinelVersionStore` |
| `services-SubjectIdResolver.tmpl` | `src/main/resources/META-INF/services/com.svenruppert.jsentinel.authorization.api.SubjectIdResolver` |
| `services-VaadinServiceInitListener.tmpl` | append to existing file (one line) |

## Drift-detection flow

```
LoginView.checkCredentials → success
  → captureJSentinelVersionSnapshot() (framework)
    → reads InMemoryJSentinelVersionStore.current(key) for (tenant=DEFAULT, subject=userId)
    → stores snapshot in VaadinSession via VaadinJSentinelVersionContext

Admin → /admin/roles → revokes role from user X
  → AdminRolesView calls VersionBumper.bump(user X)
    → InMemoryJSentinelVersionStore.increment(key) → +1

User X navigates anywhere
  → JSentinelVersionEnforcerListener.beforeEnter
    → reads stored snapshot vs current(key)
    → snapshot != current → reroute to {{SUBJECT_PREFIX}}LoginView
    → audit SessionStale event
```

Result: user X is forced to re-authenticate on the next click. New
session captures fresh snapshot — they see the updated role set.

## Verification checklist

1. `./mvnw -pl <module> -am compile` — green.
2. `./mvnw -pl <module> jetty:run`.
3. Open `http://localhost:8080/login` — log in as admin (browser A).
4. In a private window (browser B), log in as `user`.
5. In browser A → `/admin/roles` → assign `ADMIN` to `user`.
6. In browser B → click around. **Expected:** next navigation
   reroutes B to `/login`. After re-login, the welcome page shows
   the ADMIN badge.
7. Check `/audit` — a `SessionStale` event appears for browser B.
8. (If HIBP enabled) try setting `Password1!` in any password field
   wired through `PasswordPreflight`. **Expected:** rejection
   message "this password is on a known-bad list".
9. Hash inspection: look at the rendered admin user's password hash
   on disk (persistence skill) or in memory. **Expected:** envelope
   starts with `$pwh$v=1$argon2id$…`, not `pbkdf2`.

## Pitfalls

### Drift detection requires BOTH SPIs

`JSentinelVersionStore` + `SubjectIdResolver` must BOTH be SPI-registered
or the snapshot-capture in `LoginView` silently no-ops. Symptom: roles
revoked mid-session don't kick anyone — the user just keeps going.
This skill registers both; do not delete either META-INF entry.

### `VersionBumper.bump(...)` must run *after* the directory mutation

`AdminRolesView` calls `assignRole` / `revokeRole` / `deleteUser` THEN
calls `VersionBumper.bump(user)`. Reversed order means: the bumper
reads the version, the mutation happens, but the bumped version is
based on the pre-mutation read — race-free because the increment is
atomic, but logically odd. Keep the order.

### HIBP needs network egress

The HIBP checker makes a `GET https://api.pwnedpasswords.com/range/<5-hex-prefix>`
on every check. Behind a corporate firewall this hangs without a
proxy. The template uses `Duration.ofSeconds(5)` as the request
timeout — failure to reach HIBP returns `Indeterminate`, and the
preflight treats `Indeterminate` as "allow" (CWE-359 fail-open by
design: a network outage should not block legitimate password
changes).

### Argon2id is intentionally slow

Argon2id with the modern profile defaults targets ~250 ms per hash.
Login throughput drops compared to PBKDF2-100k. Adjust via
`Argon2idDefaults` overrides if your hardware can't sustain it; do
not weaken below `iterations=2, memory=64 MiB`.

### Mixed-algorithm verification

Existing PBKDF2 hashes (created under `jsentinel-vaadin`) still
verify under `BouncyCastleHashingServices.modern()` — the registry
keeps all four providers (PBKDF2, bcrypt, scrypt, Argon2id) on the
verification path. The rehash engine upgrades them silently on the
next successful login. Production deployments with millions of stale
PBKDF2 hashes can budget the transition by enabling the modern
profile and waiting one login cycle per user.

### `Q_ADMIN` / `NERD` / `NOBODY` roles not bumped

`VersionBumper.bump(user)` knows nothing about which role changed —
it just increments the version. Any role mutation triggers the
drift, including roles whose absence would not affect the user's
access. That is intentional: an admin who revokes anything wants
that user out, full stop.

## What this skill deliberately does NOT cover

- **API keys / refresh tokens / rate limiting** — roadmap V00.74+;
  reaches beyond the V00.71 surface.
- **Tenant-scoped policies** — single-tenant only.
- **Persistent JSentinelVersionStore** — when combined with
  `jsentinel-vaadin-persistence`, swap the META-INF/services entry to point
  at `EclipseStoreJSentinelVersionStore` via a custom provider class
  (manual one-line edit; not templated).
- **Multi-factor authentication** — separate concern, not part of
  V00.71.
