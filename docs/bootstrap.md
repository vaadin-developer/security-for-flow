# Bootstrap mechanism — first administrator setup

A fresh installation does not ship with any administrator account. The
**bootstrap mechanism** authorizes the **one-time** creation of the very
first administrator while the system is still uninitialized. Once an
administrator exists, the mechanism turns itself off.

**The bootstrap token is not the administrator password.** It only
authorizes the initial setup. The administrator chooses a real password
during setup; that password is hashed and stored.

---

## Modes

| Mode | When the token is generated | Where the token lives | Survives restart? |
|---|---|---|---|
| `PERSISTENT_FILE` | Once, until setup completes | File on disk (POSIX `0600`) | Yes |
| `TRANSIENT_CONSOLE` | On every server start while uninitialized | In memory only | No — a new token is generated next start |
| `DISABLED` | Never | n/a | n/a |

Configuration (system properties or environment variables):

```text
security.bootstrap.mode        DISABLED (default) | TRANSIENT_CONSOLE | PERSISTENT_FILE
security.bootstrap.token.file  ./data/bootstrap.token    (PERSISTENT_FILE only)
```

---

## Library API (`security-core` / `com.svenruppert.vaadin.security.bootstrap`)

| Type | Purpose |
|---|---|
| `BootstrapMode`, `BootstrapConfiguration` | Configuration |
| `BootstrapToken`, `BootstrapTokenGenerator` | Token model + `SecureRandom` generator (XXXX-XXXX-XXXX-XXXX-XXXX, ~100 bits, no `O 0 I 1`) |
| `BootstrapTokenStore`, `InMemoryBootstrapTokenStore`, `FileBootstrapTokenStore` | Token persistence |
| `BootstrapTokenOutput`, `ConsoleBootstrapTokenOutput`, `FileBootstrapTokenOutput` | Operator-facing banner emitter |
| `BootstrapStateService` | Tells whether bootstrap is required |
| `BootstrapStartup` | One-shot init on server boot |
| `AdministratorAccountStore`, `NewAdministrator` | App-side seam |
| `PasswordHasher`, `Pbkdf2PasswordHasher` | Password hashing (PBKDF2-HMAC-SHA256, 120 000 iterations) |
| `PasswordPolicy`, `MinimumLengthPasswordPolicy` | Password validation |
| `CreateInitialAdminCommand`, `InitialAdminCreationResult` | Service contract |
| `InitialAdminBootstrapService` | Orchestrator: validate → check race → hash → create → invalidate token, all under a single `ReentrantLock` |

The library has no Vaadin, Servlet, or REST-framework dependencies.

---

## Three setup paths

### 1. REST (`demo-rest`)

Endpoints:

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/bootstrap/status` | `{ "bootstrapRequired": true, "mode": "..." }` — never returns the token |
| `POST` | `/api/bootstrap/admin` | body: `{ bootstrapToken, username, password, displayName?, email? }` |

Possible response codes: `201 created`, `400 bad_request` / `password_policy_violation` / `invalid_username`, `403 invalid_bootstrap_token`, `409 system_already_initialized`, `500 internal_error`. Bodies are short and generic — no token, no stack traces, no class names.

Run:

```bash
# transient — token printed to stdout
mvn -pl :demo-rest exec:java -Dsecurity.bootstrap.mode=TRANSIENT_CONSOLE

# persistent — token written to file
mvn -pl :demo-rest exec:java \
    -Dsecurity.bootstrap.mode=PERSISTENT_FILE \
    -Dsecurity.bootstrap.token.file=./data/bootstrap.token
```

### 2. CLI (`demo-rest`)

```text
> init-admin
Bootstrap token: ********
Admin username [admin]: admin
New admin password: ********
Repeat password: ********
Display name (optional):
Email (optional):
Administrator created. You can now log in with the chosen password.
```

The CLI calls the same `/api/bootstrap/*` endpoints. Passwords are read via
`Console.readPassword()` when a TTY is available, otherwise fall back to
visible input (e.g. when piped).

### 3. Vaadin `/setup` (`demo-vaadin`)

The Vaadin demo defaults to `TRANSIENT_CONSOLE` so it works out-of-the-box:

```bash
# Default — transient token printed to the server console
cd demo-vaadin && mvn jetty:run

# Persistent token file
mvn -pl :demo-vaadin jetty:run \
    -Dsecurity.bootstrap.mode=PERSISTENT_FILE \
    -Dsecurity.bootstrap.token.file=./data/bootstrap.token

# Disable the bootstrap mechanism entirely
mvn -pl :demo-vaadin jetty:run -Dsecurity.bootstrap.mode=DISABLED
```

- `BootstrapServiceInitListener` (`VaadinServiceInitListener` SPI) eagerly
  initializes the bootstrap on Vaadin service start, so the token banner
  appears in the console **immediately** — without having to navigate to
  any view first.
- `/setup` is shown only while the system is uninitialized.
- `/login` redirects to `/setup` until the first administrator exists.
- After setup, the view forwards to `/login` and is no longer reachable.
- The Vaadin form calls `InitialAdminBootstrapService` directly in-JVM —
  the same authoritative service the REST endpoint uses. The UI never
  decides whether bootstrap is allowed; the service does.

If you want to clear the pre-populated `Herr Admin` to play through the
flow on every restart, comment out the `addUser("admin", ...)` line in
`UserStorage` (or call `UserStorage.enableBootstrapMode()` programmatically
— `BootstrapWiring` already does this when the mode is non-`DISABLED`).

---

## Security rules

- The token is **never** written to the application logger.
- The token is **never** echoed in HTTP responses.
- The token is **never** included in Vaadin notifications.
- In persistent mode, only the **path** to the token file is logged.
- Token files use `rw-------` (0600) on POSIX file systems.
- Passwords are passed as `char[]` and cleared after hashing.
- Passwords are stored as PBKDF2-HMAC-SHA256 hashes, never plaintext.
- The `check-admin-exists / create / invalidate-token` sequence runs under a
  `ReentrantLock`, so two parallel setup requests cannot both create an
  administrator. There is a dedicated parallelism test for this.
- After successful setup the token is invalidated. Persistent mode also
  deletes the token file. If deletion fails, the setup still succeeds —
  the failure is not surfaced to the client.

---

## Operator hygiene

- The token file must **not** be committed to a repository.
- The token file must **not** be shared on chat or email.
- After setup, delete the token file even if the server already removed it.
- In transient mode, the printed token banner must not be archived in CI logs.
- For production, consider replacing `MinimumLengthPasswordPolicy(8)` with a
  stronger application policy.
- Production deployments should also pair the bootstrap mechanism with the
  audit, brute-force, and session policies described in
  `Konzept-V00.60.00.md`.
