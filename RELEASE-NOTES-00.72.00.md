# Release Notes — V00.72.00 (Developer Experience)

## What's new

V00.72.00 is the developer-experience version of `security-for-flow`. No
new security primitives — the focus is on lowering the integration
barrier built up over V00.60 – V00.71.

### Four DX building blocks

1. **Fluent Bootstrap API** — three adapter facades, each in its own
   module:
   - `VaadinSecurity.bootstrap()` in `security-dx-vaadin`
   - `RestSecurity.bootstrap()` in `security-dx-rest`
   - `StandaloneSecurity.bootstrap()` in `security-dx-standalone`

   Shared by all three: `CommonSecurityBootstrap<B>`, `SecurityRuntime`,
   `SecurityBootstrapMode` (`COMMUNITY_DEFAULTS` / `DEVELOPMENT` /
   `PRODUCTION` / `STRICT`), `SecurityBootstrapException`, all hosted in
   the `security-dx` module.

2. **`@SecurityAutoService`** — project-owned annotation + JDK-only
   annotation processor that generates `META-INF/services/<spi>` at
   compile time. No external `auto-service` library (Maven Enforcer ban
   on `com.google.auto.service:*` in both AutoService modules).

3. **`security-vaadin-starter`** — `SecuredUi.button / link / menuItem`
   declarative builders, `@SecureRoute` annotation with documented
   most-restrictive-wins precedence, and three profiles
   (`developmentDefaults`, `productionDefaults`, `strictDefaults`).

4. **Compile-time wrapper path made visible** — `security-processor`
   stays unchanged in behaviour. A new `WrapperIndexReader` consumes a
   processor-emitted index file at `META-INF/security-for-flow/generated-wrappers.idx`
   and surfaces each wrapper in `SecurityDiagnostics.inspect()` via the
   `SecurityProcessorReport`. The corresponding writer in
   `security-processor` is staged as V00.73 follow-up to keep the V00.72
   invariant "behaviour of `security-processor` unchanged".

### New modules

| Module | Purpose | Runtime deps |
|---|---|---:|
| `security-dx` | Common bootstrap contracts + diagnostics | `security-core` only |
| `security-dx-vaadin` | `VaadinSecurity.bootstrap()` facade | + `security-vaadin` |
| `security-dx-rest` | `RestSecurity.bootstrap()` facade | + `security-rest` |
| `security-dx-standalone` | `StandaloneSecurity.bootstrap()` facade | + `security-standalone` |
| `security-autoservice-annotations` | `@SecurityAutoService` (SOURCE retention) | – |
| `security-autoservice-processor` | Annotation processor | JDK API only |
| `security-vaadin-starter` | `SecuredUi`, `@SecureRoute`, profiles | + `security-dx-vaadin` |

### Diagnostics

- `SecurityDiagnostics.inspect()` — standalone, callable at any time,
  side-effect free.
- `DiagnosticContributor` SPI — adapter-DX modules contribute additional
  findings without polluting `security-dx` with adapter types. Three
  implementations: `VaadinDiagnosticContributor`,
  `RestDiagnosticContributor`, `StandaloneDiagnosticContributor`.
- Stable warning code namespace surfaces in both `SecurityRuntime.warnings()`
  (after `install()`) and `SecurityServiceReport.warnings()`
  (`SecurityDiagnostics.inspect()`); `STRICT` mode raises
  `SecurityBootstrapException` on any `Severity.ERROR` warning.

### Demo migrations

- `demo-vaadin`            — `AuthenticationService` + `AuthorizationService` via `@SecurityAutoService`
- `demo-vaadin-rest-client` — same
- `demo-rest`              — `@SecurityAutoService` where applicable (demo-rest does not own AuthN/AuthZ implementations)
- `demo-standalone`        — `AuthenticationService` + `AuthorizationService` via `@SecurityAutoService`

All four demos build & test green; the migrated SPI service files were
deleted in favour of the processor-generated ones under
`target/classes/META-INF/services/`.

## Compatibility

V00.72 is fully additive. Existing manual `META-INF/services` files,
direct `SecurityServiceResolver` calls and hand-written bootstrap
classes from V00.60 – V00.71 continue to work unchanged. The new
adapter facades and the AutoService toolchain are opt-in.

## Acceptance summary

- Reactor: 19 modules build clean.
- Tests: full reactor green; new DX modules contribute >50 unit tests.
- `security-core` runtime dependencies: unchanged from V00.71.
- All public DX types carry `@ExperimentalSecurityApi` until V00.73.

## Known limitations

- `SecuredUi.requiresPolicy(...)` throws `UnsupportedOperationException`
  at `build()`. Use `@SecureRoute(policy = ...)` on the route class instead.
- The wrapper-index writer in `security-processor` is V00.73; until
  then the reader surfaces no entries unless a consumer ships a manual
  index file.
- See "Mutation coverage (V00.72)" below for the first-pass PIT
  baseline of the DX modules.

## Mutation coverage (V00.72)

First PIT pass over the new DX modules. No coverage threshold is
enforced; the goal is to record the starting point.

| Module | Line coverage | Mutation coverage | Note |
|---|---|---|---|
| `security-dx` | 80% (201/250) | 49% (47/96) | DiagnosticContributor and WrapperIndexReader edge cases dominate the surviving mutants |
| `security-dx-vaadin` | 87% (46/53) | 61% (14/23) | small surface; one DiagnosticContributor + the Vaadin bootstrap impl |
| `security-dx-rest` | 71% (52/73) | 54% (15/28) | default decision mapper / error-body strategy branches |
| `security-dx-standalone` | 61% (30/49) | 43% (9/21) | smallest module; primarily the standalone bootstrap impl |
| `security-vaadin-starter` | 72% (99/138) | 66% (49/74) | SecuredUi builder validation paths well covered; the SecureRouteEvaluator combine() ranks contribute surviving mutants |
| `security-autoservice-processor` | 70% (87/124) | 52% (34/65) | validation branches well covered; file-write edge cases (multi-round merging, marker preservation) dominate the surviving mutants |

## Roadmap

- V00.73 — promote `@ExperimentalSecurityApi` DX types to stable; add
  the wrapper-index writer in `security-processor`; finish the
  PolicyRegistry integration for `SecuredUi.requiresPolicy`.
- V00.75 — Security Event Bus (signed envelopes, REST/SSE bridge).
- V00.80 — High-security profile: MFA, OIDC/OAuth2, hardening.
