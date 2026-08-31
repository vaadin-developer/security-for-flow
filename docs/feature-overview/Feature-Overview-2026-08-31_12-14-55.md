# jSentinel Feature Overview — Snapshot 2026-08-31 (post V00.80.00 — Operations & Forensics)

**Latest release:** V00.80.00 — *Operations & Forensics* — published to Maven Central
(deployment `90a07904-fe1d-4146-9f1b-c18424632446`, tag `v00.80.00` @ `4310e907`).
**47 Central artifacts** — 46 published library modules + the `jSentinel-parent` POM.
GitHub release: https://github.com/vaadin-developer/security-for-flow/releases/tag/v00.80.00

---

## New in V00.80.00 — Operations & Forensics

The first feature release after the V00.79.x hardening line. Three concept goals shipped
(goal 9 — operations & monitoring, goal 8 — event integrations, goal 7 — tamper-evident audit),
seven new reactor modules (reactor now 61), detail in `RELEASE-NOTES-00.80.00.md`
(ClickUp plan parent `86can9fvf`).

### Seven new modules

| Module | What it adds |
|---|---|
| `jSentinel-monitoring` | `JSentinelMetricsPublisher` SPI (never-throws, ServiceLoader-discovered, no-op default), the binding metric-name catalog (`security.eventbus.*`, `security.auth.*`, `security.session.*`, `security.audit.store.lag`), `MetricsEventBusListener` counter bridge, health layer (`JSentinelHealthIndicator`, `DiagnosticsHealthIndicator`, audit-store saturation). |
| `jSentinel-events-webhook` | `WebhookEventPublisher` — signed envelopes POSTed via JDK HttpClient (body = wire format), bounded queue + virtual-thread worker, exponential backoff + jitter, https-required (loopback exempt), bearer via supplier, CR/LF header guard. |
| `jSentinel-events-opentelemetry` | `OpenTelemetryEventPublisher` — envelope → OTel LogRecord via the Logs Bridge API (`jsentinel.*` attribute keys), api-only at compile scope, noop-safe; tests against the real in-memory SDK. |
| `jSentinel-events-siem` | `SiemEventExporter` + formatter SPI: CEF, LEEF 2.0, JSON-lines/NDJSON (metadata projection by default — no payload/signature). |
| `jSentinel-audit-integrity` | Tamper-evident hash chain: `AuditChainStore` SPI (append-only), `AuditChainEntryHasher` (length-prefixed framing, domain `jsentinel-audit-chain/v1`, golden-value pinned), `AuditChainAppender` (CAS, contention-safe), `AuditIntegrityVerifier` (sealed Valid/Empty/Broken), `SignedAuditBatch` + signer/verifier on the events key SPIs, NDJSON export/decode/verify with public material only, `AuditIntegrityListener` + `HashChainingAuditSink`. |
| `jSentinel-audit-integrity-testkit` | `AuditChainStoreContract` + tamper helpers for third-party store implementations. |
| `jSentinel-audit-integrity-persistence-eclipsestore` | Eclipse-Store-backed chain store (`openAt(Path)`, owner-only hardening, restart-proof — verified by contract + restart test). |

### Changes in existing modules

- **`jSentinel-events`**: bus-level envelope tap (`subscribeEnvelope(...)` / `SignedEnvelopePublisher`),
  self-observability events for all verification failures (`EventBusSelfObservabilityEvent` marker,
  `SelfObservabilityEvents.fromVerification(...)`), `DeadLetterRecorder`, in-tree publishers
  (`LoggingEventPublisher`, `EventStreamPublisher`, `JSentinelAlertPublisher` + alert sink SPI),
  strict-mode consume wiring (`ConsumeFailurePolicy.strict()/operationalDefaults()`,
  `ConsumeFailureHandler` — one event per failure, stable operator log codes), wire codec moved to
  `events.wire` with new secret-free `encodeMetadata(...)` (deprecated one-release delegator kept in
  `events-rest`, removal planned V00.81), `CanonicalJson` promoted to public.
- **`jSentinel-events-rest`**: `EventPublishService` gains one optional `ConsumeFailureHandler`
  parameter — HTTP mapping byte-identical.

## Quality gates (V00.80.00)

- Entry review: 11 findings (R00–R10), **all fixed in-cycle**; standards pass: 0 findings;
  exit review: SHIP (RF00+RF01 fixed in-cycle).
- No-mocks discipline throughout (real HttpServer, real OTel SDK, real Ed25519/ECDSA keys,
  real Eclipse Store with restart test).
- **PIT**: core 84 % (flat) · events 84 % · monitoring 79 % · webhook 62 % · otel 100 % ·
  siem 94 % · audit-integrity 78 % · audit-integrity-pe 77 %.
- Deploy lesson (fixed in `e65ca5fa`): the Central bundle script's module list is hardcoded —
  Central validates only what is IN the bundle, so a stale list validates green. The first
  deployment was dropped pre-publish; the shipped bundle stages 370 primary files across 47 modules.

---

## Backlog & Roadmap (versioned 2026-08-28)

All open work is versioned under ClickUp backlog parents:

| Version | Theme |
|---|---|
| **V00.81.00** | Session lifecycle & critical security backlog — session records never transition to EXPIRED (bug), TimeoutSessionPolicy STRICT diagnostic, T1/T2 audit findings (OAuth2 `state` login-CSRF, processor template audit, propagation host binding), wire-codec delegator removal, coverage finder pass. |
| **V00.81.10** | **Full rebranding jSentinel → jCustos**: packages → `eu.jsentinel.jcustos`, modules → `jCustos-*`, 172 class renames; project moves to `Workspaces/jSentinel/jCustos`. Feature-free cycle; prerequisite: `jsentinel.eu` + Central namespace verification. |
| V00.82.00 | Hardening rest (T3) & CSRF — first release under the jCustos name. |
| V00.83.00 | API stabilization (stable promotions), DX, PIT uplift sprint. |
| V00.84.00 | Credential hardening (pepper, blocklists, sliding-window rate limit, cluster brute force). |
| V00.85.00 | MFA & step-up epic (TOTP, WebAuthn/passkeys, device management, risk-based auth). |
| V00.86.00 | Identity completion (DPoP wiring, logout hardening, reactive strategy). |
| V00.87.00 | Compliance & operations (privacy/retention, backup/restore, supply chain). |
| TBD | JDBC/Redis persistence, Quarkus/JavaFX adapters, secured UI component family. |
