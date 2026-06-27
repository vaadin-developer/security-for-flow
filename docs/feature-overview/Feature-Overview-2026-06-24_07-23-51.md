# jSentinel Feature Overview — snapshot 2026-06-24_07-23-51

Taken right after the **V00.75.00 Security Event Bus** release to Maven Central
(deployment `78519f1a-9589-451b-b481-8032ae90ff0d`, published).

## New in V00.75.00 — Security Event Bus

Four new library modules (all on Central as
`com.svenruppert.jsentinel:*:00.75.00`):

| Module | What it gives you |
|---|---|
| `jSentinel-events` | SPI core: ~34 typed `JSentinelEvent` records, signed `SignedJSentinelEventEnvelope`, `EventBus` + publish/consume pipelines, seven SPIs (signature / payload-codec / key-management / replay / sequence / producer-policy / event+dead-letter store) with in-memory defaults, audit-subscriber + feature flag. No Vaadin / REST / Eclipse-Store dependency. |
| `jSentinel-events-rest` | REST/SSE bridge — `GET /api/events/stream` (Last-Event-ID resume + live tail) and permission-gated `POST /api/events`, over the JDK HttpServer. |
| `jSentinel-events-testkit` | `@Test default` contract suites for all seven SPIs + fixtures. |
| `jSentinel-events-persistence-eclipsestore` | JVM-restart-safe Eclipse-Store replay / sequence / envelope / dead-letter stores. |

### Capabilities

- **Integrity**: Ed25519 (default) + SHA256withECDSA fallback; the signature
  binds tenant / type / expiry / producer / sequence / key-id / payload-hash.
- **Replay protection**: mandatory, atomic `markSeen`; bounded-LRU in-memory +
  persistent Eclipse-Store variants.
- **Ordering**: monotone per-`(tenant, producer)` sequence with
  REJECT / DEAD_LETTER / ACCEPT_WITH_WARNING strategies.
- **Producer policy**: default-deny allow-list, per-tenant grants.
- **Differentiated verification**: sealed `JSentinelEventVerificationResult`
  (Valid / InvalidSignature / UnknownKey / KeyRevoked / Expired /
  PayloadHashMismatch / ReplayDetected / SequenceViolation / ProducerNotAllowed).
- **Audit as a consumer**: `AuditEventBusListener` maps bus events → core
  `AuditEvent`, sink failures isolated.
- **Distribution**: REST/SSE bridge for cross-process (REST service ⇄ Vaadin)
  delivery; channel secured by HTTPS / mTLS (the bus does not encrypt it).

5-minute setup: `docs/dx/5-minute-setup-eventbus.md`.

## Backlog / deferred

- **P014 — Eclipse-Serializer payload codec**: deferred. eclipse-store 4.1.0
  does not transitively expose the standalone `org.eclipse.serializer` facade;
  pinning risks a version clash with the embedded persistence binary. Revisit
  once aligned. Canonical-JSON is the shipped, mandatory default.
- **P033/P034 call-site wiring**: the audit-subscriber + feature-flagged
  publisher ship in `jSentinel-events`; inserting them into `jSentinel-core`'s
  session/token/rate-limit services (without a core→events cycle) is a
  host/follow-up concern, gated by `jsentinel.events.bus.enabled` (default off).
- **PIT re-measure** for `jSentinel-events-rest` and
  `jSentinel-events-persistence-eclipsestore` (HTTP / storage profiles).

## Roadmap

`Konzept-V00.80.00.md` builds on the bus: monitoring/metrics, SIEM + webhook
integrations, risk-based authentication, device + remember-me management,
MFA/step-up flows, tamper-evident audit as a separate listener, and streaming
transports (Kafka/NATS/RabbitMQ/Pulsar). `Konzept-V00.76.00.md` is the next
planned cycle. `security-javafx` stays gated on real JavaFX usage of
`jSentinel-standalone`.

## Released cycles to date

V00.70 → V00.71 → V00.72 → V00.73 (jSentinel rebrand) → V00.74.00 → V00.74.10
→ V00.74.20 → **V00.75.00 (Security Event Bus)**.
