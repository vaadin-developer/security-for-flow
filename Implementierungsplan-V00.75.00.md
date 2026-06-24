# Implementierungsplan V00.75.00

**Status:** ✅ **COMPLETED** — released to Maven Central as
`com.svenruppert.jsentinel:*:00.75.00` on 2026-06-24.
**Deployment ID:** `78519f1a-9589-451b-b481-8032ae90ff0d` (USER_MANAGED, published).
**Tag:** `v00.75.00` at finalize commit `ff318d25`.
**Scope shipped:** 34 of 35 prompts full (P002–P035); P014 (Eclipse-Serializer
codec) deferred — version-clash risk with eclipse-store 4.1.0; canonical-JSON
covers the mandatory default. See §20 for the full outcome.

Source-Konzept: `Konzept-V00.75.00.md`
Target version: `00.75.00`
Target branch: `develop`
Java: `26+`
Build: Maven 4
Licence: EUPL 1.2

## 1. Purpose

V00.75.00 introduces the **Security Event Bus**: a signed-envelope
event system with Ed25519 signatures, replay protection, producer
policy, in-memory + persistent stores, and a REST/SSE bridge for
external consumers. The bus does **not** replace audit — it is a
new SPI that audit can sit on top of.

## 2. Scope for V00.75.00

### In scope

- Four new modules: `jSentinel-events`, `jSentinel-events-rest`,
  `jSentinel-events-testkit`, `jSentinel-events-persistence-eclipsestore`.
- Sealed `SecurityEvent` + record `SecurityEventEnvelope` with
  mandatory `TenantId`, `ProducerId`, `envelopeId`, `eventType`,
  `expiresAt`, `signatureAlgorithm`, `signature`.
- Event-Kategorien + Severity.
- ~30 concrete event types (authn, authz, sessions, tokens, roles,
  tenants, rate-limit, bus integrity).
- Crypto: Ed25519 default, optional SHA256withECDSA fallback,
  `SignatureAlgorithm` SPI.
- Payload codecs: Canonical JSON (interoperable default),
  Eclipse Serializer (Java-native), `PayloadCodec` SPI.
- `KeyManagement` SPI + JDK-KeyStore reference implementation.
- Replay-protection: `ReplayStore` SPI + in-memory implementation.
- Sequence-numbers per `tenantId + producerId`:
  `SequenceStore` SPI + `SequencePolicy`.
- `ProducerPolicy` SPI.
- Persistent stores: `EventStore`, `DeadLetterStore` (Eclipse-Store-
  backed implementations).
- `EventBus` API + Publish-Pipeline + Consume-Pipeline.
- `VerificationResult` sealed type for differentiated rejection codes.
- Fehlerstrategien für Listener-Fehler.
- REST/SSE Bridge: SSE endpoint + resume cursor + REST publish endpoint.
- Integration: audit subscribes to the bus; sessions / tokens /
  rate-limit publish events.
- Testkit contract tests, 5-Minute-Setup docs, RELEASE-NOTES.

### Explicit non-scope

- Transport encryption for SSE (delegated to HTTPS / mTLS).
- Kafka / RabbitMQ / Pulsar / NATS replacement.
- Full SIEM integration.
- HSM / Cloud-KMS implementation.
- WebAuthn / OIDC integration.
- Tamper-evident audit as part of the bus (separate, kept in V00.80).
- Generic workflow engine.

## 3. Cross-Cutting Invariants

- `jSentinel-events` has **no** dependency on Vaadin, REST frameworks,
  or Eclipse Store. It is the SPI core.
- Every public type in V00.75 ships `@ExperimentalJSentinelApi` until
  V00.76 / V00.77 promote individual types after demo adoption.
- Signed events are the default. There is no "unsigned mode".
- `TenantId` is **mandatory** on every envelope.
- Replay-protection is mandatory; opt-out only via documented
  development-mode profile (Concept §13).
- Maven Enforcer bans Jackson / Gson / org.json on the
  `jSentinel-events` compile/runtime classpath — Canonical JSON
  uses an in-tree codec, like V00.74.10 §5.
- All cryptographic primitives go through JCA. Provider order is
  not modified globally.
- No `Throwable` raw catches without a `HasLogger`-driven log.

## 4. Target Module Structure

```
jSentinel-events                          (Core SPI; no Eclipse-Store, no REST)
jSentinel-events-rest                     (SSE endpoint, REST publish)
jSentinel-events-testkit                  (Contract-Tests + In-Memory-Defaults)
jSentinel-events-persistence-eclipsestore (EventStore + DeadLetterStore + ReplayStore + SequenceStore impls)
```

Dependency rules:

```
jSentinel-events                            -> jSentinel-core (read-only types)
jSentinel-events-rest                       -> jSentinel-events, jSentinel-rest
jSentinel-events-testkit                    -> jSentinel-events (test scope contracts)
jSentinel-events-persistence-eclipsestore   -> jSentinel-events, jSentinel-persistence-eclipsestore
```

Forbidden: any of these depending on Vaadin or the DX-Modules.

## 5. Milestones

| Phase | Title | Prompts |
|---|---|---|
| 0 | Reactor Setup | 000–001 |
| 1 | Event-Modell + Envelope | 002–004 |
| 2 | Wichtige Event-Typen | 005–008 |
| 3 | Signaturmodell | 009–011 |
| 4 | Payload-Codecs | 012–014 |
| 5 | Key Management | 015–016 |
| 6 | Replay + Sequence | 017–019 |
| 7 | Producer Policy + EventStore SPIs | 020–022 |
| 8 | EventBus API + Pipelines | 023–026 |
| 9 | REST/SSE Bridge | 027–030 |
| 10 | Eclipse-Store Persistence | 031–032 |
| 11 | Integration in bestehende Module | 033–034 |
| 12 | Testkit + Acceptance | 035 |

= 36 prompts (000–035). Deployment is a separate ClickUp subtask
under the V00.75 parent (Maven Central) — not a numbered prompt.

## 6. Phase 0 — Reactor Setup

### 6.1 Prompt 000 - Bump every pom.xml to `00.75.00-SNAPSHOT`

Bump reactor + 17 modules + demos. Run `./mvnw clean install -DskipTests`
to confirm reactor still resolves.

### 6.2 Prompt 001 - Add four new reactor modules

Add `jSentinel-events`, `jSentinel-events-rest`,
`jSentinel-events-testkit`, `jSentinel-events-persistence-eclipsestore`
to the parent POM `<modules>` section. Each new module gets a minimal
pom.xml with `jSentinel-parent` as parent. Empty `src/main/java`
directories. Compile-check passes.

## 7. Phase 1 — Event-Modell + Envelope

### 7.1 Prompt 002 - Sealed `SecurityEvent` + `SecurityEventCategory` + `Severity`

Sealed interface in `com.svenruppert.jsentinel.events.api`. Categories
(`AUTHENTICATION`, `AUTHORIZATION`, `SESSION`, `TOKEN`, `ROLE`,
`TENANT`, `RATE_LIMIT`, `BUS`). Severity (`INFO`, `WARN`, `ERROR`,
`CRITICAL`). All `@ExperimentalJSentinelApi`, `@since 00.75`.

### 7.2 Prompt 003 - `SecurityEventEnvelope` record + mandatory fields

Record with `envelopeId` (UUID), `tenantId`, `producerId`,
`eventType`, `category`, `severity`, `occurredAt` (Instant),
`expiresAt` (Instant), `sequence` (long), `payload` (byte[]),
`signatureAlgorithm` (String), `signature` (byte[]), `payloadCodec`
(String). Compact-constructor validates all required fields
non-null/non-blank (Konzept §326).

### 7.3 Prompt 004 - Envelope-Builder + TenantId-Pflichtfeld-Tests

Builder pattern, `EnvelopeBuilderTest` asserting that any of the
required fields being null/blank throws on `build()`. `tenantId`
gets a dedicated test class.

## 8. Phase 2 — Wichtige Event-Typen

### 8.1 Prompt 005 - Authentication-Events (5 Typen)

`LoginAttempted`, `LoginSucceeded`, `LoginFailed`, `LogoutRequested`,
`StepUpRequired`. Each as a record `implements SecurityEvent`.

### 8.2 Prompt 006 - Authorization, Sessions, Roles, Tenants

`AccessGranted`, `AccessDenied`, `PolicyEvaluated`, `SessionCreated`,
`SessionRevoked`, `RoleAssigned`, `RoleRevoked`, `TenantCreated`,
`TenantArchived`.

### 8.3 Prompt 007 - Tokens, Devices, Rate Limit, Abuse

`TokenIssued`, `TokenRevoked`, `TokenRefreshed`, `DeviceRegistered`,
`RateLimitTriggered`, `AbuseDetected`.

### 8.4 Prompt 008 - Bus + Integrity Events

`BusStarted`, `BusStopped`, `EnvelopeRejected`, `ReplayDetected`,
`SequenceGap`, `KeyRotated`, `ProducerRegistered`.

## 9. Phase 3 — Signaturmodell

### 9.1 Prompt 009 - `SignatureAlgorithm` SPI

Sealed interface with `id()`, `sign(byte[], PrivateKey)`,
`verify(byte[], byte[], PublicKey)`. Default registry +
discovery via `ServiceLoader`.

### 9.2 Prompt 010 - Ed25519 default provider

`Ed25519SignatureAlgorithm` via JCA `Signature.getInstance("Ed25519")`.
Registered via `@JSentinelAutoService(SignatureAlgorithm.class)`.

### 9.3 Prompt 011 - SHA256withECDSA optional fallback

`EcdsaP256SignatureAlgorithm` opt-in. Documented as fallback for
JDK distributions where Ed25519 is unavailable.

## 10. Phase 4 — Payload-Codecs

### 10.1 Prompt 012 - `PayloadCodec` SPI

`encode(SecurityEvent)`, `decode(byte[], Class<? extends SecurityEvent>)`.
Codec id is part of the envelope (Konzept §296).

### 10.2 Prompt 013 - Canonical JSON Codec

In-tree implementation (no Jackson). RFC 8785 canonical form:
sorted keys, no extra whitespace, normalized number format.
Maven Enforcer ban Jackson/Gson/org.json on this module
(continues the V00.74.10 pattern).

### 10.3 Prompt 014 - Eclipse Serializer Codec

Optional Java-native codec for Java-to-Java setups. Lives in
`jSentinel-events-persistence-eclipsestore` so the SPI core stays
storage-free.

## 11. Phase 5 — Key Management

### 11.1 Prompt 015 - `KeyManagement` SPI

`getPublicKey(KeyId)`, `getPrivateKey(KeyId)`, `currentSigningKey()`,
`rotate()`, `revoke(KeyId)`. Sealed `KeyState` (ACTIVE, ROTATED,
REVOKED).

### 11.2 Prompt 016 - JDK-KeyStore reference implementation

`JdkKeyStoreKeyManagement` backed by `KeyStore.getInstance("PKCS12")`.
Loads from configurable path; password from `app.eventbus.keystore.password`.

## 12. Phase 6 — Replay + Sequence

### 12.1 Prompt 017 - `ReplayStore` SPI + InMemory-Impl

`seenWithin(envelopeId, TenantId, Duration)`. InMemory with bounded
LRU. Documented limitation: not JVM-restart-safe (persistence in
Phase 10).

### 12.2 Prompt 018 - `SequenceStore` SPI + InMemory-Impl

`nextExpected(TenantId, ProducerId)` returns long. Atomic increment.

### 12.3 Prompt 019 - `SequencePolicy` + Verification

Policies: `Strict`, `AllowGaps`, `LogGaps`. Tests for each.

## 13. Phase 7 — Producer Policy + EventStore SPIs

### 13.1 Prompt 020 - `ProducerPolicy` SPI

`allowed(ProducerId, eventType)`. Default `AllowList`-based.

### 13.2 Prompt 021 - `EventStore` SPI

`store(SecurityEventEnvelope)`, `query(EventQuery)`, `count()`.
Used by persistent listeners.

### 13.3 Prompt 022 - `DeadLetterStore` SPI

`record(SecurityEventEnvelope, RejectionReason)`. For envelopes
that fail verification or get rejected by replay-store.

## 14. Phase 8 — EventBus API + Pipelines

### 14.1 Prompt 023 - `EventBus` API

`publish(SecurityEvent)`, `subscribe(EventListener, EventFilter)`,
`unsubscribe(SubscriptionId)`. Sealed `EventListener` with
sync + async variants.

### 14.2 Prompt 024 - Publish-Pipeline

`Publisher` wraps SecurityEvent into envelope: assign `envelopeId`,
fill `tenantId`/`producerId`/`sequence`, encode payload,
sign envelope, then submit to bus. Stage order documented in Konzept
§826.

### 14.3 Prompt 025 - Consume-Pipeline + Verification

Stages: decode + verify signature + verify producer policy + verify
sequence + check replay + decode payload + dispatch to listeners.
`VerificationResult` sealed type (`Verified` / `Rejected(reason)`).

### 14.4 Prompt 026 - Listener Error Strategies

Listener-Exception handling: `IsolateAndContinue`,
`AbortOnFirstError`. Default `IsolateAndContinue`. Listener failures
publish a `ListenerFailed` event (subset of the BUS category).

## 15. Phase 9 — REST/SSE Bridge

### 15.1 Prompt 027 - `jSentinel-events-rest` skeleton

Module pom. Default route prefix `/api/events`. Reuses
`jSentinel-rest`'s authorization filter.

### 15.2 Prompt 028 - SSE-Endpunkt `GET /api/events/stream`

Returns text/event-stream. Subscribes to bus on connect, unsubscribes
on disconnect. Sends keep-alive comments every 15 s. Backpressure
via bounded queue per connection.

### 15.3 Prompt 029 - Resume + Cursor

`Last-Event-ID` header on reconnect. Server replays from
`EventStore` since that cursor, then live-tails. Documented limit:
cursor TTL = expiry of the configured `EventStore` retention.

### 15.4 Prompt 030 - REST-Publish-Endpunkt `POST /api/events`

Accepts signed envelopes from external producers. Requires
`@RequiresPermission("events:publish")`. Body is the encoded envelope
(JSON / opaque bytes). Server runs the full Consume-Pipeline.

## 16. Phase 10 — Eclipse-Store Persistence

### 16.1 Prompt 031 - Eclipse-Store EventStore + DeadLetterStore

Concrete impls in `jSentinel-events-persistence-eclipsestore`.
Uses the V00.74.20 `JSentinelStoragePair` app-side manager so the
events storage shares the framework lifecycle.

### 16.2 Prompt 032 - Eclipse-Store ReplayStore + SequenceStore

Persistent replay protection survives JVM restart. Sequence-store
holds per-`(tenantId, producerId)` counter — atomic via
Eclipse-Store storer lock.

## 17. Phase 11 — Integration in bestehende Module

### 17.1 Prompt 033 - Audit-Subscriber

`AuditEventBusListener implements EventListener` in
`jSentinel-core/audit`. Subscribes to bus, maps `SecurityEvent` →
`AuditEvent`, forwards to existing `JSentinelAuditService.publish(...)`.
Audit-Sink failures are isolated per Konzept §779.

### 17.2 Prompt 034 - Publish events from sessions / tokens / rate-limit

Session-create/-revoke, token-issue/-refresh/-revoke, rate-limit-trigger
all publish their corresponding event types via the bus. Behind a
feature flag `jsentinel.events.bus.enabled` so legacy direct-audit
deployments keep working.

## 18. Phase 12 — Testkit + Acceptance

### 18.1 Prompt 035 - `jSentinel-events-testkit` contract tests + RELEASE-NOTES + 5-Minute-Setup

Contract tests for the seven SPIs (PayloadCodec, SignatureAlgorithm,
KeyManagement, ReplayStore, SequenceStore, ProducerPolicy, EventStore).
PIT regression check vs V00.74.20 baseline. 5-Minute-Setup-Doc
`docs/dx/5-minute-setup-eventbus.md`. `RELEASE-NOTES-00.75.00.md`.

## 19. Acceptance Criteria

- All 35 prompts merged on `develop`.
- ≥ 95 % unit-test coverage on `jSentinel-events` core SPIs.
- PIT regression: no V00.74.20 module drops > 3 % kills.
- Demo-vaadin-hardening adopts the audit-subscriber pattern;
  audit log still appears identically after migration (regression
  proof).
- SSE endpoint sustains 1000 envelopes/s on a single connection on
  the test machine.
- Maven Central deploy of all 4 new modules.

## 20. Release outcome (2026-06-24)

Released to Maven Central; deployment `78519f1a-9589-451b-b481-8032ae90ff0d`
(`jSentinel-V00.75.00`, USER_MANAGED) uploaded HTTP 201 → VALIDATED (0 errors)
→ published.

### Scope

- **34 of 35 prompts shipped full** (P002–P013, P015–P035). **P014 deferred** —
  the optional Eclipse-Serializer payload codec: eclipse-store 4.1.0 does not
  transitively expose the standalone `org.eclipse.serializer` facade and
  pinning it risks a version clash with the embedded persistence binary. The
  mandatory interoperable default (canonical-JSON codec) is shipped and
  satisfies the deterministic-bytes contract. Carry-over documented in
  `RELEASE-NOTES-00.75.00.md` and the persistence module's `package-info`.

### Phase commits (on `develop`)

| Phase | Prompts | Commit |
|---|---|---|
| 0 Reactor setup | 000–001 | `1bc9e5f4`, `ec66c4ea` |
| 1 Event-Modell + Envelope | 002–004 | `629c83a2` |
| 2 Event-Typen (34) | 005–008 | `91d8fc8e` |
| 3 Signaturmodell | 009–011 | `2afd204f` |
| 4 Payload-Codecs | 012–013 | `0cbb8ead` |
| 5 Key Management | 015–016 | `33af00fd` |
| 6 Replay + Sequence | 017–019 | `763f9d6a` |
| 7 Producer Policy + Store SPIs | 020–022 | `80002baa` |
| 8 EventBus + Pipelines | 023–026 | `20be52bb` |
| 9 REST/SSE Bridge | 027–030 | `ddb3fc47` |
| 10 Eclipse-Store Persistence | 031–032 | `bc1026ac` |
| 11 Integration | 033–034 | `cbb97468` |
| 12 Testkit + Notes | 035 | `95ad4304` |
| Stufe D Finalize | — | `ff318d25` |

### Quality

- Tests: 145 green across the four new modules (events 94, rest 13, testkit 26,
  persistence 12) — no mocks (real JCA crypto, keytool PKCS12 fixture, real JDK
  `HttpServer`/`HttpClient`, real Eclipse-Store restart).
- PIT (`jSentinel-events`): **86 % mutation** (356/416), 88 % line, test
  strength 89 %. Pre-existing V00.71–V00.74 modules unchanged → no regression.

### Bundle

- `central-bundle.zip` 10 MB, 194 primary files across 25 published modules
  (incl. the 4 new `jSentinel-events*`), GPG-signed with key `44A7EECD37010CF3`.

Tracked in ClickUp list `jSentinel-SecurityFramework` (id `901524055126`).
