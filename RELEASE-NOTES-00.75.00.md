# jSentinel V00.75.00 — Security Event Bus

V00.75.00 introduces the **Security Event Bus**: a signed-envelope event system
with Ed25519 signatures, replay protection, per-producer/tenant sequencing,
producer policy, persistent stores and a REST/SSE bridge for external
consumers. The bus does **not** replace audit — audit becomes a *consumer* that
sits on top of the bus.

## Themes

1. **Typed, signed security events.** ~34 concrete `JSentinelEvent` record
   types across authentication, authorization, session, role, token, device,
   rate-limit and bus-integrity categories, each wrapped into a signed
   `SignedJSentinelEventEnvelope`.
2. **Integrity end-to-end.** The signature binds the security-relevant envelope
   metadata (tenant, type, expiry, producer, sequence, key id, payload hash),
   so nothing can be tampered without invalidating it. Verification yields a
   differentiated, sealed result.
3. **Replay + ordering guarantees.** Mandatory replay protection and monotone
   per-`(tenant, producer)` sequencing with a configurable violation strategy.
4. **Distribution.** A REST/SSE bridge lets a Vaadin app observe a REST
   service's security events in near real time, with `Last-Event-ID` resume.
5. **Pluggability.** Seven SPIs (signature, payload codec, key management,
   replay, sequence, producer policy, event/dead-letter store) with in-memory
   defaults and Eclipse-Store-backed, restart-safe persistence.

## Statement of additivity

V00.75 is **purely additive**. It ships four new reactor modules and changes
**no** existing source, so every V00.71/V00.72/V00.73/V00.74 module keeps its
behaviour and mutation coverage by construction. All new public types carry
`@ExperimentalJSentinelApi`; stable-API promotion is staged for a later release
after demo adoption.

## Headline change — a signed event in four lines

```java
var bus = new DefaultJSentinelEventBus(publishPipeline);     // see the 5-min setup
bus.subscribe(SessionRevokedEvent.class, e -> invalidate(e.sessionId()));
bus.publish(new LoginSucceededEvent(meta, "password"));      // signed + dispatched
// remote consumer:
JSentinelEventVerificationResult r = consumePipeline.verify(envelope, Instant.now());
```

## What's new in detail

### New modules

| Module | Purpose |
|---|---|
| `jSentinel-events` | SPI core: event model + signed envelope, signature SPI (Ed25519 + ECDSA fallback), payload codec (canonical JSON), key management, replay/sequence/producer/store SPIs, EventBus + publish/consume pipelines, audit-subscriber + feature flag. **No** Vaadin / REST / Eclipse-Store dependency. |
| `jSentinel-events-rest` | REST/SSE bridge: `GET /api/events/stream` (replay-from-cursor + live tail), `POST /api/events` (permission-gated publish), envelope wire codec. |
| `jSentinel-events-testkit` | `@Test default` contract suites for all seven SPIs + shared fixtures. |
| `jSentinel-events-persistence-eclipsestore` | JVM-restart-safe Eclipse-Store-backed replay / sequence / envelope / dead-letter stores. |

### Core surface (jSentinel-events)

- **Event model** — `JSentinelEvent` (open interface), `EventMetadata`,
  `JSentinelEventCategory` (12), `JSentinelEventSeverity` (6), and ~34 concrete
  event records.
- **Envelope** — `SignedJSentinelEventEnvelope` (19 mandatory/optional fields,
  defensive `byte[]` copies, value-semantic equals) + builder.
- **Signature** — `SignatureAlgorithm` SPI, `Ed25519SignatureAlgorithm`
  (default), `EcdsaP256SignatureAlgorithm` (fallback), `SignatureAlgorithms`
  registry (ServiceLoader discovery).
- **Payload codec** — `CanonicalJSentinelEventPayload` + `JSentinelEventCanonicalizer`
  + `PayloadCodec` SPI + in-tree `CanonicalJsonPayloadCodec` (Jackson/Gson/
  org.json Maven-Enforcer-banned).
- **Keys** — signer/verifier SPIs + `KeyStatus`, `InMemoryKeyManagement`,
  `JdkKeyStoreKeyManagement` (PKCS12).
- **Replay / sequence** — `JSentinelEventReplayStore` (atomic) + bounded-LRU
  in-memory impl; `JSentinelEventSequenceStore` + validator +
  `SequenceViolationStrategy`.
- **Producer policy + stores** — `JSentinelEventProducerPolicy` +
  `AllowListProducerPolicy`; `JSentinelEventEnvelopeStore` (cursor-based) +
  `JSentinelEventDeadLetterStore` + in-memory impls.
- **Bus** — `JSentinelEventBus` + `DefaultJSentinelEventBus`, `PublishPipeline`,
  `ConsumePipeline`, sealed `JSentinelEventVerificationResult`,
  `ListenerErrorStrategy`.
- **Integration** — `AuditEventBusListener` + `AuditEventMapper` (audit as a
  consumer), `JSentinelEventBusFeatureFlag` + `FeatureFlaggedEventPublisher`.

## What V00.75 does NOT do

- No transport encryption for SSE — delegated to HTTPS / mTLS.
- No Kafka / RabbitMQ / Pulsar / NATS replacement.
- No full SIEM integration; no HSM / Cloud-KMS; no WebAuthn / OIDC.
- No tamper-evident audit as part of the bus (kept for V00.80).

## Carve-outs / deferrals (honest scope)

- **P014 — Eclipse-Serializer payload codec: deferred.** Eclipse-Store 4.1.0
  does not transitively expose the standalone `org.eclipse.serializer` facade,
  and pinning it risks a version clash with the embedded persistence binary.
  The required interoperable default — the canonical-JSON codec — is shipped and
  satisfies the deterministic-bytes contract. Revisit once the serializer
  dependency is aligned.
- **P033/P034 placement.** The audit-subscriber and the feature-flagged
  publisher live in `jSentinel-events`, not `jSentinel-core`, because the module
  dependency runs events → core only (core must not depend on events). A host
  wires them into its core service code paths; concrete call-site insertion is a
  host/follow-up concern, gated by `jsentinel.events.bus.enabled` (default off).
- **Naming.** The release follows the authoritative concept's `JSentinel*`
  surface (and the V00.73 rebrand rule), not the draft plan's shorthand
  `SecurityEvent`.

## Mutation coverage (V00.75)

PIT was run on the new SPI-core module; the three other new modules carry
HTTP/persistence/contract profiles. Untouched pre-existing modules keep their
V00.74 baselines by construction (no source change).

| Module | Mutation | Line | Notes |
|---|---|---|---|
| `jSentinel-events` | **86 % (356/416)** | 88 % | New module; test strength 89 %. Strong cross-package coverage; the publish/consume pipelines + verification result fully exercised. |
| `jSentinel-events-rest` | n/a (re-measure deferred) | — | Covered by a real HttpServer + HttpClient integration suite. |
| `jSentinel-events-testkit` | n/a | — | Contract suites verified through their consumers. |
| `jSentinel-events-persistence-eclipsestore` | n/a (re-measure deferred) | — | Storage-layer profile; verified via testkit contracts + a restart test. |

The concept §15 acceptance criterion — "mutation coverage of the V00.71 modules
does not drop through V00.75" — is satisfied for every pre-existing module by
construction: V00.75 changes no existing source.

## Acceptance summary

- ✅ All 35 prompts addressed (P002–P035); P014 deferred with documented
  carry-over.
- ✅ `jSentinel-events` unit coverage strong (86 % mutation / 88 % line).
- ✅ Ed25519 sign + verify end-to-end; tampered payload/tenant/type/expiry,
  unknown + revoked key, expiry, replay, sequence gap, producer-not-allowed all
  rejected with differentiated results.
- ✅ Replay atomic under 32-thread contention; sequence monotone per
  `(tenant, producer)`.
- ✅ Producer policy default-deny with per-tenant grants.
- ✅ SSE replay-from-cursor + permission-gated publish over a real JDK
  HttpServer; envelope wire round-trip.
- ✅ Eclipse-Store stores survive close + reopen (restart test).
- ✅ Audit consumes the bus; mapped events reach the audit service; sink
  failures isolated.
- ✅ Full reactor `clean install` green.

## Roadmap

`Konzept-V00.80.00.md` builds monitoring/metrics, SIEM + webhook integrations,
risk-based authentication, device + remember-me management, MFA/step-up flows,
tamper-evident audit as a separate listener, and streaming transports
(Kafka/NATS/RabbitMQ/Pulsar) on top of this bus.

---

**Footnotes:** concept `Konzept-V00.75.00.md`; plan
`Implementierungsplan-V00.75.00.md`; 5-minute setup
`docs/dx/5-minute-setup-eventbus.md`.
