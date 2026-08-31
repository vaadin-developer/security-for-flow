# 5-Minute Setup — jCustos Security Event Bus (V00.75)

Wire a signed, replay-protected Security Event Bus into a JDK app in five
minutes. Everything below uses only `jCustos-events` (the SPI core);
persistence and the REST/SSE bridge are opt-in add-ons at the end.

## 1. Dependency

```xml
<dependency>
  <groupId>eu.jsentinel</groupId>
  <artifactId>jCustos-events</artifactId>
  <version>00.75.00</version>
</dependency>
```

## 2. Wire the publisher + bus

```java
// Keys: in-memory Ed25519 for local setups (swap for JdkKeyStoreKeyManagement
// in production — same SPI).
var keys = new InMemoryKeyManagement(new Ed25519SignatureAlgorithm(), KeyId.of("eventbus-1"));

// Who is allowed to publish what.
var producer = EventProducerId.of("my-service");
var policy = AllowListProducerPolicy.builder()
    .allow(producer, LoginSucceededEvent.TYPE)
    .allow(producer, SessionRevokedEvent.TYPE)
    .build();

// The publish pipeline: canonicalize -> hash -> sign -> replay-mark.
var publish = new PublishPipeline(
    keys, new RecordReflectionCanonicalizer(), new CanonicalJsonPayloadCodec(),
    PayloadHashAlgorithm.SHA_256, producer,
    new InMemorySequenceStore(), new InMemoryReplayStore(), policy,
    Duration.ofMinutes(5), Instant::now);

var bus = new DefaultJCustosEventBus(publish);
```

## 3. Subscribe + publish

```java
bus.subscribe(SessionRevokedEvent.class, e ->
    System.out.println("revoke UI session " + e.sessionId()));

var meta = EventMetadata.create(TenantId.DEFAULT, SubjectId.of("alice"),
    Instant.now(), JCustosEventSeverity.INFO);
bus.publish(new LoginSucceededEvent(meta, "password"));
```

`publish` signs the event into a `SignedJCustosEventEnvelope` and dispatches
the typed event to local listeners. A failing listener is isolated by default
(`ISOLATE_AND_CONTINUE`) and reported as a `ListenerFailedEvent`.

## 4. Audit on the bus

Audit is a *consumer*, not hard-wired:

```java
JCustosAuditService audit = /* your audit service */;
new AuditEventBusListener(audit).subscribeTo(bus);
```

`LoginSucceeded` / `LoginFailed` / `PermissionDenied` events are mapped to the
core `AuditEvent` model; a throwing audit sink is isolated.

## 5. Verify an incoming envelope (consumer side)

A remote consumer (e.g. a Vaadin app) verifies envelopes it receives:

```java
var consume = new ConsumePipeline(
    keys /* the matching public keys */, SignatureAlgorithms.defaults(),
    new InMemoryReplayStore(), new InMemorySequenceStore(),
    new SequenceValidator(), SequenceViolationStrategy.REJECT, policy);

JCustosEventVerificationResult result = consume.verify(envelope, Instant.now());
if (result.isValid()) { /* react */ }
// else: InvalidSignature / UnknownKey / KeyRevoked / Expired /
//       PayloadHashMismatch / ReplayDetected / SequenceViolation / ProducerNotAllowed
```

## 6. Opt-in: persistence + REST/SSE bridge

* **Persistent, restart-safe stores** — add `jCustos-events-persistence-eclipsestore`
  and swap the in-memory stores for `EclipseStoreEventStorage.openAt(dir)`'s
  `replayStore()` / `sequenceStore()` / `envelopeStore()` / `deadLetterStore()`.
* **REST/SSE bridge** — add `jCustos-events-rest`, register
  `SseStreamHttpHandler` at `GET /api/events/stream` (replay-from-cursor + live
  tail) and `EventPublishHttpHandler` at `POST /api/events` (permission-gated,
  runs the consume pipeline). The channel itself is secured by HTTPS / mTLS —
  the bridge does not encrypt it.

## 7. Feature flag

Emission from existing services is gated by `jcustos.events.bus.enabled`
(default off) via `FeatureFlaggedEventPublisher`, so legacy direct-audit
deployments are unaffected until you opt in.

---

All V00.75 types carry `@ExperimentalJCustosApi`; stable-API promotion is
staged for a later release after demo adoption.
