# 5-Minute Setup — jSentinel Event Exporters (V00.80)

Ship signed Security-Event envelopes to your ops world — log stream,
in-process consumers, webhooks, OpenTelemetry, SIEM — in five minutes.
Konzept goal 8: the signed envelope from V00.75 stays the ONE integration
base; every exporter below consumes the same
`SignedJSentinelEventEnvelope` through the same tap.

## 1. The envelope tap (V00.80, in `jSentinel-events`)

```java
Registration tap = bus.subscribeEnvelope(envelope -> {
  // called for EVERY signed envelope the bus publishes, on the publish
  // thread, after the envelope store has appended it. Be fast or hand off —
  // a RuntimeException here is isolated and counted, never breaks publish.
});
```

All four V00.80 publishers implement `SignedEnvelopePublisher`, so wiring is
always the same: `bus.subscribeEnvelope(publisher)`.

## 2. In-tree publishers (`jSentinel-events`)

```java
// Grep-friendly EVENT lines on the named stream com.svenruppert.jsentinel.events
bus.subscribeEnvelope(new LoggingEventPublisher());

// In-process reactive tap (dashboards, custom pipelines) — java.util.concurrent.Flow
var stream = new EventStreamPublisher();
bus.subscribeEnvelope(stream);
stream.subscribe(mySubscriber);   // Flow.Subscriber<SignedJSentinelEventEnvelope>

// Alerts: severity-filtered typed listener (default threshold ERROR)
var alerts = new JSentinelAlertPublisher(new LoggingAlertSink());
alerts.subscribeTo(bus);          // pager/ticket/chat sinks implement JSentinelAlertSink
```

## 3. Webhook (`jSentinel-events-webhook`)

```xml
<dependency>
  <groupId>com.svenruppert.jsentinel</groupId>
  <artifactId>jSentinel-events-webhook</artifactId>
  <version>00.80.00</version>
</dependency>
```

```java
var webhook = new WebhookEventPublisher(WebhookPublisherConfig.defaults(
    URI.create("https://hooks.example.com/jsentinel")));
bus.subscribeEnvelope(webhook);
```

The POST body is the shared wire form (`EnvelopeWireCodec`) — byte-identical
to the REST/SSE bridge, so the receiver verifies the envelope with the
events verification SPIs (that is why there is deliberately no second HMAC
layer). Bounded queue + one virtual-thread worker (never blocks publish),
retry with backoff + jitter, dead-drop counters, bearer token via supplier
(never logged), `https` mandatory for non-loopback targets. Close it on
shutdown: `webhook.close()`.

## 4. OpenTelemetry (`jSentinel-events-opentelemetry`)

```xml
<dependency>
  <groupId>com.svenruppert.jsentinel</groupId>
  <artifactId>jSentinel-events-opentelemetry</artifactId>
  <version>00.80.00</version>
</dependency>
```

```java
bus.subscribeEnvelope(new OpenTelemetryEventPublisher(openTelemetry.getLogsBridge()));
```

One log record per envelope (Logs Bridge API, api-only at compile scope,
noop-safe — `LoggerProvider.noop()` makes it free). Attributes are the
`jsentinel.*` vocabulary from `OtelEnvelopeAttributes`; severity grades come
from the event type (replay → `ERROR2`); payload and signature bytes never
become attributes.

## 5. SIEM (`jSentinel-events-siem`)

```xml
<dependency>
  <groupId>com.svenruppert.jsentinel</groupId>
  <artifactId>jSentinel-events-siem</artifactId>
  <version>00.80.00</version>
</dependency>
```

```java
// CEF to a file your SIEM ingests — the framework ships FORMATTING only,
// the transport (file, socket, syslog pipe) is yours:
var out = Files.newBufferedWriter(Path.of("/var/log/jsentinel/security.cef"),
    StandardCharsets.UTF_8, CREATE, APPEND);
bus.subscribeEnvelope(new SiemEventExporter(new CefEnvelopeFormatter(), out));
```

Formatters: `CefEnvelopeFormatter` (CEF:0), `LeefEnvelopeFormatter`
(LEEF 2.0), `JsonLinesEnvelopeFormatter` (`application/x-ndjson` — metadata
projection by default; `new JsonLinesEnvelopeFormatter(true)` emits the full
verifiable signed record as an explicit opt-in).

## 6. Make verification failures observable (P012 wiring)

On the consume side (REST bridge), wire the failure handler so every
rejected envelope produces its self-observability event (which the
monitoring bridge counts), an operator log line with a stable
`events/...` code, and — per policy — a dead letter:

```java
var handler = new ConsumeFailureHandler(
    ConsumeFailurePolicy.strict(),      // fail-closed: reject everything, keep nothing
    null,                               // dead-letter store (required for operationalDefaults())
    bus,                                // the bus publishes the observability events
    Instant::now);
var service = new EventPublishService(wireCodec, consumePipeline,
    envelopeStore, broadcaster, Instant::now, handler);
```

`ConsumeFailurePolicy.operationalDefaults()` additionally dead-letters
sequence violations and expired envelopes for operator review — it requires
a `JSentinelEventDeadLetterStore` and fails at WIRING time without one.
The HTTP outcomes do not change either way.
