# 5-Minute Setup — jSentinel Monitoring (V00.80)

Wire runtime metrics and health signals into any jSentinel app in five
minutes. Konzept goal 9: clean export points, no bundled monitoring stack —
`jSentinel-monitoring` gives you one counter/gauge SPI, one canonical
metric-name catalog, one event-bus bridge and one health aggregator; the
backend (Micrometer, OpenTelemetry, Prometheus client, StatsD) stays your
choice.

## 1. Dependency

```xml
<dependency>
  <groupId>com.svenruppert.jsentinel</groupId>
  <artifactId>jSentinel-monitoring</artifactId>
  <version>00.80.00</version>
</dependency>
```

## 2. Implement the metrics SPI (or start with the no-op)

```java
// Adapter to whatever your ops stack speaks. The contract: NEVER throw.
public final class MicrometerMetricsPublisher implements JSentinelMetricsPublisher {

  private final MeterRegistry registry;

  public MicrometerMetricsPublisher(MeterRegistry registry) {
    this.registry = registry;
  }

  @Override
  public void increment(String counterName, long delta) {
    registry.counter(counterName).increment(delta);
  }

  @Override
  public void gauge(String gaugeName, long value) {
    registry.gauge(gaugeName, value);
  }
}
```

No adapter yet? `NoOpJSentinelMetricsPublisher.INSTANCE` is free and silent,
and `JSentinelMetricsPublishers.discover()` falls back to it when no
implementation is registered via `META-INF/services`.

## 3. Count the event stream — the bridge

```java
var metrics = new MicrometerMetricsPublisher(registry);
var bridge = new MetricsEventBusListener(metrics);
bridge.subscribeTo(bus);   // non-critical subscription — a metrics bug never
                           // aborts security dispatch
```

Every published event now increments `security.eventbus.published.total`
plus its specific counter (`security.auth.login.success.total`,
`security.authz.denied.total`, `security.session.created.total`, …).
Verification failures land on the umbrella
`security.eventbus.rejected.total` plus their drill-down
(`…replay.detected.total`, `…signature.invalid.total`,
`…sequence.violation.total`); dead letters and listener failures have their
own counters. All names live in `JSentinelMetricNames` — the constants are
API, dashboards can rely on them.

Gauges are state, not events — push them from where the state lives:

```java
metrics.gauge(JSentinelMetricNames.SESSION_ACTIVE, sessionStore.activeCount());
metrics.gauge(JSentinelMetricNames.EVENTBUS_SSE_CONNECTIONS_ACTIVE,
    sseHandler.activeStreamCount());
metrics.gauge(JSentinelMetricNames.AUDIT_STORE_LAG, ringBufferSink.size());
```

## 4. Health

```java
HealthStatus status = JSentinelHealthCheck.check(List.of(
        new DiagnosticsHealthIndicator(),                  // missing/duplicate SPIs
        new AuditStoreSaturationHealthIndicator(ringBufferSink)),  // audit-store lag
    Instant::now);
// status.overall(): HEALTHY | DEGRADED | FAILED — same rules as
// JSentinelRuntime.healthCheck(); findings carry stable codes such as
// diagnostics/missing-service or monitoring/audit-store-saturation.
```

Custom checks implement `JSentinelHealthIndicator` (`id()` +
`check(): List<HealthFinding>` — cheap, no I/O, never throw);
`JSentinelHealthCheck.discoverAndCheck()` picks up `META-INF/services`
registrations.

## 5. Diagnostics

`jSentinel-monitoring` registers a `DiagnosticContributor` (id
`monitoring`): `JSentinelDiagnostics.inspect()` now reports discovered
metrics publishers and health indicators — and warns
`monitoring/no-metrics-publisher` when metrics would silently go to the
no-op.

## What this module deliberately does NOT do

- No histograms, no tags/dimensions in V1 (cardinality and data
  minimization — tenant-tagged counters explode series counts).
- No bundled exporter/scrape endpoint — the SPI is the export point, the
  transport belongs to your ops stack.
- `security.eventbus.sse.reconnects.total` is reserved (name stable, no
  framework emission hook yet).
