# 5-Minute Setup — jCustos Monitoring (V00.80)

Wire runtime metrics and health signals into any jCustos app in five
minutes. Konzept goal 9: clean export points, no bundled monitoring stack —
`jCustos-monitoring` gives you one counter/gauge SPI, one canonical
metric-name catalog, one event-bus bridge and one health aggregator; the
backend (Micrometer, OpenTelemetry, Prometheus client, StatsD) stays your
choice.

## 1. Dependency

```xml
<dependency>
  <groupId>eu.jsentinel</groupId>
  <artifactId>jCustos-monitoring</artifactId>
  <version>00.80.00</version>
</dependency>
```

## 2. Implement the metrics SPI (or start with the no-op)

```java
// Adapter to whatever your ops stack speaks. The contract: NEVER throw.
public final class MicrometerMetricsPublisher implements JCustosMetricsPublisher {

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

No adapter yet? `NoOpJCustosMetricsPublisher.INSTANCE` is free and silent,
and `JCustosMetricsPublishers.discover()` falls back to it when no
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
own counters. All names live in `JCustosMetricNames` — the constants are
API, dashboards can rely on them.

Gauges are state, not events — push them from where the state lives:

```java
metrics.gauge(JCustosMetricNames.SESSION_ACTIVE, sessionStore.activeCount());
metrics.gauge(JCustosMetricNames.EVENTBUS_SSE_CONNECTIONS_ACTIVE,
    sseHandler.activeStreamCount());
metrics.gauge(JCustosMetricNames.AUDIT_STORE_LAG, ringBufferSink.size());
```

## 4. Health

```java
HealthStatus status = JCustosHealthCheck.check(List.of(
        new DiagnosticsHealthIndicator(),                  // missing/duplicate SPIs
        new AuditStoreSaturationHealthIndicator(ringBufferSink)),  // audit-store lag
    Instant::now);
// status.overall(): HEALTHY | DEGRADED | FAILED — same rules as
// JCustosRuntime.healthCheck(); findings carry stable codes such as
// diagnostics/missing-service or monitoring/audit-store-saturation.
```

Custom checks implement `JCustosHealthIndicator` (`id()` +
`check(): List<HealthFinding>` — cheap, no I/O, never throw);
`JCustosHealthCheck.discoverAndCheck()` picks up `META-INF/services`
registrations.

## 5. Diagnostics

`jCustos-monitoring` registers a `DiagnosticContributor` (id
`monitoring`): `JCustosDiagnostics.inspect()` now reports discovered
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
