# Release Notes — jSentinel V00.80.00

**Theme:** Operations & Forensics — the operations and forensics release: runtime
metrics and health export points (concept goal 9), production-grade event
integrations on the signed envelope base (goal 8), and a tamper-evident,
independently verifiable audit hash chain (goal 7), plus the strict-mode
wiring of the consume-side verification failure paths (goal 10 subset).

**Result:** 7 new modules (reactor 54 → 61 library+demo modules), 13 feature
prompts (P001–P013), 11 in-cycle entry-review fixes (R00–R10), 2 in-cycle
exit-review fixes (RF00–RF01), 19 commits, ~200 files, full reactor green.

## Statement of additivity

Everything in V00.80.00 is additive. No published API was removed; the one
relocation (`EnvelopeWireCodec` → `com.svenruppert.jsentinel.events.wire`)
keeps a `@Deprecated(forRemoval = true, since = "00.80.00")` delegator at the
old `events.rest` location for one release. Existing constructors of
`EventPublishService` keep working (the failure-handler variant is a new
overload). All new public types carry `@ExperimentalJSentinelApi` +
`@since 00.80.00`.

## Headline change — one tap, every exporter

Before V00.80, signed envelopes only reached remote consumers through the
REST/SSE bridge; locally published envelopes had no integration point.

```java
// V00.80: ONE contract for every operational integration
bus.subscribeEnvelope(new LoggingEventPublisher());                         // grep-able EVENT lines
bus.subscribeEnvelope(new WebhookEventPublisher(config));                   // signed envelopes over HTTPS
bus.subscribeEnvelope(new OpenTelemetryEventPublisher(otel.getLogsBridge()));// OTel log records
bus.subscribeEnvelope(new SiemEventExporter(new CefEnvelopeFormatter(), out));// CEF/LEEF/NDJSON
new MetricsEventBusListener(metrics).subscribeTo(bus);                      // security.eventbus.* counters
new AuditIntegrityListener(appender).subscribeTo(bus);                      // tamper-evident hash chain
```

A failing integration is isolated and counted — it can never break
`publish(...)`.

## What's new in detail

### Goal 9 — Operations & Monitoring (`jSentinel-monitoring`, P001–P003 + P002)

| Piece | Delivered |
|---|---|
| Metrics SPI | `JSentinelMetricsPublisher` (counters + push gauges, never-throw contract per the `CredentialJSentinelMetrics` precedent), `NoOpJSentinelMetricsPublisher.INSTANCE`, ServiceLoader `JSentinelMetricsPublishers.discover()` with deterministic multi-impl resolution |
| Name catalog | `JSentinelMetricNames` — the 9 concept-verbatim `security.eventbus.*` names plus minted `security.auth.*` / `security.authz.*` / `security.session.*` / `security.audit.store.lag`; names are API; `…sse.reconnects.total` reserved (no emission hook yet) |
| Bridge | `MetricsEventBusListener` (non-critical subscription): `rejected.total` is the umbrella over the whole rejection family with per-kind drill-downs; self-observability events never count `published.total`; deliberately unmapped with documented rationale: RateLimitExceeded, SessionExpired, LogoutSucceeded, OidcLoginSucceeded, StepUpRequired; gauges stay app-wired |
| Health | `JSentinelHealthIndicator` SPI + `JSentinelHealthCheck` aggregator (dx `HealthFinding`/`HealthStatus` reused — one `/health` body shape framework-wide), `DiagnosticsHealthIndicator` (wraps `JSentinelDiagnostics.inspect()`), `AuditStoreSaturationHealthIndicator`, `MonitoringDiagnosticContributor` (warns `monitoring/no-metrics-publisher`) |

### Goal 8 — Event integrations (P004–P008)

| Piece | Delivered |
|---|---|
| Self-observability (P004) | `EventBusSelfObservabilityEvent` marker on the six V00.75 integrity records; `EventBusObservabilityPublisher` direct-dispatch path (never through the signed pipeline — structurally loop-free); `SelfObservabilityEvents.fromVerification(...)` maps the sealed 10-variant verification result to exactly ONE most-specific event per failure (replay → `CRITICAL`); `DeadLetterRecorder` as the canonical dead-letter emission point; publish-side producer-policy denial now emits `EnvelopeRejectedEvent` before rethrowing |
| Envelope tap (P005) | `SignedEnvelopePublisher` SPI + `JSentinelEventBus.subscribeEnvelope(...)`; fan-out after store-append, before typed dispatch; per-publisher failure isolation + `envelopePublisherFailureCount()` |
| In-tree publishers (P005) | `LoggingEventPublisher` (named stream `com.svenruppert.jsentinel.events`, scrubbed `EVENT …` lines, never payload/signature), `EventStreamPublisher` (`java.util.concurrent.Flow`, drop-not-retry), `JSentinelAlert`/`JSentinelAlertSink`/`LoggingAlertSink`/`JSentinelAlertPublisher` (typed listener by design — severity lives on the event; default threshold ERROR, so every verification failure alerts) |
| Wire codec (P005) | Moved to `events.wire` (+`encodeMetadata(...)` secret-free projection sharing one field home with `encode()`); deprecated delegator in events-rest; `CanonicalJson` promoted to public (P010 reuse) |
| Webhook (P006) | `WebhookEventPublisher`: bounded queue + one virtual-thread worker (never blocks publish, per-target order), shared wire form as body (receiver verifies with the events SPIs — deliberately NO second HMAC layer), retry with backoff+jitter, dead-drop counters, bearer token per attempt (never logged), redirects disabled, https mandatory for non-loopback |
| OpenTelemetry (P007) | `OpenTelemetryEventPublisher` over the Logs Bridge API — api-only at compile scope (`opentelemetry-api` 1.49.0, module-property pinned), noop-safe; `jsentinel.*` attribute vocabulary without payload/signature; severity grades from the record TYPE constants (replay → `ERROR2`) |
| SIEM (P008) | `SiemEventExporter` (Appendable transport — formatting only, no vendor binding) + `CefEnvelopeFormatter` (CEF:0), `LeefEnvelopeFormatter` (LEEF 2.0, self-consistent devTime/devTimeFormat), `JsonLinesEnvelopeFormatter` (NDJSON; full verifiable record as explicit opt-in) |

### Goal 7 — Tamper-evident audit (`jSentinel-audit-integrity` + testkit + Eclipse-Store module, P009–P011)

| Piece | Delivered |
|---|---|
| Chain model (P009) | `AuditChainEntry` (defensive bytes, non-hex genesis anchor), `AuditChainStore` SPI (append-only BY CONTRACT, linkage-CAS), `AuditChainEntryHasher` (injective length-prefixed base `jsentinel-audit-chain/v1`, H(prev‖entry), fail-closed on unavailable digests, golden-pinned), `AuditChainAppender` (retries while the chain grows — the CAS guarantees global progress; `audit-integrity/append-contention` only for a stalling store), `InMemoryAuditChainStore` (CapacityBound, throw-on-full) |
| Verify + export (P010) | `AuditIntegrityVerifier` (paged + range form, sealed result with 5 break reasons), `SignedAuditBatch`/`AuditBatchSigner`/`AuditBatchVerifier` (events key/signature SPIs — one signing home; atomic `SigningKeySnapshot` per batch; rotated keys keep verifying, revoked do not), `AuditExportService` + `AuditExportNdjsonCodec` (`application/x-ndjson`, strict decode, re-verification needs only the text + public keys) |
| Feeds + persistence (P011) | `AuditRelevancePolicy` (default: ≥ NOTICE ∪ AUTHENTICATION/AUTHORIZATION/ADMIN/INTEGRITY), `AuditIntegrityListener` (bus feed, strictly isolated), `AuditEventCanonicalizer` + `HashChainingAuditSink` (the V00.70 audit path gains chaining ON TOP of its sinks), `jSentinel-audit-integrity-persistence-eclipsestore` (`openAt(Path)`, StorageTreeHardening, restart-safe: pre+post-restart entries verify as one chain), `jSentinel-audit-integrity-testkit` (`AuditChainStoreContract` + `TestkitChainEntries`) |

### Goal 10 subset — strict-mode consume wiring (P012)

`ConsumeFailureAction` (reject is ALWAYS; dead-lettering is the only choice),
`ConsumeFailurePolicy` (`strict()` fail-closed / `operationalDefaults()`
dead-letters sequence violations + expired envelopes / `custom()` from the
fail-closed base), `ConsumeFailureHandler` — the ONE place a failure becomes
observable: exactly one self-observability event (the metric seam for the
monitoring bridge — no events→monitoring dependency), optional dead letter,
one operator log line per kind with stable `events/...` codes and actionable
guidance; total and never-throwing; a dead-lettering policy without a store
fails AT WIRING TIME. `EventPublishService` gained one optional handler
parameter; the HTTP mapping is byte-identical either way (pinned by test).

## Entry production-review (11 findings, all fixed in-cycle)

R00 signing-snapshot TOCTOU (PublishPipeline/InMemoryKeyManagement) ·
R01 injective nested-record canonicalization · R02 identity-based
Registration removal · R03 framed persisted sequence key (`v2:` + migration)
· R04 consume commit order CAS-before-markSeen · R05 SSE negative
Last-Event-ID totality · R06 CapacityBound single-home in
InMemoryReplayStore · R07 scrubbed SSE logs (+seam) · R08 SSE constructor
guards · R09 ServiceConfigurationError-resilient diagnostics ·
R10 logged audit-store append failures. 32 named negatives documented on the
review task.

## Exit production-review (SHIP; 2 low findings, fixed in-cycle)

RF00 webhook close-race drop accounting · RF01 NDJSON trailing-newline file
round-trip. Named negatives on the review task (bus fan-out coherence,
webhook secret hygiene, framing injectivity, handler totality, scrubbing
coverage, Eclipse-Store lock discipline, OTel data minimization, metric
double-count freedom).

## What V00.80.00 does NOT do

- No bundled monitoring stack, scrape endpoint, histograms or metric
  tags/dimensions (V1 cardinality decision) — the SPI is the export point.
- No SIEM as part of the framework, no vendor binding — formatters only,
  the transport belongs to the host.
- No transport-level HMAC on the webhook — the signed envelope is the
  integrity layer; receivers verify with the events SPIs.
- No per-tenant audit chains (single chain per store in V1) and no
  automatic mapping of `JSentinelBootstrapMode.STRICT` to
  `ConsumeFailurePolicy.strict()` (a dx↔events wiring prompt is a candidate
  for a later release).
- `security.eventbus.sse.reconnects.total` is reserved — the events-rest
  counting hook is deliberately deferred.
- Deferred concept goals stay deferred: MFA/step-up, WebAuthn,
  device/remember-me, risk-based auth, CSRF, privacy/retention
  (V00.80.x / V00.81+).

## Mutation coverage (V00.80.00)

Measured with the reactor PIT setup (kill = KILLED + TIMED_OUT); baseline
comparison per the ≤ 3 pp acceptance bar; new modules set new baselines.

| Module | Baseline | V00.80.00 | Note |
|---|---|---|---|
| `jSentinel-core` | 84 % (2230/2658, V00.79.41) | **84 % (2231/2658)** | flat — R10 delta only |
| `jSentinel-dx` | 71 % (313/441, V00.75.20) | **65 % (465/714)** | kills +152 absolute; the V00.80 delta is R09 only — the pp drop is the V00.73-precedent denominator effect: 273 mutants of never-PIT-measured V00.76–79 dx growth entered the denominator. Backlog: focused dx PIT lift. |
| `jSentinel-events` | 85 % (379/445, V00.75.20) | **84 % (556/664)** | −1 pp at +49 % code — within the bar |
| `jSentinel-events-rest` | 67 % (101/151, V00.75.20) | **70 % (74/106)** | +3 pp (codec moved out of the denominator) |
| `jSentinel-events-persistence-eclipsestore` | no recorded baseline | **74 % (109/148)** | first recorded measurement (R03 delta) |
| `jSentinel-monitoring` | new | **79 % (65/82)** | new baseline |
| `jSentinel-events-webhook` | new | **62 % (42/68)** | new baseline; retry/timing mutants dominate survivors |
| `jSentinel-events-opentelemetry` | new | **100 % (5/5)** | new baseline (api-only mapping — tiny mutation surface) |
| `jSentinel-events-siem` | new | **94 % (59/63)** | new baseline |
| `jSentinel-audit-integrity` | new | **78 % (170/219)** | new baseline. First measurement was 29 % — the verifier/export tests lived in the testkit module and were invisible to per-module PIT; they were moved into the module (module-local fixture), documented in the test-move commit. |
| `jSentinel-audit-integrity-persistence-eclipsestore` | new | **77 % (41/53)** | new baseline |

## Acceptance summary

- ✅ All 13 feature prompts implemented, tested (no mocks — real
  implementations, recording doubles, real HttpServer/SDK/storage), each
  green at commit time.
- ✅ concept goal-7 acceptance: tamper-evident chains verify — including
  across process restarts and via signed NDJSON exports with public
  material only.
- ✅ concept goal-8 acceptance: all exporters consume signed envelopes;
  critical verification failures produce alerts
  (`JSentinelAlertPublisher` end-to-end test).
- ✅ concept goal-9 acceptance: the 9 concept metric names ship verbatim and
  are emitted by the bridge (pinned literally by tests).
- ✅ Strict-mode failure paths: Reject + Event + Metric seam + operator
  codes, fail-closed profile default.
- ✅ Standards pass over the delta: 0 findings
  (haslogger/httpstatus/mediatype/result/extract-constants; vaadin-i18n
  N/A).
- ✅ Entry review: 11/11 findings fixed in-cycle. Exit review: SHIP,
  2 low findings fixed in-cycle.
- ✅ Full 61-module reactor build with tests green.

## Roadmap

V00.80.x candidates: SSE reconnect counter hook, per-tenant audit chains,
dx↔events STRICT bridging, optional webhook HMAC opt-in for
non-verifying receivers. V00.81+: the deferred concept goals (MFA/step-up,
WebAuthn, device management, risk-based auth, CSRF, privacy/retention).
