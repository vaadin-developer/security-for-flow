package com.svenruppert.jsentinel.monitoring.metrics;

/*-
 * #%L
 * jSentinel Monitoring — metrics, health and diagnostics export points
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jSentinel by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * http://ec.europa.eu/idabc/eupl5
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;

/**
 * Backend-neutral export point for jSentinel operational metrics.
 *
 * <p>The framework never assumes a specific metrics stack. Adapters
 * plug in their preferred exporter (Micrometer, OpenTelemetry,
 * Prometheus, StatsD) by implementing this interface and registering
 * it via {@code META-INF/services} (picked up by
 * {@link JSentinelMetricsPublishers#discover()}) or by wiring an
 * instance programmatically. The default is
 * {@link NoOpJSentinelMetricsPublisher}, which records nothing —
 * minimal deployments don't pay any cost.</p>
 *
 * <p>Implementations <strong>must</strong> swallow exceptions
 * internally; metric emission sits on security-critical paths (login,
 * authorization, event-bus dispatch) and must never block or break
 * them because of a metrics-backend hiccup (CWE-778). A failed
 * publish call is absorbed silently.</p>
 *
 * <p>Metric names are not free-form: callers pass the constants from
 * {@link JSentinelMetricNames}, the single source of truth for the
 * catalog. Names passed to {@link #increment(String, long)} and
 * {@link #gauge(String, long)} must be non-null; only the no-op
 * default is more liberal.</p>
 *
 * <p><strong>Deliberately no tags / dimensions API in V1.</strong>
 * The surface is counters and push-style gauges only — no histograms,
 * no per-call label maps. Tags multiply time-series cardinality and
 * would let per-subject or per-tenant identifiers leak into the
 * metrics backend; keeping the V1 surface flat is a conscious
 * cardinality (and data-minimization) decision. Backends that want
 * dimensions can attach static ones (host, instance, application) on
 * their side of the bridge.</p>
 *
 * @since 00.80.00
 */
@ExperimentalJSentinelApi
public interface JSentinelMetricsPublisher {

  /**
   * Adds {@code delta} to the named counter. Counters are cumulative
   * and monotonically increasing; {@code delta} is expected to be
   * positive. Implementations <em>must not</em> throw; if the backend
   * is unavailable, swallow the failure.
   *
   * @param counterName a counter name from {@link JSentinelMetricNames}
   * @param delta       the amount to add (normally {@code 1})
   */
  void increment(String counterName, long delta);

  /**
   * Adds {@code 1} to the named counter. Convenience shorthand for
   * {@link #increment(String, long) increment(counterName, 1L)}.
   *
   * @param counterName a counter name from {@link JSentinelMetricNames}
   */
  default void increment(String counterName) {
    increment(counterName, 1L);
  }

  /**
   * Pushes the current value of the named gauge. Gauges are
   * last-write-wins snapshots (push style — the framework never
   * polls a callback). Implementations <em>must not</em> throw; if
   * the backend is unavailable, swallow the failure.
   *
   * @param gaugeName a gauge name from {@link JSentinelMetricNames}
   * @param value     the current value
   */
  void gauge(String gaugeName, long value);
}
