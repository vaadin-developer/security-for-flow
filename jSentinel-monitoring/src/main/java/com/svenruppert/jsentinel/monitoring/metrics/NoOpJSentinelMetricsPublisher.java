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
 * Default {@link JSentinelMetricsPublisher} that records nothing.
 *
 * <p>Single shared instance — metrics export is opt-in by design.
 * Minimal deployments use this and pay zero cost; production
 * deployments swap it for an adapter that bridges to Micrometer /
 * OpenTelemetry / Prometheus / similar.</p>
 *
 * @since 00.80.00
 */
@ExperimentalJSentinelApi
public final class NoOpJSentinelMetricsPublisher implements JSentinelMetricsPublisher {

  public static final NoOpJSentinelMetricsPublisher INSTANCE =
      new NoOpJSentinelMetricsPublisher();

  private NoOpJSentinelMetricsPublisher() {
  }

  @Override
  public void increment(String counterName, long delta) {
    // intentionally empty
  }

  @Override
  public void gauge(String gaugeName, long value) {
    // intentionally empty
  }
}
