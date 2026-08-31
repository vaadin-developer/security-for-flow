package eu.jsentinel.jcustos.monitoring.metrics;

/*-
 * #%L
 * jCustos Monitoring — metrics, health and diagnostics export points
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

/**
 * Default {@link JCustosMetricsPublisher} that records nothing.
 *
 * <p>Single shared instance — metrics export is opt-in by design.
 * Minimal deployments use this and pay zero cost; production
 * deployments swap it for an adapter that bridges to Micrometer /
 * OpenTelemetry / Prometheus / similar.</p>
 *
 * @since 00.80.00
 */
@ExperimentalJCustosApi
public final class NoOpJCustosMetricsPublisher implements JCustosMetricsPublisher {

  public static final NoOpJCustosMetricsPublisher INSTANCE =
      new NoOpJCustosMetricsPublisher();

  private NoOpJCustosMetricsPublisher() {
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
