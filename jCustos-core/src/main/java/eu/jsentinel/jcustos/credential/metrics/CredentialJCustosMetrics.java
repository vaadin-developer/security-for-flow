/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */
package eu.jsentinel.jcustos.credential.metrics;

/**
 * Backend-neutral sink for {@link CredentialMetricEvent}s.
 *
 * <p>The core never assumes a specific metrics framework. Adapters
 * plug in their preferred exporter (Micrometer, OpenTelemetry,
 * Statsd, Prometheus) through this interface. The default is
 * {@link NoOpCredentialJCustosMetrics}, which records nothing —
 * minimal deployments don't pay any cost.</p>
 *
 * <p>Implementations <strong>must</strong> swallow exceptions
 * internally; the credential pipeline is on a security-critical path
 * and must not be blocked by a metrics-backend hiccup (CWE-778).
 * The default {@link #publish} contract documents this — failed
 * publish calls are absorbed silently.</p>
 */
public interface CredentialJCustosMetrics {

  /**
   * Records one event. Implementations <em>must not</em> throw; if
   * the backend is unavailable, swallow the failure.
   */
  void publish(CredentialMetricEvent event);
}
