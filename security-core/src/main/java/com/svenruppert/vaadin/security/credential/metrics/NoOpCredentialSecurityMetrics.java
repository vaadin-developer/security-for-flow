/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or - as soon they will be
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
package com.svenruppert.vaadin.security.credential.metrics;

/**
 * Default {@link CredentialSecurityMetrics} that records nothing.
 *
 * <p>Single shared instance — metrics collection is opt-in by design.
 * Minimal deployments use this and pay zero cost; production
 * deployments swap it for an adapter that bridges to Micrometer /
 * OpenTelemetry / similar.</p>
 */
public final class NoOpCredentialSecurityMetrics implements CredentialSecurityMetrics {

  public static final NoOpCredentialSecurityMetrics INSTANCE =
      new NoOpCredentialSecurityMetrics();

  private NoOpCredentialSecurityMetrics() {
  }

  @Override
  public void publish(CredentialMetricEvent event) {
    // intentionally empty
  }
}
