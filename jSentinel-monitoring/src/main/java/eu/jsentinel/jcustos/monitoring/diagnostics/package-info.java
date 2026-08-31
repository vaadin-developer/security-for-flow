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

/**
 * Diagnostics integration: the
 * {@link eu.jsentinel.jcustos.monitoring.diagnostics.MonitoringDiagnosticContributor}
 * plugs the monitoring module into the dx
 * {@code JSentinelDiagnostics.inspect()} sweep — discovered
 * {@code JSentinelMetricsPublisher} / {@code JSentinelHealthIndicator}
 * registrations plus warnings when a deployment runs without either.
 * Registered via the manual
 * {@code META-INF/services/eu.jsentinel.jcustos.dx.diagnostics.DiagnosticContributor}
 * entry (this module carries no annotation processor).
 *
 * @since 00.80.00
 */
package eu.jsentinel.jcustos.monitoring.diagnostics;
