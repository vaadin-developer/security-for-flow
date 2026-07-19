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
 * Health export point: the
 * {@link com.svenruppert.jsentinel.monitoring.health.JSentinelHealthIndicator}
 * SPI, the
 * {@link com.svenruppert.jsentinel.monitoring.health.JSentinelHealthCheck}
 * aggregator (reusing the dx
 * {@link com.svenruppert.jsentinel.dx.runtime.HealthStatus} /
 * {@link com.svenruppert.jsentinel.dx.runtime.HealthFinding} report
 * model — no parallel type zoo) and two built-in indicators:
 * {@link com.svenruppert.jsentinel.monitoring.health.DiagnosticsHealthIndicator}
 * over {@code JSentinelDiagnostics.inspect()} and
 * {@link com.svenruppert.jsentinel.monitoring.health.AuditStoreSaturationHealthIndicator}
 * over the {@code RingBufferAuditSink} fill level.
 *
 * @since 00.80.00
 */
package com.svenruppert.jsentinel.monitoring.health;
