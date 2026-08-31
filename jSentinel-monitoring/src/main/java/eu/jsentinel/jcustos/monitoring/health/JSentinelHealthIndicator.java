package eu.jsentinel.jcustos.monitoring.health;

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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;
import eu.jsentinel.jcustos.dx.runtime.HealthFinding;
import eu.jsentinel.jcustos.dx.runtime.Severity;

import java.util.List;

/**
 * One health probe contributing {@link HealthFinding}s to an aggregated
 * {@link eu.jsentinel.jcustos.dx.runtime.HealthStatus} produced by
 * {@link JSentinelHealthCheck}.
 *
 * <p>Implementations are discovered via {@code ServiceLoader}
 * ({@link JSentinelHealthCheck#discoverAndCheck()}) or passed
 * programmatically to
 * {@link JSentinelHealthCheck#check(List, java.util.function.Supplier)}.
 * An empty findings list means the probed subsystem is healthy.</p>
 *
 * <p>Contract (mirrors the dx {@code DiagnosticContributor} contract):</p>
 * <ul>
 *   <li>Must be cheap — suitable for a periodically polled
 *       {@code /health} endpoint.</li>
 *   <li>No network I/O; probe in-process state only.</li>
 *   <li>Should not throw. A {@link RuntimeException} escaping
 *       {@link #check()} is caught by the aggregator and surfaced as a
 *       {@link Severity#ERROR} finding with code
 *       {@link JSentinelHealthCheck#INDICATOR_FAILURE_CODE
 *       monitoring/indicator-failure} — it never crashes the health
 *       endpoint, but it does fail the overall status.</li>
 * </ul>
 *
 * @since 00.80.00
 */
@ExperimentalJSentinelApi
public interface JSentinelHealthIndicator {

  /**
   * Stable identifier of this indicator (e.g. {@code "diagnostics"},
   * {@code "audit-store"}). Drives the sorted invocation order in
   * {@link JSentinelHealthCheck}, so reports are reproducible.
   *
   * @return the stable indicator id
   */
  String id();

  /**
   * Probes the subsystem and reports its findings.
   *
   * @return the findings; an empty list means healthy, never {@code null}
   */
  List<HealthFinding> check();
}
