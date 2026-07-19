package com.svenruppert.jsentinel.monitoring.diagnostics;

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
import com.svenruppert.jsentinel.dx.diagnostics.DiagnosticContributor;
import com.svenruppert.jsentinel.dx.diagnostics.DiagnosticReportBuilder;
import com.svenruppert.jsentinel.dx.diagnostics.DiscoveredService;
import com.svenruppert.jsentinel.dx.diagnostics.ServiceWarning;
import com.svenruppert.jsentinel.monitoring.health.JSentinelHealthIndicator;
import com.svenruppert.jsentinel.monitoring.metrics.JSentinelMetricsPublisher;

import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;
import java.util.Set;

/**
 * Contributes the monitoring-module findings to
 * {@code JSentinelDiagnostics.inspect()}: enumerates the registered
 * {@link JSentinelMetricsPublisher} and {@link JSentinelHealthIndicator}
 * implementations (as discovered entries) and warns when none is found —
 * a deployment without a metrics publisher silently discards every
 * metric via the no-op default, and one without health indicators gets
 * an empty {@code discoverAndCheck()} report.
 *
 * <p>Honors the {@link DiagnosticContributor} contract: never throws,
 * performs no I/O beyond {@link ServiceLoader} lookups, and inspects
 * provider <em>classes</em> only ({@code stream()} +
 * {@code Provider.type()}) — nothing is instantiated. Broken
 * registrations degrade to a {@link #PROVIDER_LOAD_FAILURE_CODE}
 * warning; healthy entries behind a broken one are still collected.</p>
 *
 * @since 00.80.00
 */
@ExperimentalJSentinelApi
public final class MonitoringDiagnosticContributor implements DiagnosticContributor {

  /** Stable contributor id. */
  public static final String ID = "monitoring";

  /** Warning code for a broken monitoring SPI registration. */
  public static final String PROVIDER_LOAD_FAILURE_CODE = "monitoring/provider-load-failure";

  /** Warning code when no {@link JSentinelMetricsPublisher} is registered. */
  public static final String NO_METRICS_PUBLISHER_CODE = "monitoring/no-metrics-publisher";

  /** Warning code when no {@link JSentinelHealthIndicator} is registered. */
  public static final String NO_HEALTH_INDICATORS_CODE = "monitoring/no-health-indicators";

  /** ServiceLoader requires a public no-arg constructor. */
  public MonitoringDiagnosticContributor() {
  }

  @Override
  public String id() {
    return ID;
  }

  @Override
  public void contribute(DiagnosticReportBuilder builder) {
    ClassLoader cl = contextClassLoader();
    int publishers = enumerate(JSentinelMetricsPublisher.class, cl, builder);
    if (publishers == 0) {
      builder.addWarning(new ServiceWarning(
          NO_METRICS_PUBLISHER_CODE,
          "No JSentinelMetricsPublisher registered — metrics are discarded (NoOp default).",
          "Register an adapter via META-INF/services or wire one programmatically."));
    }
    int indicators = enumerate(JSentinelHealthIndicator.class, cl, builder);
    if (indicators == 0) {
      builder.addWarning(new ServiceWarning(
          NO_HEALTH_INDICATORS_CODE,
          "No JSentinelHealthIndicator registered — "
              + "JSentinelHealthCheck.discoverAndCheck() reports no findings.",
          "Register an indicator via META-INF/services or pass indicators "
              + "programmatically to JSentinelHealthCheck.check(...)."));
    }
  }

  /**
   * Enumerates the implementation classes registered for {@code spi},
   * records each as a {@link DiscoveredService} and returns the count
   * of distinct implementations found.
   */
  private static <T> int enumerate(Class<T> spi, ClassLoader cl,
      DiagnosticReportBuilder builder) {
    LinkedHashSet<Class<?>> distinct = new LinkedHashSet<>();
    drainResilient(ServiceLoader.load(spi, cl).stream().iterator(), spi, distinct, builder);
    String loaderStr = String.valueOf(cl);
    for (Class<?> impl : distinct) {
      builder.addDiscovered(new DiscoveredService(spi, impl, loaderStr));
    }
    return distinct.size();
  }

  /**
   * Drains a {@link ServiceLoader} provider iterator with a per-element
   * try/catch: a broken {@code META-INF/services} entry becomes a
   * {@link #PROVIDER_LOAD_FAILURE_CODE} warning instead of a
   * {@link ServiceConfigurationError} aborting the sweep. If the exact
   * same failure message repeats, the loader is not advancing — stop
   * instead of spinning.
   */
  private static <T> void drainResilient(Iterator<ServiceLoader.Provider<T>> source,
      Class<T> spi, Set<Class<?>> distinct, DiagnosticReportBuilder builder) {
    Set<String> seenFailures = new LinkedHashSet<>();
    while (true) {
      try {
        if (!source.hasNext()) {
          return;
        }
        distinct.add(source.next().type());
      } catch (ServiceConfigurationError e) {
        if (!seenFailures.add(String.valueOf(e.getMessage()))) {
          return;
        }
        builder.addWarning(new ServiceWarning(
            PROVIDER_LOAD_FAILURE_CODE,
            "A " + spi.getSimpleName() + " provider failed to load: " + e.getMessage(),
            "Remove or correct the broken META-INF/services/" + spi.getName() + " entry."));
      }
    }
  }

  private static ClassLoader contextClassLoader() {
    ClassLoader cl = Thread.currentThread().getContextClassLoader();
    if (cl == null) {
      cl = MonitoringDiagnosticContributor.class.getClassLoader();
    }
    return cl;
  }
}
