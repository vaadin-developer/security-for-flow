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

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;
import eu.jsentinel.jcustos.dx.runtime.Health;
import eu.jsentinel.jcustos.dx.runtime.HealthFinding;
import eu.jsentinel.jcustos.dx.runtime.HealthStatus;
import eu.jsentinel.jcustos.dx.runtime.Severity;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.function.Supplier;

/**
 * Aggregates {@link JSentinelHealthIndicator}s into one
 * {@link HealthStatus} — the runtime counterpart of the bootstrap-time
 * {@code JSentinelRuntime.healthCheck()}.
 *
 * <p>Indicators are invoked in sorted {@link JSentinelHealthIndicator#id()}
 * order so reports are reproducible; an indicator whose {@code id()}
 * returns {@code null} or throws is sorted by its class name. A
 * {@link RuntimeException} escaping an indicator's {@code check()} is
 * caught and surfaced as a {@link Severity#ERROR} finding with code
 * {@link #INDICATOR_FAILURE_CODE} — healthy siblings still contribute.</p>
 *
 * <p>Overall classification follows exactly the {@link HealthStatus} /
 * {@code JSentinelRuntime.healthCheck()} severity rules: any
 * {@link Severity#ERROR} finding ⇒ {@link Health#FAILED}; any
 * {@link Severity#WARNING} finding (no errors) ⇒ {@link Health#DEGRADED};
 * only {@link Severity#INFO} findings (or none) ⇒
 * {@link Health#HEALTHY}.</p>
 *
 * <p>In this construction path
 * {@link HealthStatus#registeredServices()} means the <em>number of
 * contributing indicators</em> (bootstrap health checks count registered
 * SPI services there instead).</p>
 *
 * @since 00.80.00
 */
@ExperimentalJSentinelApi
public final class JSentinelHealthCheck {

  /**
   * Finding code for an indicator whose {@code check()} threw a
   * {@link RuntimeException} (or returned {@code null}). Always
   * {@link Severity#ERROR}.
   */
  public static final String INDICATOR_FAILURE_CODE = "monitoring/indicator-failure";

  /**
   * Finding code for a {@code META-INF/services} registration of
   * {@link JSentinelHealthIndicator} that failed to load during
   * {@link #discoverAndCheck()}. Always {@link Severity#ERROR}.
   */
  public static final String INDICATOR_LOAD_FAILURE_CODE = "monitoring/indicator-load-failure";

  private JSentinelHealthCheck() {
  }

  /**
   * Runs the supplied indicators and aggregates their findings.
   *
   * @param indicators the indicators to invoke; may be empty, never
   *                   {@code null}
   * @param clock      supplies the {@link HealthStatus#inspectedAt()}
   *                   stamp, never {@code null}
   * @return the aggregated status;
   *     {@link HealthStatus#registeredServices()} equals
   *     {@code indicators.size()}
   */
  public static HealthStatus check(List<JSentinelHealthIndicator> indicators,
      Supplier<Instant> clock) {
    Objects.requireNonNull(indicators, "indicators");
    Objects.requireNonNull(clock, "clock");
    return aggregate(indicators, List.of(), clock);
  }

  /**
   * Discovers indicators via {@link ServiceLoader} and delegates to the
   * aggregation. Resilient to broken registrations: a
   * {@link ServiceConfigurationError} becomes a {@link Severity#ERROR}
   * finding with code {@link #INDICATOR_LOAD_FAILURE_CODE} and discovery
   * continues with the providers that did load.
   *
   * @return the aggregated status over all discoverable indicators,
   *     stamped with {@link Instant#now()}
   */
  public static HealthStatus discoverAndCheck() {
    List<JSentinelHealthIndicator> indicators = new ArrayList<>();
    List<HealthFinding> loadFailures = new ArrayList<>();
    drainResilient(ServiceLoader.load(JSentinelHealthIndicator.class).iterator(),
        indicators, loadFailures);
    return aggregate(indicators, loadFailures, Instant::now);
  }

  private static HealthStatus aggregate(List<JSentinelHealthIndicator> indicators,
      List<HealthFinding> preFindings, Supplier<Instant> clock) {
    List<JSentinelHealthIndicator> sorted = new ArrayList<>(indicators);
    sorted.sort(Comparator.comparing(JSentinelHealthCheck::safeIndicatorId));
    List<HealthFinding> findings = new ArrayList<>(preFindings);
    for (JSentinelHealthIndicator indicator : sorted) {
      for (HealthFinding finding : checkOne(indicator)) {
        if (finding != null) {
          findings.add(finding);
        }
      }
    }
    // exactly the JSentinelRuntime.healthCheck() severity rules:
    // any ERROR -> FAILED, any WARNING (no error) -> DEGRADED, else HEALTHY
    boolean anyError = findings.stream().anyMatch(f -> f.severity() == Severity.ERROR);
    boolean anyWarning = findings.stream().anyMatch(f -> f.severity() == Severity.WARNING);
    Health overall = anyError ? Health.FAILED : (anyWarning ? Health.DEGRADED : Health.HEALTHY);
    return new HealthStatus(overall, findings, indicators.size(), clock.get());
  }

  private static List<HealthFinding> checkOne(JSentinelHealthIndicator indicator) {
    try {
      List<HealthFinding> findings = indicator.check();
      if (findings == null) {
        return List.of(indicatorFailure(indicator,
            "check() returned null instead of a findings list"));
      }
      return findings;
    } catch (RuntimeException e) {
      HasLogger.staticLogger().warn(
          "{}: indicator '{}' threw {}: {}",
          INDICATOR_FAILURE_CODE, safeIndicatorId(indicator),
          e.getClass().getSimpleName(), e.getMessage());
      return List.of(indicatorFailure(indicator,
          e.getClass().getSimpleName() + ": " + e.getMessage()));
    }
  }

  private static HealthFinding indicatorFailure(JSentinelHealthIndicator indicator,
      String summary) {
    return new HealthFinding(Severity.ERROR, INDICATOR_FAILURE_CODE,
        "Health indicator '" + safeIndicatorId(indicator) + "' ("
            + indicator.getClass().getName() + ") failed: " + summary);
  }

  /**
   * An indicator whose {@code id()} throws (or returns {@code null})
   * must neither kill the deterministic sort nor the failure-report
   * path — fall back to the implementation class name.
   */
  private static String safeIndicatorId(JSentinelHealthIndicator indicator) {
    try {
      String id = indicator.id();
      return id == null ? indicator.getClass().getName() : id;
    } catch (RuntimeException | Error e) {
      return indicator.getClass().getName();
    }
  }

  /**
   * Drains a {@link ServiceLoader} iterator with a per-element try/catch
   * so a broken {@code META-INF/services} entry becomes an ERROR finding
   * instead of a {@link ServiceConfigurationError} crashing discovery.
   * The JDK lookup iterator consumes the offending entry before it
   * throws, so retrying resumes with the next entry. If the exact same
   * failure message repeats, the loader is not advancing — stop instead
   * of spinning.
   */
  private static void drainResilient(Iterator<JSentinelHealthIndicator> source,
      List<JSentinelHealthIndicator> indicators, List<HealthFinding> loadFailures) {
    Set<String> seenFailures = new LinkedHashSet<>();
    while (true) {
      try {
        if (!source.hasNext()) {
          return;
        }
        indicators.add(source.next());
      } catch (ServiceConfigurationError e) {
        if (!seenFailures.add(String.valueOf(e.getMessage()))) {
          return;
        }
        HasLogger.staticLogger().warn(
            "{}: a JSentinelHealthIndicator provider failed to load: {}",
            INDICATOR_LOAD_FAILURE_CODE, e.getMessage());
        loadFailures.add(new HealthFinding(Severity.ERROR, INDICATOR_LOAD_FAILURE_CODE,
            "A JSentinelHealthIndicator provider failed to load: " + e.getMessage()));
      }
    }
  }
}
