package eu.jsentinel.jcustos.monitoring.health;

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

import eu.jsentinel.jcustos.dx.runtime.Health;
import eu.jsentinel.jcustos.dx.runtime.HealthFinding;
import eu.jsentinel.jcustos.dx.runtime.HealthStatus;
import eu.jsentinel.jcustos.dx.runtime.Severity;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Aggregation matrix, ordering and failure isolation of
 * {@link JCustosHealthCheck} — exercised with real inline indicator
 * implementations, no doubles.
 */
class JCustosHealthCheckTest {

  private static final Instant FIXED = Instant.parse("2026-07-19T12:00:00Z");

  private static JCustosHealthIndicator indicator(String id, HealthFinding... findings) {
    return new JCustosHealthIndicator() {
      @Override
      public String id() {
        return id;
      }

      @Override
      public List<HealthFinding> check() {
        return List.of(findings);
      }
    };
  }

  private static HealthFinding finding(Severity severity, String code) {
    return new HealthFinding(severity, code, "message for " + code);
  }

  @Test
  @DisplayName("no indicators -> HEALTHY, zero registered services, fixed clock propagated")
  void emptyIndicatorListIsHealthy() {
    HealthStatus status = JCustosHealthCheck.check(List.of(), () -> FIXED);
    assertEquals(Health.HEALTHY, status.overall());
    assertEquals(List.of(), status.findings());
    assertEquals(0, status.registeredServices());
    assertEquals(FIXED, status.inspectedAt());
  }

  @Test
  @DisplayName("indicators with empty findings -> HEALTHY")
  void emptyFindingsAreHealthy() {
    HealthStatus status = JCustosHealthCheck.check(
        List.of(indicator("a"), indicator("b")), () -> FIXED);
    assertEquals(Health.HEALTHY, status.overall());
    assertEquals(2, status.registeredServices());
  }

  @Test
  @DisplayName("INFO-only findings do not degrade -> HEALTHY (dx rule pinned)")
  void infoOnlyStaysHealthy() {
    HealthStatus status = JCustosHealthCheck.check(
        List.of(indicator("a", finding(Severity.INFO, "info/one")),
            indicator("b", finding(Severity.INFO, "info/two"))),
        () -> FIXED);
    assertEquals(Health.HEALTHY, status.overall());
    assertEquals(2, status.findings().size());
  }

  @Test
  @DisplayName("any WARNING without ERROR -> DEGRADED")
  void warningWithoutErrorDegrades() {
    HealthStatus status = JCustosHealthCheck.check(
        List.of(indicator("a", finding(Severity.INFO, "info/one")),
            indicator("b", finding(Severity.WARNING, "warn/one"))),
        () -> FIXED);
    assertEquals(Health.DEGRADED, status.overall());
  }

  @Test
  @DisplayName("any ERROR -> FAILED, even alongside WARNING and INFO")
  void anyErrorFails() {
    HealthStatus status = JCustosHealthCheck.check(
        List.of(indicator("a", finding(Severity.WARNING, "warn/one")),
            indicator("b", finding(Severity.ERROR, "error/one")),
            indicator("c", finding(Severity.INFO, "info/one"))),
        () -> FIXED);
    assertEquals(Health.FAILED, status.overall());
    assertEquals(3, status.findings().size());
  }

  @Test
  @DisplayName("indicators run in sorted id() order regardless of list order")
  void indicatorsRunInSortedIdOrder() {
    List<String> callOrder = new ArrayList<>();
    JCustosHealthIndicator first = recording("a-first", callOrder);
    JCustosHealthIndicator second = recording("b-second", callOrder);
    JCustosHealthIndicator third = recording("c-third", callOrder);

    JCustosHealthCheck.check(List.of(third, first, second), () -> FIXED);
    assertEquals(List.of("a-first", "b-second", "c-third"), callOrder);

    callOrder.clear();
    JCustosHealthCheck.check(List.of(second, third, first), () -> FIXED);
    assertEquals(List.of("a-first", "b-second", "c-third"), callOrder);
  }

  @Test
  @DisplayName("throwing indicator becomes monitoring/indicator-failure ERROR, siblings still contribute")
  void throwingIndicatorIsIsolated() {
    JCustosHealthIndicator failing = new JCustosHealthIndicator() {
      @Override
      public String id() {
        return "a-fails";
      }

      @Override
      public List<HealthFinding> check() {
        throw new IllegalStateException("boom");
      }
    };
    JCustosHealthIndicator healthy = indicator("b-ok", finding(Severity.INFO, "info/ok"));

    HealthStatus status = JCustosHealthCheck.check(List.of(failing, healthy), () -> FIXED);

    assertEquals(Health.FAILED, status.overall());
    assertEquals(2, status.registeredServices());
    List<HealthFinding> failures = status.findings().stream()
        .filter(f -> JCustosHealthCheck.INDICATOR_FAILURE_CODE.equals(f.code()))
        .toList();
    assertEquals(1, failures.size());
    HealthFinding failure = failures.get(0);
    assertEquals(Severity.ERROR, failure.severity());
    assertTrue(failure.message().contains("a-fails"),
        "failure message should name the indicator id: " + failure.message());
    assertTrue(failure.message().contains("IllegalStateException"),
        "failure message should carry the exception type: " + failure.message());
    assertTrue(failure.message().contains("boom"),
        "failure message should carry the exception message: " + failure.message());
    assertTrue(status.findings().stream().anyMatch(f -> "info/ok".equals(f.code())),
        "healthy sibling finding must survive the failure");
  }

  @Test
  @DisplayName("indicator with throwing id() falls back to its class name, defensively")
  void throwingIdFallsBackToClassName() {
    JCustosHealthIndicator brokenId = new JCustosHealthIndicator() {
      @Override
      public String id() {
        throw new UnsupportedOperationException("no id");
      }

      @Override
      public List<HealthFinding> check() {
        throw new IllegalStateException("also broken");
      }
    };
    HealthStatus status = JCustosHealthCheck.check(List.of(brokenId), () -> FIXED);
    assertEquals(Health.FAILED, status.overall());
    assertEquals(1, status.findings().size());
    assertTrue(status.findings().get(0).message().contains(brokenId.getClass().getName()),
        "fallback must use the implementation class name");
  }

  @Test
  @DisplayName("indicator returning null findings becomes an indicator-failure ERROR")
  void nullFindingsListIsAFailure() {
    JCustosHealthIndicator nullReturning = new JCustosHealthIndicator() {
      @Override
      public String id() {
        return "null-returner";
      }

      @Override
      public List<HealthFinding> check() {
        return null;
      }
    };
    HealthStatus status = JCustosHealthCheck.check(List.of(nullReturning), () -> FIXED);
    assertEquals(Health.FAILED, status.overall());
    assertEquals(JCustosHealthCheck.INDICATOR_FAILURE_CODE,
        status.findings().get(0).code());
  }

  @Test
  @DisplayName("registeredServices counts all supplied indicators, throwing ones included")
  void registeredServicesCountsAllIndicators() {
    List<JCustosHealthIndicator> indicators = List.of(
        indicator("a"), indicator("b", finding(Severity.WARNING, "warn/one")),
        new JCustosHealthIndicator() {
          @Override
          public String id() {
            return "c-fails";
          }

          @Override
          public List<HealthFinding> check() {
            throw new IllegalStateException("broken");
          }
        });
    HealthStatus status = JCustosHealthCheck.check(indicators, () -> FIXED);
    assertEquals(indicators.size(), status.registeredServices());
  }

  @Test
  @DisplayName("discoverAndCheck() on the bare test classpath is HEALTHY with zero indicators")
  void discoverAndCheckOnBareClasspath() {
    // deliberately no META-INF/services registration for
    // JCustosHealthIndicator on the test classpath (see
    // JCustosMetricsPublishersTest for the same fixture idea)
    HealthStatus status = JCustosHealthCheck.discoverAndCheck();
    assertEquals(Health.HEALTHY, status.overall());
    assertEquals(0, status.registeredServices());
    assertEquals(List.of(), status.findings());
  }

  @Test
  @DisplayName("utility class is final with a single private constructor")
  void utilityClassIsFinalWithPrivateConstructor() {
    assertTrue(Modifier.isFinal(JCustosHealthCheck.class.getModifiers()));
    Constructor<?>[] constructors = JCustosHealthCheck.class.getDeclaredConstructors();
    assertEquals(1, constructors.length);
    assertTrue(Modifier.isPrivate(constructors[0].getModifiers()));
  }

  private static JCustosHealthIndicator recording(String id, List<String> callOrder) {
    return new JCustosHealthIndicator() {
      @Override
      public String id() {
        return id;
      }

      @Override
      public List<HealthFinding> check() {
        callOrder.add(id);
        return List.of();
      }
    };
  }
}
