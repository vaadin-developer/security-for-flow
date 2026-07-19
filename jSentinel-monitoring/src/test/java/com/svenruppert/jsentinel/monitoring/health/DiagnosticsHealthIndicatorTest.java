package com.svenruppert.jsentinel.monitoring.health;

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

import com.svenruppert.jsentinel.dx.runtime.HealthFinding;
import com.svenruppert.jsentinel.dx.runtime.Severity;
import com.svenruppert.jsentinel.monitoring.diagnostics.MonitoringDiagnosticContributor;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Runs against the REAL test classpath: this module registers no
 * {@code AuthenticationService} / {@code AuthorizationService}, so
 * {@code JSentinelDiagnostics.inspect()} genuinely reports the missing
 * criticals — the classpath is the fixture, no doubles.
 */
class DiagnosticsHealthIndicatorTest {

  @Test
  @DisplayName("id() is the stable 'diagnostics' identifier")
  void idIsStable() {
    assertEquals("diagnostics", new DiagnosticsHealthIndicator().id());
    assertEquals(DiagnosticsHealthIndicator.ID, new DiagnosticsHealthIndicator().id());
  }

  @Test
  @DisplayName("missing critical SPIs surface as ERROR diagnostics/missing-service findings")
  void missingCriticalsBecomeErrorFindings() {
    List<HealthFinding> findings = new DiagnosticsHealthIndicator().check();

    List<HealthFinding> missing = findings.stream()
        .filter(f -> DiagnosticsHealthIndicator.MISSING_SERVICE_CODE.equals(f.code()))
        .toList();
    assertFalse(missing.isEmpty(), "bare classpath must report missing critical SPIs");
    assertTrue(missing.stream().allMatch(f -> f.severity() == Severity.ERROR),
        "every missing-service finding is an ERROR");
    assertTrue(missing.stream().anyMatch(f -> f.message().contains("AuthenticationService")),
        "AuthenticationService must be reported missing: " + missing);
    assertTrue(missing.stream().anyMatch(f -> f.message().contains("AuthorizationService")),
        "AuthorizationService must be reported missing: " + missing);
  }

  @Test
  @DisplayName("missing-service messages carry reason and suggested fix from the report record")
  void missingServiceMessagesCarryReasonAndFix() {
    List<HealthFinding> missing = new DiagnosticsHealthIndicator().check().stream()
        .filter(f -> DiagnosticsHealthIndicator.MISSING_SERVICE_CODE.equals(f.code()))
        .toList();
    assertTrue(missing.stream()
            .allMatch(f -> f.message().contains("No implementation discovered via ServiceLoader.")),
        "reason from MissingRecommendedService must be part of the message");
    assertTrue(missing.stream().allMatch(f -> f.message().contains("Suggested fix:")),
        "suggestedFix from MissingRecommendedService must be part of the message");
  }

  @Test
  @DisplayName("report warnings pass their own code through as WARNING findings")
  void reportWarningsPassTheirCodeThrough() {
    // the module's own MonitoringDiagnosticContributor runs inside
    // inspect() and, on this bare classpath, contributes the
    // no-metrics-publisher warning — proving the code pass-through with
    // a genuine report entry
    List<HealthFinding> findings = new DiagnosticsHealthIndicator().check();
    List<HealthFinding> passedThrough = findings.stream()
        .filter(f -> MonitoringDiagnosticContributor.NO_METRICS_PUBLISHER_CODE.equals(f.code()))
        .toList();
    assertEquals(1, passedThrough.size(),
        "the report warning must keep its original code: " + findings);
    assertEquals(Severity.WARNING, passedThrough.get(0).severity());
  }

  @Test
  @DisplayName("every finding carries a non-blank code and message")
  void findingsAreWellFormed() {
    List<HealthFinding> findings = new DiagnosticsHealthIndicator().check();
    assertFalse(findings.isEmpty());
    assertTrue(findings.stream().noneMatch(f -> f.code().isBlank()));
    assertTrue(findings.stream().noneMatch(f -> f.message().isBlank()));
  }
}
