package eu.jsentinel.jcustos.monitoring.diagnostics;

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

import eu.jsentinel.jcustos.dx.diagnostics.DiagnosticContributor;
import eu.jsentinel.jcustos.dx.diagnostics.ServiceWarning;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The bare test classpath is the fixture: no
 * {@code JCustosMetricsPublisher} and no
 * {@code JCustosHealthIndicator} is registered via
 * {@code META-INF/services}, so the contributor must warn about both.
 */
class MonitoringDiagnosticContributorTest {

  @Test
  @DisplayName("id() is the stable 'monitoring' identifier")
  void idIsStable() {
    assertEquals("monitoring", new MonitoringDiagnosticContributor().id());
    assertEquals(MonitoringDiagnosticContributor.ID,
        new MonitoringDiagnosticContributor().id());
  }

  @Test
  @DisplayName("bare classpath -> no-metrics-publisher and no-health-indicators warnings")
  void bareClasspathProducesBothWarnings() {
    RecordingDiagnosticReportBuilder recorder = new RecordingDiagnosticReportBuilder();
    new MonitoringDiagnosticContributor().contribute(recorder);

    assertEquals(List.of(), recorder.discovered(),
        "nothing is registered, so nothing may be discovered");
    assertEquals(List.of(), recorder.missing());
    assertEquals(List.of(), recorder.duplicates());

    List<String> codes = recorder.warnings().stream().map(ServiceWarning::code).toList();
    assertEquals(2, codes.size(), "exactly the two no-registration warnings: " + codes);
    assertTrue(codes.contains(MonitoringDiagnosticContributor.NO_METRICS_PUBLISHER_CODE));
    assertTrue(codes.contains(MonitoringDiagnosticContributor.NO_HEALTH_INDICATORS_CODE));
  }

  @Test
  @DisplayName("no-registration warnings carry an actionable suggested fix")
  void warningsCarrySuggestedFix() {
    RecordingDiagnosticReportBuilder recorder = new RecordingDiagnosticReportBuilder();
    new MonitoringDiagnosticContributor().contribute(recorder);
    assertTrue(recorder.warnings().stream()
            .allMatch(w -> w.suggestedFix().contains("META-INF/services")),
        "every warning must point to the META-INF/services registration path");
    assertTrue(recorder.warnings().stream().noneMatch(w -> w.message().isBlank()));
  }

  @Test
  @DisplayName("contribute() never throws, even when invoked repeatedly")
  void contributeNeverThrows() {
    MonitoringDiagnosticContributor contributor = new MonitoringDiagnosticContributor();
    RecordingDiagnosticReportBuilder recorder = new RecordingDiagnosticReportBuilder();
    assertDoesNotThrow(() -> contributor.contribute(recorder));
    assertDoesNotThrow(() -> contributor.contribute(recorder));
  }

  @Test
  @DisplayName("ServiceLoader round-trip: a contributor with id 'monitoring' is discoverable")
  void serviceLoaderRoundTrip() {
    List<DiagnosticContributor> monitoring = new ArrayList<>();
    for (DiagnosticContributor contributor : ServiceLoader.load(DiagnosticContributor.class)) {
      if (MonitoringDiagnosticContributor.ID.equals(contributor.id())) {
        monitoring.add(contributor);
      }
    }
    assertEquals(1, monitoring.size(),
        "exactly one contributor with id 'monitoring' must be registered");
    assertEquals(MonitoringDiagnosticContributor.class, monitoring.get(0).getClass());
  }
}
