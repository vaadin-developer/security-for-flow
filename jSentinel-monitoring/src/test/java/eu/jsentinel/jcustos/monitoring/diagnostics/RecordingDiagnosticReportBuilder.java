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

import eu.jsentinel.jcustos.dx.diagnostics.DiagnosticReportBuilder;
import eu.jsentinel.jcustos.dx.diagnostics.DiscoveredService;
import eu.jsentinel.jcustos.dx.diagnostics.DuplicateService;
import eu.jsentinel.jcustos.dx.diagnostics.MissingRecommendedService;
import eu.jsentinel.jcustos.dx.diagnostics.ServiceWarning;

import java.util.ArrayList;
import java.util.List;

/**
 * Hand-written {@link DiagnosticReportBuilder} that records every
 * appended entry into plain lists — a real implementation of the dx
 * contract for direct assertions, not a mock.
 */
final class RecordingDiagnosticReportBuilder implements DiagnosticReportBuilder {

  private final List<DiscoveredService> discovered = new ArrayList<>();
  private final List<MissingRecommendedService> missing = new ArrayList<>();
  private final List<DuplicateService> duplicates = new ArrayList<>();
  private final List<ServiceWarning> warnings = new ArrayList<>();

  @Override
  public DiagnosticReportBuilder addDiscovered(DiscoveredService entry) {
    discovered.add(entry);
    return this;
  }

  @Override
  public DiagnosticReportBuilder addMissing(MissingRecommendedService entry) {
    missing.add(entry);
    return this;
  }

  @Override
  public DiagnosticReportBuilder addDuplicate(DuplicateService entry) {
    duplicates.add(entry);
    return this;
  }

  @Override
  public DiagnosticReportBuilder addWarning(ServiceWarning warning) {
    warnings.add(warning);
    return this;
  }

  List<DiscoveredService> discovered() {
    return discovered;
  }

  List<MissingRecommendedService> missing() {
    return missing;
  }

  List<DuplicateService> duplicates() {
    return duplicates;
  }

  List<ServiceWarning> warnings() {
    return warnings;
  }
}
