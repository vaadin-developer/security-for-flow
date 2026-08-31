/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.dx.diagnostics;


import java.util.List;
import java.util.Objects;

/**
 * Aggregate diagnostic report produced by {@link JCustosDiagnostics#inspect()}.
 *
 * @since 00.72.00
 */
public record JCustosServiceReport(
    List<DiscoveredService> discovered,
    List<MissingRecommendedService> missing,
    List<DuplicateService> duplicates,
    List<ServiceWarning> warnings,
    JCustosProcessorReport processorReport) {

  public JCustosServiceReport {
    Objects.requireNonNull(discovered, "discovered");
    Objects.requireNonNull(missing, "missing");
    Objects.requireNonNull(duplicates, "duplicates");
    Objects.requireNonNull(warnings, "warnings");
    Objects.requireNonNull(processorReport, "processorReport");
    discovered = List.copyOf(discovered);
    missing = List.copyOf(missing);
    duplicates = List.copyOf(duplicates);
    warnings = List.copyOf(warnings);
  }
}
