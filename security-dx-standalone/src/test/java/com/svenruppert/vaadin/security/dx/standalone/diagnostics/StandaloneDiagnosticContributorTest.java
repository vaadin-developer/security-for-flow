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
package com.svenruppert.vaadin.security.dx.standalone.diagnostics;

import com.svenruppert.vaadin.security.bruteforce.LoginAttemptPolicy;
import com.svenruppert.vaadin.security.dx.diagnostics.DiagnosticContributor;
import com.svenruppert.vaadin.security.dx.diagnostics.DiagnosticReportBuilder;
import com.svenruppert.vaadin.security.dx.diagnostics.DiscoveredService;
import com.svenruppert.vaadin.security.dx.diagnostics.DuplicateService;
import com.svenruppert.vaadin.security.dx.diagnostics.MissingRecommendedService;
import com.svenruppert.vaadin.security.dx.diagnostics.ServiceWarning;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StandaloneDiagnosticContributorTest {

  private final StandaloneDiagnosticContributor contributor = new StandaloneDiagnosticContributor();

  @Test
  void idIsStandalone() {
    assertEquals("standalone", contributor.id());
  }

  @Test
  void missingLoginAttemptPolicy_emitsMissingRecommendedService() {
    Recorder r = new Recorder();
    contributor.contribute(r);
    // The test classpath ships no LoginAttemptPolicy via ServiceLoader,
    // so the contributor MUST emit the missing-service entry.
    boolean found = r.missing.stream()
        .anyMatch(m -> m.spi() == LoginAttemptPolicy.class);
    assertTrue(found, "expected MissingRecommendedService for LoginAttemptPolicy, "
        + "got: " + r.missing);
  }

  @Test
  void implementsDiagnosticContributor() {
    assertTrue(contributor instanceof DiagnosticContributor);
  }

  private static final class Recorder implements DiagnosticReportBuilder {
    final List<MissingRecommendedService> missing = new ArrayList<>();
    final List<ServiceWarning> warnings = new ArrayList<>();

    @Override
    public DiagnosticReportBuilder addDiscovered(DiscoveredService entry) {
      return this;
    }

    @Override
    public DiagnosticReportBuilder addMissing(MissingRecommendedService entry) {
      missing.add(entry);
      return this;
    }

    @Override
    public DiagnosticReportBuilder addDuplicate(DuplicateService entry) {
      return this;
    }

    @Override
    public DiagnosticReportBuilder addWarning(ServiceWarning warning) {
      warnings.add(warning);
      return this;
    }
  }
}
