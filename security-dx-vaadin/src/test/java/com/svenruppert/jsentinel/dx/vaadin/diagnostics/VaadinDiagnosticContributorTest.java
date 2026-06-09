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
package com.svenruppert.jsentinel.dx.vaadin.diagnostics;

import com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver;
import com.svenruppert.jsentinel.dx.diagnostics.DiagnosticContributor;
import com.svenruppert.jsentinel.dx.diagnostics.DiagnosticReportBuilder;
import com.svenruppert.jsentinel.dx.diagnostics.DiscoveredService;
import com.svenruppert.jsentinel.dx.diagnostics.DuplicateService;
import com.svenruppert.jsentinel.dx.diagnostics.MissingRecommendedService;
import com.svenruppert.jsentinel.dx.diagnostics.ServiceWarning;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VaadinDiagnosticContributorTest {

  private final VaadinDiagnosticContributor contributor = new VaadinDiagnosticContributor();

  @BeforeEach
  @AfterEach
  void resetResolver() {
    JSentinelServiceResolver.setStepUpRouteName(JSentinelServiceResolver.DEFAULT_STEP_UP_ROUTE_NAME);
  }

  @Test
  void idIsVaadin() {
    assertEquals("vaadin", contributor.id());
  }

  @Test
  void defaultStepUpRouteIsNotBlank_noWarning() {
    Recorder r = new Recorder();
    contributor.contribute(r);
    boolean blankWarning = r.warnings.stream()
        .anyMatch(w -> "vaadin/step-up-route-blank".equals(w.code()));
    assertEquals(false, blankWarning,
        "default step-up route is non-blank; should not emit blank warning");
  }

  /**
   * The contributor must not throw on its own; if the underlying state
   * is inconsistent it should add a "vaadin/rule-failed" warning
   * instead. This test verifies the happy-path call simply runs.
   */
  @Test
  void contributeDoesNotThrowOnDefaultState() {
    Recorder r = new Recorder();
    contributor.contribute(r);
    assertTrue(true);
  }

  @Test
  void implementsDiagnosticContributor() {
    assertTrue(contributor instanceof DiagnosticContributor);
  }

  private static final class Recorder implements DiagnosticReportBuilder {
    final List<ServiceWarning> warnings = new ArrayList<>();

    @Override
    public DiagnosticReportBuilder addDiscovered(DiscoveredService entry) {
      return this;
    }

    @Override
    public DiagnosticReportBuilder addMissing(MissingRecommendedService entry) {
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
