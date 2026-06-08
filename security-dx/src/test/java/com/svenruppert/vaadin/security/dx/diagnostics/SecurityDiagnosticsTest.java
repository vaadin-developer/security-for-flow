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
package com.svenruppert.vaadin.security.dx.diagnostics;

import com.svenruppert.vaadin.security.authentication.AuthenticationService;
import com.svenruppert.vaadin.security.authorization.api.AuthorizationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecurityDiagnosticsTest {

  @BeforeEach
  void clearRecorder() {
    RecordingContributor.CALL_ORDER.clear();
  }

  @Test
  void noCriticalImplsRegistered_reportsMissing() {
    SecurityServiceReport report = SecurityDiagnostics.inspect();

    assertTrue(report.missing().stream()
            .anyMatch(m -> m.spi() == AuthenticationService.class),
        "expected missing AuthenticationService entry");
    assertTrue(report.missing().stream()
            .anyMatch(m -> m.spi() == AuthorizationService.class),
        "expected missing AuthorizationService entry");
  }

  @Test
  void inspectIsSideEffectFree() {
    SecurityServiceReport first = SecurityDiagnostics.inspect();
    SecurityServiceReport second = SecurityDiagnostics.inspect();

    assertEquals(first.missing().size(), second.missing().size());
    assertEquals(first.discovered().size(), second.discovered().size());
  }

  @Test
  void contributorsAreInvokedInSortedIdOrder() {
    RecordingContributor.CALL_ORDER.clear();
    SecurityDiagnostics.inspect();

    // "aaa-recording" must come before "zzz-throwing"
    assertEquals(2, RecordingContributor.CALL_ORDER.size(),
        "both fixture contributors must run, got " + RecordingContributor.CALL_ORDER);
    assertEquals("aaa-recording", RecordingContributor.CALL_ORDER.get(0));
    assertEquals("zzz-throwing", RecordingContributor.CALL_ORDER.get(1));
  }

  @Test
  void throwingContributorBecomesServiceWarning_othersStillRun() {
    SecurityServiceReport report = SecurityDiagnostics.inspect();

    // recording contributor added a benign warning
    boolean recordingWarning = report.warnings().stream()
        .anyMatch(w -> "test/recording".equals(w.code()));
    assertTrue(recordingWarning, "expected the recording contributor's warning");

    // throwing contributor becomes the documented failure code
    boolean contributorFailure = report.warnings().stream()
        .anyMatch(w -> "diagnostics/contributor-failure".equals(w.code())
            && w.message().contains("zzz-throwing"));
    assertTrue(contributorFailure,
        "expected diagnostics/contributor-failure for the throwing contributor, "
            + "got: " + report.warnings());
  }

  @Test
  void reportListsAreUnmodifiable() {
    SecurityServiceReport report = SecurityDiagnostics.inspect();

    assertFalse(report.processorReport().wrappers() == null);
    try {
      report.warnings().add(new ServiceWarning("a", "b", "c"));
      throw new AssertionError("expected unmodifiable warnings list");
    } catch (UnsupportedOperationException expected) {
      // ok
    }
  }
}
