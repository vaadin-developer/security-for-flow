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

import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.api.AuthorizationEvaluator;
import eu.jsentinel.jcustos.authorization.api.AuthorizationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JCustosDiagnosticsTest {

  @BeforeEach
  void clearRecorder() {
    RecordingContributor.CALL_ORDER.clear();
  }

  @Test
  void noCriticalImplsRegistered_reportsMissing() {
    JCustosServiceReport report = JCustosDiagnostics.inspect();

    assertTrue(report.missing().stream()
            .anyMatch(m -> m.spi() == AuthenticationService.class),
        "expected missing AuthenticationService entry");
    assertTrue(report.missing().stream()
            .anyMatch(m -> m.spi() == AuthorizationService.class),
        "expected missing AuthorizationService entry");
  }

  @Test
  void inspectIsSideEffectFree() {
    JCustosServiceReport first = JCustosDiagnostics.inspect();
    JCustosServiceReport second = JCustosDiagnostics.inspect();

    assertEquals(first.missing().size(), second.missing().size());
    assertEquals(first.discovered().size(), second.discovered().size());
  }

  @Test
  void inspectEnumeratesProviderTypesWithoutConstructingThem() {
    // R030: a registered AuthorizationEvaluator whose ctor records a side
    // effect must NOT be constructed by inspect() — enumeration uses provider
    // types, never instances.
    SideEffectRecordingEvaluator.INSTANTIATIONS.set(0);

    JCustosServiceReport report = JCustosDiagnostics.inspect();

    assertEquals(0, SideEffectRecordingEvaluator.INSTANTIATIONS.get(),
        "inspect() must enumerate provider types without running their constructors");
    assertTrue(report.discovered().stream()
            .anyMatch(d -> d.spi() == AuthorizationEvaluator.class
                && d.impl() == SideEffectRecordingEvaluator.class),
        "the AuthorizationEvaluator impl must still be discovered by class");
  }

  @Test
  void contributorsAreInvokedInSortedIdOrder() {
    RecordingContributor.CALL_ORDER.clear();
    JCustosDiagnostics.inspect();

    // "aaa-recording" must come before "zzz-throwing"
    assertEquals(2, RecordingContributor.CALL_ORDER.size(),
        "both fixture contributors must run, got " + RecordingContributor.CALL_ORDER);
    assertEquals("aaa-recording", RecordingContributor.CALL_ORDER.get(0));
    assertEquals("zzz-throwing", RecordingContributor.CALL_ORDER.get(1));
  }

  @Test
  void throwingContributorBecomesServiceWarning_othersStillRun() {
    JCustosServiceReport report = JCustosDiagnostics.inspect();

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
    JCustosServiceReport report = JCustosDiagnostics.inspect();

    assertFalse(report.processorReport().wrappers() == null);
    try {
      report.warnings().add(new ServiceWarning("a", "b", "c"));
      throw new AssertionError("expected unmodifiable warnings list");
    } catch (UnsupportedOperationException expected) {
      // ok
    }
  }
}
