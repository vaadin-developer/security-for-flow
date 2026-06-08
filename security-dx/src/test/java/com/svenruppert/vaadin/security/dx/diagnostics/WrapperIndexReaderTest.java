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

import com.svenruppert.vaadin.security.dx.diagnostics.fixture.FixtureSourceType;
import com.svenruppert.vaadin.security.dx.diagnostics.fixture.FixtureSourceTypeSecured;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies WrapperIndexReader + SecurityDiagnostics integration. The
 * src/test/resources/META-INF/security-for-flow/generated-wrappers.idx
 * fixture contains one valid entry plus two failure cases.
 */
class WrapperIndexReaderTest {

  @Test
  void inspectsValidWrapperEntry() {
    SecurityServiceReport report = SecurityDiagnostics.inspect();

    boolean found = report.processorReport().wrappers().stream()
        .anyMatch(w -> w.sourceType() == FixtureSourceType.class
            && w.generatedType() == FixtureSourceTypeSecured.class
            && "test-processor".equals(w.processor())
            && "00.11.00".equals(w.proxyBuilderVersion())
            && w.delegatedMethods().contains("doWork"));

    assertTrue(found, "expected valid fixture wrapper entry; got: "
        + report.processorReport().wrappers());
  }

  @Test
  void unknownSourceProducesSecuredWithoutWrapperWarning() {
    SecurityServiceReport report = SecurityDiagnostics.inspect();

    boolean found = report.warnings().stream()
        .anyMatch(w -> "secured-without-wrapper".equals(w.code())
            && w.message().contains("UnknownSourceType"));
    assertTrue(found, "expected secured-without-wrapper warning for unknown source");
  }

  @Test
  void mismatchedWrapperFqnProducesSecuredWithoutWrapperWarning() {
    SecurityServiceReport report = SecurityDiagnostics.inspect();

    boolean found = report.warnings().stream()
        .anyMatch(w -> "secured-without-wrapper".equals(w.code())
            && w.message().contains("java.lang.String")
            && w.message().contains("java.lang.Object"));
    assertTrue(found, "expected mismatch warning for String/Object pair");
  }

  @Test
  void warningsAlsoSurfaceInProcessorReport() {
    SecurityServiceReport report = SecurityDiagnostics.inspect();

    long processorWarnings = report.processorReport().warnings().stream()
        .filter(w -> "secured-without-wrapper".equals(w.code()))
        .count();
    assertTrue(processorWarnings >= 2,
        "expected at least 2 secured-without-wrapper entries in the processor report");
  }

  @Test
  void resourcePathConstantIsStable() {
    assertEquals("META-INF/security-for-flow/generated-wrappers.idx",
        WrapperIndexReader.internalsForTesting().get("path"));
  }
}
