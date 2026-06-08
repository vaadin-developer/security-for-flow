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

/**
 * Test-only contributor that records its invocation order and adds a
 * benign warning. Used to verify the contributor invocation path.
 */
public final class RecordingContributor implements DiagnosticContributor {

  public static final java.util.List<String> CALL_ORDER =
      java.util.Collections.synchronizedList(new java.util.ArrayList<>());

  @Override
  public String id() {
    return "aaa-recording";
  }

  @Override
  public void contribute(DiagnosticReportBuilder builder) {
    CALL_ORDER.add(id());
    builder.addWarning(new ServiceWarning(
        "test/recording", "recording contributor ran", "no fix needed"));
  }
}
