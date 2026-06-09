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


import java.util.List;
import java.util.Objects;

/**
 * Sub-report covering proxybuilder-generated wrappers. V00.73
 * completes the pipeline: {@code security-processor} writes the
 * index file at compile time, {@link WrapperIndexReader} parses it,
 * and this record carries the result in
 * {@link JSentinelDiagnostics#inspect()}.
 *
 * @since 00.72.00
 */
public record JSentinelProcessorReport(
    List<GeneratedJSentinelWrapper> wrappers,
    List<ProcessorWarning> warnings) {

  public JSentinelProcessorReport {
    Objects.requireNonNull(wrappers, "wrappers");
    Objects.requireNonNull(warnings, "warnings");
    wrappers = List.copyOf(wrappers);
    warnings = List.copyOf(warnings);
  }

  public static JSentinelProcessorReport empty() {
    return new JSentinelProcessorReport(List.of(), List.of());
  }
}
