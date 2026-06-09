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
package com.svenruppert.jsentinel.dx.diagnostics;


/**
 * Adapter-specific diagnostic contributor.
 * <p>
 * Adapter-DX modules ({@code security-dx-vaadin} / {@code -rest} /
 * {@code -standalone}) ship one implementation each, registered via
 * {@code @JSentinelAutoService(DiagnosticContributor.class)} (or a
 * manual {@code META-INF/services/...} entry). The diagnostics engine
 * discovers them through {@code ServiceLoader} and invokes them in
 * sorted {@link #id()} order so reports are reproducible.
 * <p>
 * Contract:
 * <ul>
 *   <li>No I/O, no network, no class-path scanning.</li>
 *   <li>Must not throw; any thrown exception is caught and emitted as
 *       a {@link ServiceWarning} with code
 *       {@code diagnostics/contributor-failure}.</li>
 *   <li>Must not load other contributors recursively.</li>
 *   <li>May reference only adapter-local SPIs; cross-adapter imports
 *       are forbidden.</li>
 * </ul>
 *
 * @since 00.72.00
 */
public interface DiagnosticContributor {

  /**
   * Stable identifier (e.g. {@code "vaadin"}, {@code "rest"},
   * {@code "standalone"}). Used to determine invocation order.
   */
  String id();

  /**
   * Appends adapter-specific findings to the report builder.
   *
   * @param builder non-null report builder
   */
  void contribute(DiagnosticReportBuilder builder);
}
