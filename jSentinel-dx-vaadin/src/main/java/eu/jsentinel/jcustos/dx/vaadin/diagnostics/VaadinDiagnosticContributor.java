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
package eu.jsentinel.jcustos.dx.vaadin.diagnostics;

import eu.jsentinel.jcustos.authorization.api.JSentinelServiceResolver;
import eu.jsentinel.jcustos.autoservice.api.JSentinelAutoService;
import eu.jsentinel.jcustos.dx.diagnostics.DiagnosticContributor;
import eu.jsentinel.jcustos.dx.diagnostics.DiagnosticReportBuilder;
import eu.jsentinel.jcustos.dx.diagnostics.ServiceWarning;

/**
 * Vaadin-side {@link DiagnosticContributor}. Adds Vaadin-specific
 * findings to {@code JSentinelDiagnostics.inspect()}.
 * <p>
 * Rules:
 * <ul>
 *   <li>{@code vaadin/step-up-route-blank} — step-up route configured
 *       but the route name is empty/whitespace.</li>
 * </ul>
 * Additional rules (SessionManagementView without SessionStore,
 * {@code @SecureRoute} referencing an unknown policy,
 * {@code subjectType} without store) require a route registry that is
 * not part of the V00.72 surface; they are reserved for V00.73 when
 * the starter's PolicyRegistry hook lands.
 *
 * @since 00.72.00
 */
@JSentinelAutoService(DiagnosticContributor.class)
public final class VaadinDiagnosticContributor implements DiagnosticContributor {

  /** ServiceLoader requires a public no-arg constructor. */
  public VaadinDiagnosticContributor() {
  }

  @Override
  public String id() {
    return "vaadin";
  }

  @Override
  public void contribute(DiagnosticReportBuilder builder) {
    try {
      String stepUp = JSentinelServiceResolver.stepUpRouteName();
      if (stepUp == null || stepUp.isBlank()) {
        builder.addWarning(new ServiceWarning(
            "vaadin/step-up-route-blank",
            "Step-up route name is blank.",
            "Set a non-empty step-up route via VaadinSecurity.bootstrap().stepUpRoute(...)."));
      }
    } catch (RuntimeException e) {
      builder.addWarning(new ServiceWarning(
          "vaadin/rule-failed",
          "step-up-route check failed: " + e.getClass().getSimpleName() + ": " + e.getMessage(),
          "Inspect JSentinelServiceResolver state."));
    }
  }
}
