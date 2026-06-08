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

import com.svenruppert.vaadin.security.autoservice.api.SecurityAutoService;
import com.svenruppert.vaadin.security.bruteforce.LoginAttemptPolicy;
import com.svenruppert.vaadin.security.dx.diagnostics.DiagnosticContributor;
import com.svenruppert.vaadin.security.dx.diagnostics.DiagnosticReportBuilder;
import com.svenruppert.vaadin.security.dx.diagnostics.MissingRecommendedService;

import java.util.ServiceLoader;

/**
 * Standalone-side {@link DiagnosticContributor}. Warns when no
 * {@link LoginAttemptPolicy} is registered.
 *
 * @since 00.72.00
 */
@SecurityAutoService(DiagnosticContributor.class)
public final class StandaloneDiagnosticContributor implements DiagnosticContributor {

  public StandaloneDiagnosticContributor() {
  }

  @Override
  public String id() {
    return "standalone";
  }

  @Override
  public void contribute(DiagnosticReportBuilder builder) {
    boolean any = ServiceLoader.load(LoginAttemptPolicy.class).findFirst().isPresent();
    if (!any) {
      builder.addMissing(new MissingRecommendedService(
          LoginAttemptPolicy.class,
          "No LoginAttemptPolicy registered for standalone bootstrap.",
          "Register a LoginAttemptPolicy via @SecurityAutoService(LoginAttemptPolicy.class) "
              + "or StandaloneSecurity.bootstrap().loginAttemptPolicy(...)."));
    }
  }
}
