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
package eu.jsentinel.jcustos.dx.standalone.diagnostics;

import eu.jsentinel.jcustos.autoservice.api.JSentinelAutoService;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptPolicy;
import eu.jsentinel.jcustos.dx.diagnostics.DiagnosticContributor;
import eu.jsentinel.jcustos.dx.diagnostics.DiagnosticReportBuilder;
import eu.jsentinel.jcustos.dx.diagnostics.MissingRecommendedService;

import java.util.ServiceLoader;

/**
 * Standalone-side {@link DiagnosticContributor}. Warns when no
 * {@link LoginAttemptPolicy} is registered.
 *
 * @since 00.72.00
 */
@JSentinelAutoService(DiagnosticContributor.class)
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
          "Register a LoginAttemptPolicy via @JSentinelAutoService(LoginAttemptPolicy.class) "
              + "or StandaloneSecurity.bootstrap().loginAttemptPolicy(...)."));
    }
  }
}
