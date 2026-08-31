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
package eu.jsentinel.jcustos.dx.rest.diagnostics;

import eu.jsentinel.jcustos.autoservice.api.JSentinelAutoService;
import eu.jsentinel.jcustos.dx.diagnostics.DiagnosticContributor;
import eu.jsentinel.jcustos.dx.diagnostics.DiagnosticReportBuilder;
import eu.jsentinel.jcustos.dx.diagnostics.DuplicateService;
import eu.jsentinel.jcustos.dx.diagnostics.MissingRecommendedService;
import eu.jsentinel.jcustos.rest.RestSubjectResolver;

import java.util.ArrayList;
import java.util.List;
import java.util.ServiceLoader;

/**
 * REST-side {@link DiagnosticContributor}. Detects missing or duplicate
 * {@link RestSubjectResolver} implementations through {@code ServiceLoader}.
 *
 * @since 00.72.00
 */
@JSentinelAutoService(DiagnosticContributor.class)
public final class RestDiagnosticContributor implements DiagnosticContributor {

  public RestDiagnosticContributor() {
  }

  @Override
  public String id() {
    return "rest";
  }

  @Override
  public void contribute(DiagnosticReportBuilder builder) {
    List<Class<?>> impls = new ArrayList<>();
    for (RestSubjectResolver r : ServiceLoader.load(RestSubjectResolver.class)) {
      impls.add(r.getClass());
    }
    if (impls.isEmpty()) {
      builder.addMissing(new MissingRecommendedService(
          RestSubjectResolver.class,
          "No RestSubjectResolver registered.",
          "Register a RestSubjectResolver via @JSentinelAutoService(RestSubjectResolver.class) "
              + "or RestSecurity.bootstrap().subjectResolver(...)."));
    } else if (impls.size() > 1) {
      builder.addDuplicate(new DuplicateService(RestSubjectResolver.class, impls));
    }
  }
}
