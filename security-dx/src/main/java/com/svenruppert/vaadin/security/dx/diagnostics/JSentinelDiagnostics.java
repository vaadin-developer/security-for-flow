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
import com.svenruppert.vaadin.security.authorization.api.AccessEvaluator;
import com.svenruppert.vaadin.security.authorization.api.AuthorizationEvaluator;
import com.svenruppert.vaadin.security.authorization.api.AuthorizationService;
import com.svenruppert.vaadin.security.authorization.api.SubjectIdResolver;
import com.svenruppert.vaadin.security.authorization.api.SubjectStore;
import com.svenruppert.vaadin.security.session.JSentinelVersionStore;
import com.svenruppert.vaadin.security.session.SessionStore;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.ServiceLoader;
import java.util.Set;

/**
 * Standalone diagnostic API for the V00.72 DX layer. May be invoked at
 * any time, with or without a prior {@code install()} call.
 * <p>
 * Sweep:
 * <ol>
 *   <li>Enumerate core-visible SPIs through {@link ServiceLoader} and
 *       record discovered / missing / duplicate entries.</li>
 *   <li>Apply core detection rules (missing-authentication-service,
 *       missing-authorization-service, duplicates,
 *       security-version-without-subject-id-resolver).</li>
 *   <li>Discover {@link DiagnosticContributor}s via {@code ServiceLoader},
 *       invoke each in sorted {@link DiagnosticContributor#id()} order,
 *       and catch any throwable as a
 *       {@code "diagnostics/contributor-failure"} warning.</li>
 * </ol>
 * <p>
 * Side-effect free: never calls service methods, never instantiates
 * anything beyond what {@code ServiceLoader} already does.
 *
 * @since 00.72.00
 */
public final class JSentinelDiagnostics {

  private static final List<Class<?>> CORE_SPIS = List.of(
      AuthenticationService.class,
      AuthorizationService.class,
      SubjectStore.class,
      SubjectIdResolver.class,
      AccessEvaluator.class,
      AuthorizationEvaluator.class,
      JSentinelVersionStore.class,
      SessionStore.class);

  private static final Set<Class<?>> CRITICAL = Set.of(
      AuthenticationService.class, AuthorizationService.class);

  private JSentinelDiagnostics() {
  }

  /**
   * @return a fresh diagnostic report
   */
  public static JSentinelServiceReport inspect() {
    ClassLoader cl = Thread.currentThread().getContextClassLoader();
    if (cl == null) {
      cl = JSentinelDiagnostics.class.getClassLoader();
    }

    InternalBuilder builder = new InternalBuilder();

    // 1. core SPI sweep
    for (Class<?> spi : CORE_SPIS) {
      List<Class<?>> impls = enumerate(spi, cl);
      String loaderStr = cl.toString();

      for (Class<?> impl : impls) {
        builder.addDiscovered(new DiscoveredService(spi, impl, loaderStr));
      }

      if (impls.isEmpty() && CRITICAL.contains(spi)) {
        builder.addMissing(new MissingRecommendedService(
            spi,
            "No implementation discovered via ServiceLoader.",
            "Register an implementation via @JSentinelAutoService(" + spi.getSimpleName()
                + ".class) or add a META-INF/services/" + spi.getName() + " entry."));
      }
      if (impls.size() > 1) {
        builder.addDuplicate(new DuplicateService(spi, impls));
        builder.addWarning(new ServiceWarning(
            "duplicate-service",
            "Multiple " + spi.getSimpleName() + " implementations registered: "
                + summarise(impls),
            "Ensure exactly one implementation per SPI, or select one explicitly."));
      }
    }

    // 2. derived rule: JSentinelVersionStore present but SubjectIdResolver missing
    boolean hasVersionStore = builder.discovered.stream()
        .anyMatch(d -> d.spi() == JSentinelVersionStore.class);
    boolean hasSubjectIdResolver = builder.discovered.stream()
        .anyMatch(d -> d.spi() == SubjectIdResolver.class);
    if (hasVersionStore && !hasSubjectIdResolver) {
      builder.addWarning(new ServiceWarning(
          "security-version-without-subject-id-resolver",
          "JSentinelVersionStore is registered, but no SubjectIdResolver was found.",
          "Register a SubjectIdResolver via @JSentinelAutoService("
              + "SubjectIdResolver.class) so version-drift detection can identify subjects."));
    }

    // 3. adapter contributors
    List<DiagnosticContributor> contributors = new ArrayList<>();
    for (DiagnosticContributor c : ServiceLoader.load(DiagnosticContributor.class, cl)) {
      contributors.add(c);
    }
    contributors.sort(Comparator.comparing(DiagnosticContributor::id));
    for (DiagnosticContributor c : contributors) {
      try {
        c.contribute(builder);
      } catch (RuntimeException | Error e) {
        builder.addWarning(new ServiceWarning(
            "diagnostics/contributor-failure",
            "Contributor '" + c.id() + "' failed: " + e.getClass().getSimpleName()
                + ": " + e.getMessage(),
            "Inspect the contributor implementation; it must not throw."));
      }
    }

    // 4. proxybuilder wrapper index — V00.72 Prompts 020-022
    builder.processorReport = WrapperIndexReader.read(cl);
    for (ProcessorWarning pw : builder.processorReport.warnings()) {
      builder.addWarning(new ServiceWarning(
          pw.code(), pw.message(), pw.suggestedFix()));
    }

    return builder.build();
  }

  private static List<Class<?>> enumerate(Class<?> spi, ClassLoader cl) {
    List<Class<?>> impls = new ArrayList<>();
    for (Object instance : ServiceLoader.load(spi, cl)) {
      impls.add(instance.getClass());
    }
    return impls;
  }

  private static String summarise(List<Class<?>> impls) {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < impls.size(); i++) {
      if (i > 0) {
        sb.append(", ");
      }
      sb.append(impls.get(i).getName());
    }
    return sb.toString();
  }

  private static final class InternalBuilder implements DiagnosticReportBuilder {
    private final List<DiscoveredService> discovered = new ArrayList<>();
    private final List<MissingRecommendedService> missing = new ArrayList<>();
    private final List<DuplicateService> duplicates = new ArrayList<>();
    private final List<ServiceWarning> warnings = new ArrayList<>();

    @Override
    public DiagnosticReportBuilder addDiscovered(DiscoveredService entry) {
      discovered.add(entry);
      return this;
    }

    @Override
    public DiagnosticReportBuilder addMissing(MissingRecommendedService entry) {
      missing.add(entry);
      return this;
    }

    @Override
    public DiagnosticReportBuilder addDuplicate(DuplicateService entry) {
      duplicates.add(entry);
      return this;
    }

    @Override
    public DiagnosticReportBuilder addWarning(ServiceWarning warning) {
      warnings.add(warning);
      return this;
    }

    JSentinelProcessorReport processorReport;

    JSentinelServiceReport build() {
      return new JSentinelServiceReport(
          discovered, missing, duplicates, warnings,
          processorReport == null ? JSentinelProcessorReport.empty() : processorReport);
    }
  }
}
