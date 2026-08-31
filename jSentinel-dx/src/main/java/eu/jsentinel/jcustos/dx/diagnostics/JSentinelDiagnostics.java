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
import eu.jsentinel.jcustos.authorization.api.AccessEvaluator;
import eu.jsentinel.jcustos.authorization.api.AuthorizationEvaluator;
import eu.jsentinel.jcustos.authorization.api.AuthorizationService;
import eu.jsentinel.jcustos.authorization.api.SubjectIdResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStore;
import eu.jsentinel.jcustos.session.JSentinelVersionStore;
import eu.jsentinel.jcustos.session.SessionStore;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.function.Consumer;

/**
 * Standalone diagnostic API for the V00.72 DX layer. May be invoked at
 * any time, with or without a prior {@code install()} call.
 * <p>
 * Sweep:
 * <ol>
 *   <li>Enumerate core-visible SPIs through {@link ServiceLoader} and
 *       record discovered / missing / duplicate entries. A broken
 *       {@code META-INF/services} entry (missing or non-assignable
 *       class) surfaces as a
 *       {@code "diagnostics/provider-load-failure"} warning instead of
 *       aborting the sweep — one bad entry does not hide the healthy
 *       ones.</li>
 *   <li>Apply core detection rules (missing-authentication-service,
 *       missing-authorization-service, duplicates,
 *       security-version-without-subject-id-resolver).</li>
 *   <li>Discover {@link DiagnosticContributor}s via {@code ServiceLoader}
 *       (broken registrations become
 *       {@code "diagnostics/provider-load-failure"} warnings too),
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
    return inspect(cl);
  }

  /**
   * Test / injection seam: runs the sweep against the supplied loader
   * instead of the thread context ClassLoader.
   */
  static JSentinelServiceReport inspect(ClassLoader cl) {
    InternalBuilder builder = new InternalBuilder();

    // 1. core SPI sweep
    for (Class<?> spi : CORE_SPIS) {
      List<Class<?>> impls = enumerate(spi, cl, builder);
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
    drainResilient(ServiceLoader.load(DiagnosticContributor.class, cl).iterator(),
        DiagnosticContributor.class, contributors::add, builder);
    contributors.sort(Comparator.comparing(JSentinelDiagnostics::safeContributorId));
    for (DiagnosticContributor c : contributors) {
      try {
        c.contribute(builder);
      } catch (RuntimeException | Error e) {
        builder.addWarning(new ServiceWarning(
            "diagnostics/contributor-failure",
            "Contributor '" + safeContributorId(c) + "' failed: "
                + e.getClass().getSimpleName() + ": " + e.getMessage(),
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

  private static List<Class<?>> enumerate(Class<?> spi, ClassLoader cl, InternalBuilder builder) {
    // R030: iterating ServiceLoader instantiates every provider (running its
    // constructor), which violates inspect()'s side-effect-free contract.
    // stream() + Provider.type() yields the implementation CLASS without
    // constructing it. Dedupe by class so a class listed more than once under
    // the same SPI is counted once (only genuinely distinct impls drive the
    // duplicate-service rule).
    LinkedHashSet<Class<?>> distinct = new LinkedHashSet<>();
    drainResilient(ServiceLoader.load(spi, cl).stream().iterator(),
        spi, provider -> distinct.add(provider.type()), builder);
    return new ArrayList<>(distinct);
  }

  /**
   * R09: drains a {@code ServiceLoader} iterator with a per-element
   * try/catch so a broken {@code META-INF/services} entry (missing class,
   * non-assignable class, missing no-arg constructor, …) becomes a
   * {@code "diagnostics/provider-load-failure"} warning instead of a
   * {@link ServiceConfigurationError} crashing the sweep. The JDK lookup
   * iterator consumes the offending entry before it throws, so retrying
   * resumes with the next entry and healthy providers behind a broken one
   * are still collected. If the exact same failure message repeats, the
   * loader is not advancing — stop instead of spinning (the warning is
   * already recorded, and everything collected so far is kept).
   */
  private static <T> void drainResilient(Iterator<? extends T> source, Class<?> spi,
      Consumer<? super T> collector, InternalBuilder builder) {
    Set<String> seenFailures = new LinkedHashSet<>();
    while (true) {
      try {
        if (!source.hasNext()) {
          return;
        }
        collector.accept(source.next());
      } catch (ServiceConfigurationError e) {
        if (!seenFailures.add(String.valueOf(e.getMessage()))) {
          return;
        }
        builder.addWarning(new ServiceWarning(
            "diagnostics/provider-load-failure",
            "A " + spi.getSimpleName() + " provider failed to load: " + e.getMessage(),
            "Remove or correct the broken META-INF/services/" + spi.getName() + " entry."));
      }
    }
  }

  /**
   * R09: a contributor whose {@code id()} throws (or returns {@code null})
   * must neither kill the deterministic sort nor the failure-report path —
   * fall back to the implementation class name.
   */
  private static String safeContributorId(DiagnosticContributor c) {
    try {
      String id = c.id();
      return id == null ? c.getClass().getName() : id;
    } catch (RuntimeException | Error e) {
      return c.getClass().getName();
    }
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
