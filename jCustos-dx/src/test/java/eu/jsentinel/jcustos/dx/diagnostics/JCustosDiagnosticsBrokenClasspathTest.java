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

import eu.jsentinel.jcustos.authorization.api.AuthorizationEvaluator;
import eu.jsentinel.jcustos.session.InMemorySessionStore;
import eu.jsentinel.jcustos.session.SessionStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * R09: a broken {@code META-INF/services} entry raises a
 * {@link java.util.ServiceConfigurationError} during enumeration —
 * {@code inspect()} must convert it into a
 * {@code diagnostics/provider-load-failure} warning instead of crashing
 * on exactly the misconfiguration it exists to report, and healthy
 * providers must stay visible.
 */
class JCustosDiagnosticsBrokenClasspathTest {

  @TempDir
  Path tempDir;

  private URLClassLoader loaderWithServicesFile(String spiName, List<String> lines)
      throws IOException {
    Path servicesDir = tempDir.resolve("META-INF").resolve("services");
    Files.createDirectories(servicesDir);
    Files.write(servicesDir.resolve(spiName), lines, StandardCharsets.UTF_8);
    return new URLClassLoader(
        new URL[]{tempDir.toUri().toURL()}, getClass().getClassLoader());
  }

  private static boolean hasProviderLoadFailure(
      JCustosServiceReport report, String spiSimpleName) {
    return report.warnings().stream().anyMatch(w ->
        "diagnostics/provider-load-failure".equals(w.code())
            && w.message().contains(spiSimpleName));
  }

  @Test
  @DisplayName("a missing provider class becomes a warning; healthy SPIs stay reported")
  void brokenEntryBecomesWarningInsteadOfCrash() throws IOException {
    try (URLClassLoader cl = loaderWithServicesFile(
        SessionStore.class.getName(), List.of("com.example.DoesNotExist"))) {

      JCustosServiceReport report = JCustosDiagnostics.inspect(cl);

      assertTrue(hasProviderLoadFailure(report, SessionStore.class.getSimpleName()),
          "expected diagnostics/provider-load-failure naming SessionStore, got: "
              + report.warnings());
      assertTrue(report.discovered().stream().anyMatch(d ->
              d.spi() == AuthorizationEvaluator.class
                  && d.impl() == SideEffectRecordingEvaluator.class),
          "healthy SPIs from the parent classpath must still be reported");
    }
  }

  @Test
  @DisplayName("a healthy provider behind a broken entry in the same file is still discovered")
  void badEntryDoesNotHideHealthyEntryInSameFile() throws IOException {
    try (URLClassLoader cl = loaderWithServicesFile(
        SessionStore.class.getName(),
        List.of("com.example.DoesNotExist", InMemorySessionStore.class.getName()))) {

      JCustosServiceReport report = JCustosDiagnostics.inspect(cl);

      assertTrue(hasProviderLoadFailure(report, SessionStore.class.getSimpleName()),
          "expected diagnostics/provider-load-failure naming SessionStore, got: "
              + report.warnings());
      assertTrue(report.discovered().stream().anyMatch(d ->
              d.spi() == SessionStore.class && d.impl() == InMemorySessionStore.class),
          "the healthy provider behind the broken entry must still be discovered");
    }
  }

  @Test
  @DisplayName("a broken DiagnosticContributor entry becomes a warning; healthy contributors still run")
  void brokenContributorEntryBecomesWarning() throws IOException {
    try (URLClassLoader cl = loaderWithServicesFile(
        DiagnosticContributor.class.getName(), List.of("com.example.MissingContributor"))) {

      JCustosServiceReport report = JCustosDiagnostics.inspect(cl);

      assertTrue(hasProviderLoadFailure(report, DiagnosticContributor.class.getSimpleName()),
          "expected diagnostics/provider-load-failure naming DiagnosticContributor, got: "
              + report.warnings());
      assertTrue(report.warnings().stream().anyMatch(w -> "test/recording".equals(w.code())),
          "the healthy parent-classpath contributor must still contribute");
    }
  }
}
