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
package eu.jsentinel.jcustos.propagation.diagnostics;

import eu.jsentinel.jcustos.authorization.api.JSentinelServiceResolver;
import eu.jsentinel.jcustos.credential.propagation.InMemoryTokenCredentialStore;
import eu.jsentinel.jcustos.credential.propagation.TokenCredential;
import eu.jsentinel.jcustos.credential.propagation.TokenCredentialStore;
import eu.jsentinel.jcustos.credential.propagation.ThreadSafeTokenCredentialStore;
import eu.jsentinel.jcustos.dx.diagnostics.DiagnosticReportBuilder;
import eu.jsentinel.jcustos.dx.diagnostics.DiscoveredService;
import eu.jsentinel.jcustos.dx.diagnostics.DuplicateService;
import eu.jsentinel.jcustos.dx.diagnostics.MissingRecommendedService;
import eu.jsentinel.jcustos.dx.diagnostics.ServiceWarning;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("PropagationDiagnosticContributor — V00.74 §13.2 codes")
class PropagationDiagnosticContributorTest {

  private final PropagationDiagnosticContributor contributor =
      new PropagationDiagnosticContributor();

  @BeforeEach @AfterEach
  void resetResolver() { JSentinelServiceResolver.resetAll(); }

  @Test
  @DisplayName("id() returns \"propagation\"")
  void idStable() {
    assertEquals("propagation", contributor.id());
  }

  @Test
  @DisplayName("No store registered → propagation/missing-credential-store")
  void missingCredentialStore() {
    RecordingBuilder builder = new RecordingBuilder();
    contributor.contribute(builder);
    assertTrue(builder.warnings.stream()
            .anyMatch(w -> "propagation/missing-credential-store".equals(w.code())),
        "expected propagation/missing-credential-store; got: " + builder.warnings);
  }

  @Test
  @DisplayName("ThreadSafe store registered → no store-not-thread-safe warning")
  void threadSafeStoreSilent() {
    JSentinelServiceResolver.setTokenCredentialStore(new ThreadSafeStub());
    RecordingBuilder builder = new RecordingBuilder();
    contributor.contribute(builder);
    assertFalse(builder.warnings.stream()
            .anyMatch(w -> "propagation/store-not-thread-safe".equals(w.code())),
        "ThreadSafe store must not produce store-not-thread-safe warning");
    assertFalse(builder.warnings.stream()
            .anyMatch(w -> "propagation/missing-credential-store".equals(w.code())));
  }

  @Test
  @DisplayName("Non-thread-safe store → propagation/store-not-thread-safe")
  void nonThreadSafeStoreWarns() {
    JSentinelServiceResolver.setTokenCredentialStore(new InMemoryTokenCredentialStore());
    RecordingBuilder builder = new RecordingBuilder();
    contributor.contribute(builder);
    assertTrue(builder.warnings.stream()
            .anyMatch(w -> "propagation/store-not-thread-safe".equals(w.code())),
        "expected propagation/store-not-thread-safe for InMemoryTokenCredentialStore");
  }

  // ── helpers ─────────────────────────────────────────────────

  private static final class RecordingBuilder implements DiagnosticReportBuilder {
    final List<ServiceWarning> warnings = new ArrayList<>();
    @Override public DiagnosticReportBuilder addDiscovered(DiscoveredService entry) { return this; }
    @Override public DiagnosticReportBuilder addMissing(MissingRecommendedService entry) { return this; }
    @Override public DiagnosticReportBuilder addDuplicate(DuplicateService entry) { return this; }
    @Override public DiagnosticReportBuilder addWarning(ServiceWarning warning) {
      warnings.add(warning); return this;
    }
  }

  private static final class ThreadSafeStub
      implements TokenCredentialStore, ThreadSafeTokenCredentialStore {
    @Override public void bind(TokenCredential credential) { }
    @Override public Optional<TokenCredential> current() { return Optional.empty(); }
    @Override public void clear() { }
  }
}
