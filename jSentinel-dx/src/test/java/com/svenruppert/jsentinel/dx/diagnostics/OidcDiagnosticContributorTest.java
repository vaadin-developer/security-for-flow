package com.svenruppert.jsentinel.dx.diagnostics;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("OidcDiagnosticContributor — warns when the nonce check is disabled")
class OidcDiagnosticContributorTest {

  private final OidcDiagnosticContributor contributor = new OidcDiagnosticContributor();

  @BeforeEach
  @AfterEach
  void resetState() {
    OidcDiagnosticState.reset();
  }

  private static final class Recorder implements DiagnosticReportBuilder {
    final List<ServiceWarning> warnings = new ArrayList<>();

    @Override public DiagnosticReportBuilder addDiscovered(DiscoveredService entry) {
      return this;
    }

    @Override public DiagnosticReportBuilder addMissing(MissingRecommendedService entry) {
      return this;
    }

    @Override public DiagnosticReportBuilder addDuplicate(DuplicateService entry) {
      return this;
    }

    @Override public DiagnosticReportBuilder addWarning(ServiceWarning warning) {
      warnings.add(warning);
      return this;
    }

    boolean has(String code) {
      return warnings.stream().anyMatch(w -> code.equals(w.code()));
    }
  }

  @Test
  @DisplayName("id is oidc")
  void idIsOidc() {
    assertEquals("oidc", contributor.id());
  }

  @Test
  @DisplayName("no snapshot -> no findings")
  void noSnapshotNoFindings() {
    Recorder r = new Recorder();
    contributor.contribute(r);
    assertTrue(r.warnings.isEmpty());
  }

  @Test
  @DisplayName("nonce required -> no warning")
  void nonceRequiredNoWarning() {
    OidcDiagnosticState.publish(new OidcDiagnosticState.Snapshot(true, false, false, false));
    Recorder r = new Recorder();
    contributor.contribute(r);
    assertFalse(r.has("oidc/nonce-disabled"));
  }

  @Test
  @DisplayName("nonce disabled -> oidc/nonce-disabled warning")
  void nonceDisabledWarns() {
    OidcDiagnosticState.publish(new OidcDiagnosticState.Snapshot(false, false, false, false));
    Recorder r = new Recorder();
    contributor.contribute(r);
    assertTrue(r.has("oidc/nonce-disabled"));
  }
}
