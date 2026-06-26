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

@DisplayName("OAuth2DiagnosticContributor — warns on PKCE-off public client + uncached introspection")
class OAuth2DiagnosticContributorTest {

  private final OAuth2DiagnosticContributor contributor = new OAuth2DiagnosticContributor();

  @BeforeEach
  @AfterEach
  void resetState() {
    OAuth2DiagnosticState.reset();
  }

  /** Minimal report builder capturing the warnings. */
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
  @DisplayName("id is oauth2")
  void idIsOauth2() {
    assertEquals("oauth2", contributor.id());
  }

  @Test
  @DisplayName("no snapshot → no findings (OAuth2 not configured)")
  void noSnapshotNoFindings() {
    Recorder recorder = new Recorder();
    contributor.contribute(recorder);
    assertTrue(recorder.warnings.isEmpty());
  }

  @Test
  @DisplayName("a public client with PKCE disabled raises oauth2/pkce-required-but-disabled")
  void publicClientPkceOffWarns() {
    OAuth2DiagnosticState.publish(
        new OAuth2DiagnosticState.Snapshot(true, false, false, false));
    Recorder recorder = new Recorder();
    contributor.contribute(recorder);
    assertTrue(recorder.has("oauth2/pkce-required-but-disabled"));
  }

  @Test
  @DisplayName("a confidential client with PKCE off does not raise the PKCE warning")
  void confidentialClientPkceOffNoWarn() {
    OAuth2DiagnosticState.publish(
        new OAuth2DiagnosticState.Snapshot(false, false, false, false));
    Recorder recorder = new Recorder();
    contributor.contribute(recorder);
    assertFalse(recorder.has("oauth2/pkce-required-but-disabled"));
  }

  @Test
  @DisplayName("introspection configured with caching disabled raises oauth2/introspection-cache-disabled")
  void introspectionCacheDisabledWarns() {
    OAuth2DiagnosticState.publish(
        new OAuth2DiagnosticState.Snapshot(false, true, true, true));
    Recorder recorder = new Recorder();
    contributor.contribute(recorder);
    assertTrue(recorder.has("oauth2/introspection-cache-disabled"));
  }
}
