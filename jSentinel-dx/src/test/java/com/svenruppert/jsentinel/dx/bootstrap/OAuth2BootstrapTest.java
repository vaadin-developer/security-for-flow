package com.svenruppert.jsentinel.dx.bootstrap;

import com.svenruppert.jsentinel.dx.internal.AbstractJSentinelBootstrap;
import com.svenruppert.jsentinel.dx.runtime.JSentinelBootstrapMode;
import com.svenruppert.jsentinel.dx.runtime.JSentinelBootstrapWarning;
import com.svenruppert.jsentinel.dx.runtime.RegisteredJSentinelService;
import com.svenruppert.jsentinel.dx.runtime.Severity;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName(".oauth2(...) sub-builder recording + STRICT validation (V00.77)")
class OAuth2BootstrapTest {

  /** Test-only bootstrap exposing the protected OAuth2 apply pass. */
  static final class TestBootstrap extends AbstractJSentinelBootstrap<TestBootstrap> {
    final List<RegisteredJSentinelService> services = new ArrayList<>();

    List<JSentinelBootstrapWarning> applyOauth2() {
      List<JSentinelBootstrapWarning> warnings = new ArrayList<>();
      applyOAuth2Configuration(services, warnings);
      return warnings;
    }
  }

  private static boolean has(List<JSentinelBootstrapWarning> warnings, String code, Severity sev) {
    return warnings.stream().anyMatch(w -> w.code().equals(code) && w.severity() == sev);
  }

  @Test
  @DisplayName("an empty .oauth2(o -> {}) is silent")
  void emptyIsSilent() {
    List<JSentinelBootstrapWarning> warnings = new TestBootstrap().oauth2(o -> { }).applyOauth2();
    assertTrue(warnings.isEmpty(), "empty oauth2 block must not emit findings");
  }

  @Test
  @DisplayName("a configuration without .clientId(...) is a STRICT-class error")
  void missingClientId() {
    List<JSentinelBootstrapWarning> warnings = new TestBootstrap()
        .oauth2(o -> o.tokenEndpoint(URI.create("https://idp.example/token"))).applyOauth2();
    assertTrue(has(warnings, "oauth2/missing-client-id", Severity.ERROR));
  }

  @Test
  @DisplayName("a configuration without .tokenEndpoint(...) is a STRICT-class error")
  void missingTokenEndpoint() {
    List<JSentinelBootstrapWarning> warnings = new TestBootstrap()
        .oauth2(o -> o.clientId("rp").authorizationEndpoint(URI.create("https://idp.example/authorize")))
        .applyOauth2();
    assertTrue(has(warnings, "oauth2/missing-token-endpoint", Severity.ERROR));
  }

  @Test
  @DisplayName("a non-https, non-loopback redirect URI is a STRICT-class error")
  void redirectUriNotHttps() {
    List<JSentinelBootstrapWarning> warnings = new TestBootstrap()
        .oauth2(o -> o.clientId("rp")
            .tokenEndpoint(URI.create("https://idp.example/token"))
            .redirectUri(URI.create("http://app.example/callback"))
            .scope("openid"))
        .applyOauth2();
    assertTrue(has(warnings, "oauth2/redirect-uri-not-https", Severity.ERROR));
  }

  @Test
  @DisplayName("a http://localhost redirect URI is accepted (local development)")
  void loopbackRedirectUriAccepted() {
    List<JSentinelBootstrapWarning> warnings = new TestBootstrap()
        .oauth2(o -> o.clientId("rp")
            .tokenEndpoint(URI.create("https://idp.example/token"))
            .redirectUri(URI.create("http://localhost:8080/callback"))
            .scope("openid"))
        .applyOauth2();
    assertFalse(has(warnings, "oauth2/redirect-uri-not-https", Severity.ERROR),
        "loopback http must be allowed");
  }

  @Test
  @DisplayName("an empty scope set is an INFO finding, not an error")
  void scopeEmptyIsInfo() {
    List<JSentinelBootstrapWarning> warnings = new TestBootstrap()
        .oauth2(o -> o.clientId("rp").tokenEndpoint(URI.create("https://idp.example/token")))
        .applyOauth2();
    assertTrue(has(warnings, "oauth2/scope-empty", Severity.INFO));
    assertFalse(warnings.stream().anyMatch(w -> w.severity() == Severity.ERROR));
  }

  @Test
  @DisplayName("a complete configuration records an OAuth2State service with no errors")
  void completeConfigurationRegisters() {
    TestBootstrap bootstrap = new TestBootstrap();
    List<JSentinelBootstrapWarning> warnings = bootstrap
        .oauth2(o -> o.clientId("rp")
            .authorizationEndpoint(URI.create("https://idp.example/authorize"))
            .tokenEndpoint(URI.create("https://idp.example/token"))
            .redirectUri(URI.create("https://app.example/oauth2/callback"))
            .scope("openid", "profile"))
        .applyOauth2();
    assertFalse(warnings.stream().anyMatch(w -> w.severity() == Severity.ERROR));
    assertTrue(bootstrap.services.stream().anyMatch(s -> "bootstrap-oauth2".equals(s.source())),
        "a complete RP config registers a bootstrap-oauth2 marker service");
  }

  @Test
  @DisplayName("JS-SEC-056: a public client with PKCE disabled is a STRICT-class error")
  void publicClientWithoutPkceIsStrictError() {
    List<JSentinelBootstrapWarning> warnings = new TestBootstrap()
        .mode(JSentinelBootstrapMode.STRICT)
        .oauth2(o -> o.clientId("rp")
            .tokenEndpoint(URI.create("https://idp.example/token"))
            .redirectUri(URI.create("https://app.example/oauth2/callback"))
            .scope("openid")
            .pkceRequired(false)) // public client (no client auth) + PKCE off
        .applyOauth2();
    assertTrue(has(warnings, "oauth2/public-client-without-pkce", Severity.ERROR),
        "STRICT must hard-fail a public client that opted out of PKCE");
  }
}
