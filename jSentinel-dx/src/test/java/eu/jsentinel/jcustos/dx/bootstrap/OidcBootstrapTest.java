package eu.jsentinel.jcustos.dx.bootstrap;

import eu.jsentinel.jcustos.dx.internal.AbstractJSentinelBootstrap;
import eu.jsentinel.jcustos.dx.runtime.JSentinelBootstrapWarning;
import eu.jsentinel.jcustos.dx.runtime.RegisteredJSentinelService;
import eu.jsentinel.jcustos.dx.runtime.Severity;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName(".oidc(...) sub-builder recording + STRICT validation (V00.78)")
class OidcBootstrapTest {

  static final class TestBootstrap extends AbstractJSentinelBootstrap<TestBootstrap> {
    final List<RegisteredJSentinelService> services = new ArrayList<>();

    List<JSentinelBootstrapWarning> applyOidc() {
      List<JSentinelBootstrapWarning> warnings = new ArrayList<>();
      applyOidcConfiguration(services, warnings);
      return warnings;
    }
  }

  private static boolean has(List<JSentinelBootstrapWarning> w, String code, Severity sev) {
    return w.stream().anyMatch(x -> x.code().equals(code) && x.severity() == sev);
  }

  @Test
  @DisplayName("an empty .oidc(o -> {}) is silent")
  void emptyIsSilent() {
    assertTrue(new TestBootstrap().oidc(o -> { }).applyOidc().isEmpty());
  }

  @Test
  @DisplayName("missing issuer is a STRICT error")
  void missingIssuer() {
    List<JSentinelBootstrapWarning> w = new TestBootstrap()
        .oidc(o -> o.clientId("app").scope("openid")).applyOidc();
    assertTrue(has(w, "oidc/missing-issuer", Severity.ERROR));
  }

  @Test
  @DisplayName("missing client id is a STRICT error")
  void missingClientId() {
    List<JSentinelBootstrapWarning> w = new TestBootstrap()
        .oidc(o -> o.issuer("https://idp").scope("openid")).applyOidc();
    assertTrue(has(w, "oidc/missing-client-id", Severity.ERROR));
  }

  @Test
  @DisplayName("a scope without openid is a STRICT error (spec violation)")
  void scopeWithoutOpenid() {
    List<JSentinelBootstrapWarning> w = new TestBootstrap()
        .oidc(o -> o.issuer("https://idp").clientId("app").scope("profile")).applyOidc();
    assertTrue(has(w, "oidc/scope-without-openid", Severity.ERROR));
  }

  @Test
  @DisplayName("a non-https, non-loopback redirect URI is a STRICT error")
  void redirectUriNotHttps() {
    List<JSentinelBootstrapWarning> w = new TestBootstrap()
        .oidc(o -> o.issuer("https://idp").clientId("app").scope("openid")
            .redirectUri(URI.create("http://app.example/cb"))).applyOidc();
    assertTrue(has(w, "oidc/redirect-uri-not-https", Severity.ERROR));
  }

  @Test
  @DisplayName("logoutEnabled without a post-logout redirect URI is a STRICT error")
  void logoutWithoutPostLogoutRedirect() {
    List<JSentinelBootstrapWarning> w = new TestBootstrap()
        .oidc(o -> o.issuer("https://idp").clientId("app").scope("openid")
            .logoutEnabled(true)).applyOidc();
    assertTrue(has(w, "oidc/logout-without-post-logout-redirect-uri", Severity.ERROR));
  }

  @Test
  @DisplayName("a complete configuration registers the bootstrap-oidc marker with no errors")
  void completeConfiguration() {
    TestBootstrap b = new TestBootstrap();
    List<JSentinelBootstrapWarning> w = b
        .oidc(o -> o.issuer("https://idp.example/realm").clientId("app")
            .redirectUri(URI.create("https://app.example/callback"))
            .scope("openid", "profile", "email")
            .logoutEnabled(true).postLogoutRedirectUri(URI.create("https://app.example/")))
        .applyOidc();
    assertFalse(w.stream().anyMatch(x -> x.severity() == Severity.ERROR));
    assertTrue(b.services.stream().anyMatch(s -> "bootstrap-oidc".equals(s.source())));
  }
}
