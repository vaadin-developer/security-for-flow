package com.svenruppert.jsentinel.dx.bootstrap;

import com.svenruppert.functional.result.Result;
import com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver;
import com.svenruppert.jsentinel.dx.internal.AbstractJSentinelBootstrap;
import com.svenruppert.jsentinel.dx.internal.JwtState;
import com.svenruppert.jsentinel.dx.internal.RecordingJwtBootstrap;
import com.svenruppert.jsentinel.dx.runtime.JSentinelBootstrapMode;
import com.svenruppert.jsentinel.dx.runtime.JSentinelBootstrapWarning;
import com.svenruppert.jsentinel.dx.runtime.RegisteredJSentinelService;
import com.svenruppert.jsentinel.dx.runtime.Severity;
import com.svenruppert.jsentinel.jwt.api.AlgorithmProfile;
import com.svenruppert.jsentinel.jwt.api.JwtValidationError;
import com.svenruppert.jsentinel.jwt.api.JwtValidator;
import com.svenruppert.jsentinel.jwt.api.ValidatedJwt;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName(".jwt(...) sub-builder recording + apply wiring")
class JwtBootstrapTest {

  private static final JwtValidator NOOP_VALIDATOR = compactJwt ->
      Result.failure(new JwtValidationError.MalformedJwt("noop"));

  /** Test-only bootstrap exposing the protected apply pass. */
  static final class TestBootstrap extends AbstractJSentinelBootstrap<TestBootstrap> {
    List<JSentinelBootstrapWarning> applyJwt() {
      List<RegisteredJSentinelService> services = new ArrayList<>();
      List<JSentinelBootstrapWarning> warnings = new ArrayList<>();
      applyJwtConfiguration(services, warnings);
      return warnings;
    }
  }

  @AfterEach
  void reset() {
    JSentinelServiceResolver.setJwtValidator(null);
  }

  private static boolean hasError(List<JSentinelBootstrapWarning> warnings, String code) {
    return warnings.stream().anyMatch(w ->
        w.code().equals(code) && w.severity() == Severity.ERROR);
  }

  private static boolean hasInfo(List<JSentinelBootstrapWarning> warnings, String code) {
    return warnings.stream().anyMatch(w ->
        w.code().equals(code) && w.severity() == Severity.INFO);
  }

  @Test
  @DisplayName("an explicit .validator(...) is installed into the resolver")
  void explicitValidatorInstalled() {
    new TestBootstrap().jwt(j -> j.validator(NOOP_VALIDATOR)).applyJwt();
    assertSame(NOOP_VALIDATOR, JSentinelServiceResolver.findJwtValidator().orElseThrow());
  }

  @Test
  @DisplayName(".validator(...) and .jwksUri(...) together raise at config time")
  void conflictingValidatorConfigRaises() {
    assertThrows(IllegalStateException.class, () ->
        new TestBootstrap().jwt(j -> j.validator(NOOP_VALIDATOR)
            .jwksUri(URI.create("https://idp.example/jwks"))));
  }

  @Test
  @DisplayName(".algorithmProfile(...) and .algorithmAllowList(...) together raise at config time")
  void conflictingAlgorithmConfigRaises() {
    JwtState state = new JwtState();
    RecordingJwtBootstrap b = new RecordingJwtBootstrap(state);
    b.algorithmProfile(AlgorithmProfile.STRICT_MODERN);
    assertThrows(IllegalStateException.class, () ->
        b.algorithmAllowList(AlgorithmProfile.STRICT_MODERN.toAllowList()));
  }

  @Test
  @DisplayName(".jwksUri(...) without a profile or allow-list is a STRICT-class error")
  void jwksUriWithoutAllowListIsError() {
    List<JSentinelBootstrapWarning> warnings = new TestBootstrap()
        .jwt(j -> j.jwksUri(URI.create("https://idp.example/jwks"))).applyJwt();
    assertTrue(hasError(warnings, "jwt/no-algorithm-allow-list"));
  }

  @Test
  @DisplayName("neither .validator(...) nor .jwksUri(...) is a STRICT-class error")
  void missingJwksUriOrValidatorIsError() {
    List<JSentinelBootstrapWarning> warnings = new TestBootstrap()
        .jwt(j -> j.issuer("https://idp.example/")).applyJwt();
    assertTrue(hasError(warnings, "jwt/missing-jwks-uri-or-validator"));
  }

  @Test
  @DisplayName("JS-SEC-005: .jwt(...) without .audience(...) emits the claims/audience-empty INFO")
  void audienceEmptyEmitsInfo() {
    List<JSentinelBootstrapWarning> warnings = new TestBootstrap()
        .jwt(j -> j.jwksUri(URI.create("https://idp.example/jwks"))
            .algorithmAllowList(AlgorithmProfile.STRICT_MODERN.toAllowList())
            .issuer("https://idp.example/"))
        .applyJwt();
    assertTrue(hasInfo(warnings, "claims/audience-empty"));
  }

  @Test
  @DisplayName("JS-SEC-005: .jwt(...) with an .audience(...) does not emit claims/audience-empty")
  void audienceSetSuppressesInfo() {
    List<JSentinelBootstrapWarning> warnings = new TestBootstrap()
        .jwt(j -> j.jwksUri(URI.create("https://idp.example/jwks"))
            .algorithmAllowList(AlgorithmProfile.STRICT_MODERN.toAllowList())
            .issuer("https://idp.example/")
            .audience("rp-client"))
        .applyJwt();
    assertFalse(hasInfo(warnings, "claims/audience-empty"));
  }

  @Test
  @DisplayName("a non-https JWKS URI is a STRICT-class error in STRICT mode")
  void nonHttpsJwksUriIsErrorInStrict() {
    List<JSentinelBootstrapWarning> warnings = new TestBootstrap()
        .mode(JSentinelBootstrapMode.STRICT)
        .jwt(j -> j.jwksUri(URI.create("http://idp.example/jwks"))
            .algorithmProfile(AlgorithmProfile.STRICT_MODERN))
        .applyJwt();
    assertTrue(hasError(warnings, "jwks/uri-not-https"));
  }

  @Test
  @DisplayName("F4: .tokenType(...) is recorded into the JWT state and flows to ClaimExpectations")
  void tokenTypeRecorded() {
    JwtState state = new JwtState();
    new RecordingJwtBootstrap(state).tokenType("at+jwt");
    assertEquals("at+jwt", state.tokenType());
    assertTrue(state.hasAnySelection(),
        "recording a tokenType must mark the .jwt(...) sub-builder as non-empty");
  }

  @Test
  @DisplayName("R11: a non-https JWKS URI is also an ERROR in PRODUCTION mode (was WARNING)")
  void nonHttpsJwksUriIsErrorInProduction() {
    List<JSentinelBootstrapWarning> warnings = new TestBootstrap()
        .mode(JSentinelBootstrapMode.PRODUCTION)
        .jwt(j -> j.jwksUri(URI.create("http://idp.example/jwks"))
            .algorithmProfile(AlgorithmProfile.STRICT_MODERN))
        .applyJwt();
    assertTrue(hasError(warnings, "jwks/uri-not-https"),
        "PRODUCTION must reject a cleartext JWKS trust root, not merely warn");
  }

  @Test
  @DisplayName("R11: a non-https JWKS URI is NOT an error in DEVELOPMENT (loopback http stays allowed)")
  void nonHttpsJwksUriIsNotErrorInDevelopment() {
    List<JSentinelBootstrapWarning> warnings = new TestBootstrap()
        .mode(JSentinelBootstrapMode.DEVELOPMENT)
        .jwt(j -> j.jwksUri(URI.create("http://localhost/jwks"))
            .algorithmProfile(AlgorithmProfile.STRICT_MODERN))
        .applyJwt();
    assertFalse(hasError(warnings, "jwks/uri-not-https"),
        "DEVELOPMENT keeps non-https at INFO so local/loopback IdPs work");
  }

  @Test
  @DisplayName("the jwksUri path needs a JwtValidatorFactory — absent in dx itself (Nimbus-free)")
  void factoryMissingWhenJwtModuleAbsent() {
    // jSentinel-dx does not depend on jSentinel-jwt, so no factory is on the
    // classpath here — proving the DX layer stays JOSE-free.
    List<JSentinelBootstrapWarning> warnings = new TestBootstrap()
        .jwt(j -> j.jwksUri(URI.create("https://idp.example/jwks"))
            .algorithmProfile(AlgorithmProfile.STRICT_MODERN).issuer("https://idp.example/"))
        .applyJwt();
    assertTrue(hasError(warnings, "jwt/factory-missing"));
  }

  @Test
  @DisplayName("the CUSTOM profile without an explicit allow-list fails gracefully, not by exception (RF02)")
  void customProfileFailsGracefully() {
    List<JSentinelBootstrapWarning> warnings = new TestBootstrap()
        .jwt(j -> j.jwksUri(URI.create("https://idp.example/jwks"))
            .algorithmProfile(AlgorithmProfile.CUSTOM))
        .applyJwt();
    assertTrue(hasError(warnings, "jwt/custom-profile-needs-allow-list"));
  }
}
