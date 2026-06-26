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
package com.svenruppert.jsentinel.dx.rest.bootstrap;

import com.svenruppert.jsentinel.authentication.AuthenticationService;
import com.svenruppert.jsentinel.authorization.api.AuthorizationService;
import com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver;
import com.svenruppert.jsentinel.authorization.api.JSentinelSubject;
import com.svenruppert.jsentinel.dx.bootstrap.JSentinelBootstrapException;
import com.svenruppert.jsentinel.dx.runtime.RegisteredJSentinelService;
import com.svenruppert.jsentinel.dx.runtime.JSentinelBootstrapMode;
import com.svenruppert.jsentinel.dx.runtime.JSentinelRuntime;
import com.svenruppert.jsentinel.rest.RestRequest;
import com.svenruppert.jsentinel.rest.RestSubjectResolver;
import com.svenruppert.jsentinel.test.FakeAuthenticationService;
import com.svenruppert.jsentinel.test.FakeAuthorizationService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RestJSentinelBootstrapTest {

  @BeforeEach
  @AfterEach
  void resetResolver() {
    JSentinelServiceResolver.setAuthenticationService((AuthenticationService<?, ?>) null);
    JSentinelServiceResolver.setAuthorizationService((AuthorizationService<?>) null);
  }

  private static final RestSubjectResolver TEST_RESOLVER = new RestSubjectResolver() {
    @Override
    public Optional<JSentinelSubject> resolveSubject(RestRequest request) {
      return Optional.empty();
    }
  };

  @Test
  void defaultRegistration_listsDecisionMapperAndErrorBodiesAsDefaulted() {
    JSentinelRuntime runtime = RestSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .subjectResolver(TEST_RESOLVER)
        .install();

    assertTrue(runtime.warnings().isEmpty(),
        "happy path must have no warnings, got: " + runtime.warnings());

    RegisteredJSentinelService mapperEntry = runtime.services().stream()
        .filter(s -> s.spi() == RestDecisionMapper.class)
        .findFirst().orElseThrow();
    assertTrue(mapperEntry.defaulted(), "default mapper must be flagged as defaulted=true");
    assertEquals(DefaultRestDecisionMapper.class, mapperEntry.impl());

    RegisteredJSentinelService bodyEntry = runtime.services().stream()
        .filter(s -> s.spi() == RestErrorBodyStrategy.class)
        .findFirst().orElseThrow();
    assertTrue(bodyEntry.defaulted());
  }

  @Test
  void customDecisionMapperOverridesDefault() {
    RestDecisionMapper custom = (decision, response) -> true;

    JSentinelRuntime runtime = RestSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .subjectResolver(TEST_RESOLVER)
        .decisionMapper(custom)
        .install();

    RegisteredJSentinelService mapperEntry = runtime.services().stream()
        .filter(s -> s.spi() == RestDecisionMapper.class)
        .findFirst().orElseThrow();
    assertEquals(custom.getClass(), mapperEntry.impl());
    assertEquals(false, mapperEntry.defaulted());
  }

  @Test
  void strictMode_missingSubjectResolver_throws() {
    JSentinelBootstrapException ex = assertThrows(JSentinelBootstrapException.class, () ->
        RestSecurity.bootstrap()
            .mode(JSentinelBootstrapMode.STRICT)
            .authentication(FakeAuthenticationService.forType(String.class))
            .authorization(new FakeAuthorizationService<String>())
            .install());

    assertTrue(ex.warnings().stream()
        .anyMatch(w -> "missing-rest-subject-resolver".equals(w.code())));
  }

  @Test
  void defaultErrorBodyIsGenericString() {
    DefaultRestErrorBodyStrategy strat = new DefaultRestErrorBodyStrategy();
    assertEquals("Unauthorized",
        strat.bodyFor(new com.svenruppert.jsentinel.authorization.api.AuthorizationDecision
            .Unauthenticated("test reason")));
    assertEquals("Forbidden",
        strat.bodyFor(new com.svenruppert.jsentinel.authorization.api.AuthorizationDecision
            .Forbidden("test reason")));
  }

  @Test
  void secondInstallCallThrows() {
    RestJSentinelBootstrap b = RestSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .subjectResolver(TEST_RESOLVER);

    JSentinelRuntime first = b.install();
    assertSame(JSentinelBootstrapMode.COMMUNITY_DEFAULTS, first.mode());
    assertThrows(IllegalStateException.class, b::install);
  }

  // ── V00.74 A2.2 problemJsonErrors / cors / openApiMetadata ─────

  @Test
  void problemJsonErrors_selectsRfc7807Strategy() {
    JSentinelRuntime runtime = RestSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .subjectResolver(TEST_RESOLVER)
        .problemJsonErrors()
        .install();

    RegisteredJSentinelService entry = runtime.services().stream()
        .filter(s -> RestErrorBodyStrategy.class.equals(s.spi()))
        .findFirst()
        .orElseThrow();
    assertEquals(ProblemJsonErrorBodyStrategy.class, entry.impl());
    assertEquals("bootstrap-explicit", entry.source());

    String body = ProblemJsonErrorBodyStrategy.INSTANCE.bodyFor(
        new com.svenruppert.jsentinel.authorization.api.AuthorizationDecision
            .Unauthenticated("nope"));
    assertTrue(body.contains("\"title\":\"Unauthorized\""));
    assertTrue(body.contains("\"status\":401"));
  }

  @Test
  void cors_publishesConfigurationAndRuntimeEntry() {
    RestCorsContext.reset();
    JSentinelRuntime runtime = RestSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .subjectResolver(TEST_RESOLVER)
        .cors(c -> c
            .allowedOrigins("https://app.example.com")
            .allowedMethods("GET", "POST")
            .allowedHeaders("Authorization", "Content-Type")
            .exposedHeaders("X-Total-Count")
            .allowCredentials(true)
            .maxAgeSeconds(3600))
        .install();

    RestCorsConfiguration cfg = RestCorsContext.configuration().orElseThrow();
    assertEquals(java.util.List.of("https://app.example.com"), cfg.allowedOrigins());
    assertEquals(java.util.List.of("GET", "POST"), cfg.allowedMethods());
    assertEquals(java.util.List.of("Authorization", "Content-Type"), cfg.allowedHeaders());
    assertEquals(java.util.List.of("X-Total-Count"), cfg.exposedHeaders());
    assertTrue(cfg.allowCredentials());
    assertEquals(3600L, cfg.maxAgeSeconds());

    assertTrue(runtime.services().stream()
        .anyMatch(s -> RestCorsContext.class.equals(s.spi())
            && RestCorsConfiguration.class.equals(s.impl())
            && "bootstrap-cors".equals(s.source())));
  }

  @Test
  void cors_wildcardWithCredentials_warnsInNonStrict() {
    RestCorsContext.reset();
    JSentinelRuntime runtime = RestSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .subjectResolver(TEST_RESOLVER)
        .cors(c -> c.allowedOrigins("*").allowCredentials(true))
        .install();

    assertTrue(runtime.warnings().stream()
            .anyMatch(w -> "cors/wildcard-with-credentials".equals(w.code())),
        "wildcard origin + credentials must surface a warning, got: " + runtime.warnings());
  }

  @Test
  void cors_wildcardWithCredentials_throwsInStrict() {
    RestCorsContext.reset();
    JSentinelBootstrapException ex = assertThrows(JSentinelBootstrapException.class, () ->
        RestSecurity.bootstrap()
            .mode(JSentinelBootstrapMode.STRICT)
            .authentication(FakeAuthenticationService.forType(String.class))
            .authorization(new FakeAuthorizationService<String>())
            .subjectResolver(TEST_RESOLVER)
            .cors(c -> c.allowedOrigins("*").allowCredentials(true))
            .install());

    assertTrue(ex.warnings().stream()
        .anyMatch(w -> "cors/wildcard-with-credentials".equals(w.code())));
  }

  @Test
  void cors_wildcardWithCredentials_notPublishedInProduction() {
    // R15 (V00.76.10): PRODUCTION records the ERROR warning AND refuses to
    // publish the dangerous credentialed-wildcard config live — CORS stays
    // unconfigured (the safe default), mirroring the JWKS PRODUCTION refusal.
    RestCorsContext.reset();
    JSentinelRuntime runtime = RestSecurity.bootstrap()
        .mode(JSentinelBootstrapMode.PRODUCTION)
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .subjectResolver(TEST_RESOLVER)
        .cors(c -> c.allowedOrigins("*").allowCredentials(true))
        .install();

    assertTrue(runtime.warnings().stream()
            .anyMatch(w -> "cors/wildcard-with-credentials".equals(w.code())),
        "PRODUCTION must still surface the credentialed-wildcard warning");
    assertTrue(RestCorsContext.configuration().isEmpty(),
        "PRODUCTION must NOT publish the dangerous credentialed-wildcard config live");
  }

  @Test
  void cors_explicitOriginWithCredentials_publishedInProduction() {
    // Control: a credentialed config with explicit origins (no wildcard) is
    // valid and must still publish in PRODUCTION.
    RestCorsContext.reset();
    RestSecurity.bootstrap()
        .mode(JSentinelBootstrapMode.PRODUCTION)
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .subjectResolver(TEST_RESOLVER)
        .cors(c -> c.allowedOrigins("https://app.example.com").allowCredentials(true))
        .install();

    assertTrue(RestCorsContext.configuration().isPresent(),
        "explicit-origin credentialed CORS must still publish in PRODUCTION");
  }

  @Test
  void openApiMetadata_publishesAndRuntimeEntry() {
    RestOpenApiContext.reset();
    JSentinelRuntime runtime = RestSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .subjectResolver(TEST_RESOLVER)
        .openApiMetadata(o -> o
            .title("Demo REST API")
            .version("0.74.0")
            .description("Demo endpoints secured by jSentinel.")
            .servers("https://api.example.com"))
        .install();

    RestOpenApiMetadata meta = RestOpenApiContext.metadata().orElseThrow();
    assertEquals("Demo REST API", meta.title());
    assertEquals("0.74.0", meta.version());
    assertEquals("Demo endpoints secured by jSentinel.", meta.description());
    assertEquals(java.util.List.of("https://api.example.com"), meta.servers());

    assertTrue(runtime.services().stream()
        .anyMatch(s -> RestOpenApiContext.class.equals(s.spi())
            && RestOpenApiMetadata.class.equals(s.impl())
            && "bootstrap-openapi-metadata".equals(s.source())));
  }

  @Test
  void openApiMetadata_blankTitleRejected() {
    assertThrows(IllegalArgumentException.class,
        () -> RestSecurity.bootstrap().openApiMetadata(o -> o.title("   ")));
  }

  @Test
  void cors_nullConsumerRejected() {
    assertThrows(NullPointerException.class,
        () -> RestSecurity.bootstrap().cors(null));
  }
}
