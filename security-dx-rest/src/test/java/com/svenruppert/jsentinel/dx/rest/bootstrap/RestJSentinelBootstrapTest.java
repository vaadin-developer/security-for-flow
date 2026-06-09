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
}
