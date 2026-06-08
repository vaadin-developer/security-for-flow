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
package com.svenruppert.vaadin.security.dx.rest.bootstrap;

import com.svenruppert.vaadin.security.authentication.AuthenticationService;
import com.svenruppert.vaadin.security.authorization.api.AuthorizationService;
import com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver;
import com.svenruppert.vaadin.security.authorization.api.SecuritySubject;
import com.svenruppert.vaadin.security.dx.bootstrap.SecurityBootstrapException;
import com.svenruppert.vaadin.security.dx.runtime.RegisteredSecurityService;
import com.svenruppert.vaadin.security.dx.runtime.SecurityBootstrapMode;
import com.svenruppert.vaadin.security.dx.runtime.SecurityRuntime;
import com.svenruppert.vaadin.security.rest.RestRequest;
import com.svenruppert.vaadin.security.rest.RestSubjectResolver;
import com.svenruppert.vaadin.security.test.FakeAuthenticationService;
import com.svenruppert.vaadin.security.test.FakeAuthorizationService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RestSecurityBootstrapTest {

  @BeforeEach
  @AfterEach
  void resetResolver() {
    SecurityServiceResolver.setAuthenticationService((AuthenticationService<?, ?>) null);
    SecurityServiceResolver.setAuthorizationService((AuthorizationService<?>) null);
  }

  private static final RestSubjectResolver TEST_RESOLVER = new RestSubjectResolver() {
    @Override
    public Optional<SecuritySubject> resolveSubject(RestRequest request) {
      return Optional.empty();
    }
  };

  @Test
  void defaultRegistration_listsDecisionMapperAndErrorBodiesAsDefaulted() {
    SecurityRuntime runtime = RestSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .subjectResolver(TEST_RESOLVER)
        .install();

    assertTrue(runtime.warnings().isEmpty(),
        "happy path must have no warnings, got: " + runtime.warnings());

    RegisteredSecurityService mapperEntry = runtime.services().stream()
        .filter(s -> s.spi() == RestDecisionMapper.class)
        .findFirst().orElseThrow();
    assertTrue(mapperEntry.defaulted(), "default mapper must be flagged as defaulted=true");
    assertEquals(DefaultRestDecisionMapper.class, mapperEntry.impl());

    RegisteredSecurityService bodyEntry = runtime.services().stream()
        .filter(s -> s.spi() == RestErrorBodyStrategy.class)
        .findFirst().orElseThrow();
    assertTrue(bodyEntry.defaulted());
  }

  @Test
  void customDecisionMapperOverridesDefault() {
    RestDecisionMapper custom = (decision, response) -> true;

    SecurityRuntime runtime = RestSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .subjectResolver(TEST_RESOLVER)
        .decisionMapper(custom)
        .install();

    RegisteredSecurityService mapperEntry = runtime.services().stream()
        .filter(s -> s.spi() == RestDecisionMapper.class)
        .findFirst().orElseThrow();
    assertEquals(custom.getClass(), mapperEntry.impl());
    assertEquals(false, mapperEntry.defaulted());
  }

  @Test
  void strictMode_missingSubjectResolver_throws() {
    SecurityBootstrapException ex = assertThrows(SecurityBootstrapException.class, () ->
        RestSecurity.bootstrap()
            .mode(SecurityBootstrapMode.STRICT)
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
        strat.bodyFor(new com.svenruppert.vaadin.security.authorization.api.AuthorizationDecision
            .Unauthenticated("test reason")));
    assertEquals("Forbidden",
        strat.bodyFor(new com.svenruppert.vaadin.security.authorization.api.AuthorizationDecision
            .Forbidden("test reason")));
  }

  @Test
  void secondInstallCallThrows() {
    RestSecurityBootstrap b = RestSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .subjectResolver(TEST_RESOLVER);

    SecurityRuntime first = b.install();
    assertSame(SecurityBootstrapMode.COMMUNITY_DEFAULTS, first.mode());
    assertThrows(IllegalStateException.class, b::install);
  }
}
