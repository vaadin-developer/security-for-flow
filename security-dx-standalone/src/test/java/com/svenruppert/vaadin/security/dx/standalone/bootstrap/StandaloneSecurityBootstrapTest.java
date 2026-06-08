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
package com.svenruppert.vaadin.security.dx.standalone.bootstrap;

import com.svenruppert.vaadin.security.authentication.AuthenticationService;
import com.svenruppert.vaadin.security.authorization.api.AuthorizationService;
import com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver;
import com.svenruppert.vaadin.security.authorization.api.SubjectStore;
import com.svenruppert.vaadin.security.dx.runtime.RegisteredSecurityService;
import com.svenruppert.vaadin.security.dx.runtime.SecurityRuntime;
import com.svenruppert.vaadin.security.standalone.ThreadLocalSubjectStore;
import com.svenruppert.vaadin.security.test.FakeAuthenticationService;
import com.svenruppert.vaadin.security.test.FakeAuthorizationService;
import com.svenruppert.vaadin.security.test.InMemorySubjectStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StandaloneSecurityBootstrapTest {

  @BeforeEach
  @AfterEach
  void resetResolver() {
    SecurityServiceResolver.setAuthenticationService((AuthenticationService<?, ?>) null);
    SecurityServiceResolver.setAuthorizationService((AuthorizationService<?>) null);
    SecurityServiceResolver.setLoginAttemptPolicy(null);
  }

  @Test
  void defaultSubjectStoreIsThreadLocal() {
    SecurityRuntime runtime = StandaloneSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .install();

    RegisteredSecurityService storeEntry = runtime.services().stream()
        .filter(s -> s.spi() == SubjectStore.class)
        .findFirst().orElseThrow();
    assertEquals(ThreadLocalSubjectStore.class, storeEntry.impl());
    assertTrue(storeEntry.defaulted(), "default ThreadLocalSubjectStore must be flagged defaulted=true");
    assertEquals("bootstrap-default", storeEntry.source());
  }

  @Test
  void customSubjectStoreOverridesDefault() {
    InMemorySubjectStore customStore = new InMemorySubjectStore();
    SecurityRuntime runtime = StandaloneSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .subjectStore(customStore)
        .install();

    RegisteredSecurityService storeEntry = runtime.services().stream()
        .filter(s -> s.spi() == SubjectStore.class)
        .findFirst().orElseThrow();
    assertEquals(InMemorySubjectStore.class, storeEntry.impl());
    assertFalse(storeEntry.defaulted());
    assertEquals("bootstrap-explicit", storeEntry.source());
  }

  @Test
  void warningsEmptyOnHappyPath() {
    SecurityRuntime runtime = StandaloneSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .install();

    assertNotNull(runtime);
    assertTrue(runtime.warnings().isEmpty());
  }
}
