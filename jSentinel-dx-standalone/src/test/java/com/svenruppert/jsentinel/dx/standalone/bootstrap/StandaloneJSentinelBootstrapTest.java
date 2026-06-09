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
package com.svenruppert.jsentinel.dx.standalone.bootstrap;

import com.svenruppert.jsentinel.authentication.AuthenticationService;
import com.svenruppert.jsentinel.authorization.api.AuthorizationService;
import com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver;
import com.svenruppert.jsentinel.authorization.api.SubjectStore;
import com.svenruppert.jsentinel.dx.runtime.RegisteredJSentinelService;
import com.svenruppert.jsentinel.dx.runtime.JSentinelRuntime;
import com.svenruppert.jsentinel.standalone.ThreadLocalSubjectStore;
import com.svenruppert.jsentinel.test.FakeAuthenticationService;
import com.svenruppert.jsentinel.test.FakeAuthorizationService;
import com.svenruppert.jsentinel.test.InMemorySubjectStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StandaloneJSentinelBootstrapTest {

  @BeforeEach
  @AfterEach
  void resetResolver() {
    JSentinelServiceResolver.setAuthenticationService((AuthenticationService<?, ?>) null);
    JSentinelServiceResolver.setAuthorizationService((AuthorizationService<?>) null);
    JSentinelServiceResolver.setLoginAttemptPolicy(null);
  }

  @Test
  void defaultSubjectStoreIsThreadLocal() {
    JSentinelRuntime runtime = StandaloneSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .install();

    RegisteredJSentinelService storeEntry = runtime.services().stream()
        .filter(s -> s.spi() == SubjectStore.class)
        .findFirst().orElseThrow();
    assertEquals(ThreadLocalSubjectStore.class, storeEntry.impl());
    assertTrue(storeEntry.defaulted(), "default ThreadLocalSubjectStore must be flagged defaulted=true");
    assertEquals("bootstrap-default", storeEntry.source());
  }

  @Test
  void customSubjectStoreOverridesDefault() {
    InMemorySubjectStore customStore = new InMemorySubjectStore();
    JSentinelRuntime runtime = StandaloneSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .subjectStore(customStore)
        .install();

    RegisteredJSentinelService storeEntry = runtime.services().stream()
        .filter(s -> s.spi() == SubjectStore.class)
        .findFirst().orElseThrow();
    assertEquals(InMemorySubjectStore.class, storeEntry.impl());
    assertFalse(storeEntry.defaulted());
    assertEquals("bootstrap-explicit", storeEntry.source());
  }

  @Test
  void warningsEmptyOnHappyPath() {
    JSentinelRuntime runtime = StandaloneSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .install();

    assertNotNull(runtime);
    assertTrue(runtime.warnings().isEmpty());
  }
}
