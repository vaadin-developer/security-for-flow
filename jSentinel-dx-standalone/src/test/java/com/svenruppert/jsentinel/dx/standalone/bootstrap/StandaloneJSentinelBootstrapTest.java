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
import com.svenruppert.jsentinel.authorization.api.SubjectStores;
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
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StandaloneJSentinelBootstrapTest {

  @BeforeEach
  @AfterEach
  void resetResolver() {
    JSentinelServiceResolver.setAuthenticationService((AuthenticationService<?, ?>) null);
    JSentinelServiceResolver.setAuthorizationService((AuthorizationService<?>) null);
    JSentinelServiceResolver.setLoginAttemptPolicy(null);
    // R008 wires SubjectStores; clear the cached override so each test starts
    // from the SPI default and overrides don't leak between tests.
    SubjectStores.reset();
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
  void customSubjectStoreIsTheStoreTheResolverReturns() {
    // R008: the bug was that the custom store was reported but never wired,
    // so SubjectStores kept returning the SPI default ThreadLocalSubjectStore.
    InMemorySubjectStore customStore = new InMemorySubjectStore();
    StandaloneSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .subjectStore(customStore)
        .install();

    assertSame(customStore, SubjectStores.subjectStore(),
        "the custom store must be the one the resolver returns after install()");
  }

  @Test
  void defaultSubjectStoreResolvesToTheSpiThreadLocal() {
    // No explicit store: the resolver must fall back to the SPI default, not
    // a leaked override (caller-wins-else-default).
    StandaloneSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .install();

    assertEquals(ThreadLocalSubjectStore.class, SubjectStores.subjectStore().getClass(),
        "without an explicit store the resolver must return the SPI ThreadLocalSubjectStore");
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

  // ── V00.74 A2.3 threadPropagation / interactiveLogin ───────────

  @Test
  void threadPropagation_publishesStrategyAndRuntimeEntry() {
    StandaloneThreadPropagationContext.reset();
    JSentinelRuntime runtime = StandaloneSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .threadPropagation(t -> t.inheritOnSubmit())
        .install();

    ThreadPropagationStrategy s = StandaloneThreadPropagationContext.strategy().orElseThrow();
    assertEquals(ThreadPropagationMode.INHERIT_ON_SUBMIT, s.mode());
    assertTrue(runtime.services().stream()
        .anyMatch(r -> StandaloneThreadPropagationContext.class.equals(r.spi())
            && ThreadPropagationStrategy.class.equals(r.impl())
            && r.source().startsWith("bootstrap-thread-propagation=INHERIT_ON_SUBMIT")));
  }

  @Test
  void threadPropagation_inheritOnSubmit_bindsSubjectOnWorker() throws Exception {
    StandaloneThreadPropagationContext.reset();
    StandaloneSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .subjectStore(new InMemorySubjectStore())
        .threadPropagation(t -> t.inheritOnSubmit())
        .install();

    var subject = new com.svenruppert.jsentinel.authorization.api.JSentinelSubject(
        "alice", "Alice", java.util.Set.of(), java.util.Set.of());
    com.svenruppert.jsentinel.authorization.api.SubjectStores.subjectStore()
        .setCurrentSubject(subject, com.svenruppert.jsentinel.authorization.api.JSentinelSubject.class);

    var pool = java.util.concurrent.Executors.newSingleThreadExecutor();
    try {
      java.util.concurrent.Executor wrapped = StandaloneThreadPropagationContext.wrap(pool);
      java.util.concurrent.CompletableFuture<String> observed = new java.util.concurrent.CompletableFuture<>();
      wrapped.execute(() -> observed.complete(
          com.svenruppert.jsentinel.authorization.api.SubjectStores.findSubjectStore()
              .flatMap(st -> st.currentSubject(
                  com.svenruppert.jsentinel.authorization.api.JSentinelSubject.class))
              .map(com.svenruppert.jsentinel.authorization.api.JSentinelSubject::subjectId)
              .orElse("<unbound>")));
      assertEquals("alice", observed.get(2, java.util.concurrent.TimeUnit.SECONDS));
    } finally {
      pool.shutdownNow();
      com.svenruppert.jsentinel.authorization.api.SubjectStores.subjectStore()
          .deleteCurrentSubject(com.svenruppert.jsentinel.authorization.api.JSentinelSubject.class);
    }
  }

  @Test
  void threadPropagation_default_passthrough() {
    StandaloneThreadPropagationContext.reset();
    java.util.concurrent.Executor pool = java.util.concurrent.Executors.newSingleThreadExecutor();
    java.util.concurrent.Executor wrapped = StandaloneThreadPropagationContext.wrap(pool);
    assertEquals(pool, wrapped, "without published strategy, wrap() must be a pass-through");
  }

  @Test
  void interactiveLogin_publishesConfigurationAndRuntimeEntry() {
    StandaloneInteractiveLoginContext.reset();
    InteractiveLoginPrompt prompt = msg -> new InteractiveLoginPrompt.Credentials(
        "alice", new char[]{'s', 'e', 'c'});
    JSentinelRuntime runtime = StandaloneSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .interactiveLogin(l -> l.prompt(prompt).maxAttempts(3))
        .install();

    InteractiveLoginConfiguration cfg = StandaloneInteractiveLoginContext.configuration().orElseThrow();
    assertEquals(prompt, cfg.prompt());
    assertEquals(3, cfg.maxAttempts());
    assertTrue(runtime.services().stream()
        .anyMatch(r -> StandaloneInteractiveLoginContext.class.equals(r.spi())
            && InteractiveLoginConfiguration.class.equals(r.impl())));
  }

  @Test
  void interactiveLogin_missingPromptRejected() {
    org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,
        () -> StandaloneSecurity.bootstrap()
            .authentication(FakeAuthenticationService.forType(String.class))
            .authorization(new FakeAuthorizationService<String>())
            .interactiveLogin(l -> l.maxAttempts(2))
            .install());
  }

  @Test
  void interactiveLogin_negativeMaxAttemptsRejected() {
    org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
        () -> StandaloneSecurity.bootstrap().interactiveLogin(l -> l.maxAttempts(-1)));
  }

  // ── V00.74.20 P015 mutation-lift: assert resolver state after install() ────

  @Test
  void install_publishesAuthnAuthzToServiceResolver() {
    AuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);
    AuthorizationService<String> authz = new FakeAuthorizationService<>();

    JSentinelRuntime runtime = StandaloneSecurity.bootstrap()
        .authentication(authn)
        .authorization(authz)
        .install();

    assertNotNull(runtime);
    // Kills the VoidMethodCallMutator that drops the
    // JSentinelServiceResolver.setAuthenticationService(...) call inside
    // StandaloneJSentinelBootstrapImpl.install() — if the call is gone,
    // the global resolver returns its empty default and these
    // assertions fail.
    assertEquals(authn, JSentinelServiceResolver.authenticationService(),
        "install() must publish the AuthenticationService to JSentinelServiceResolver");
    assertEquals(authz, JSentinelServiceResolver.authorizationService(),
        "install() must publish the AuthorizationService to JSentinelServiceResolver");
  }
}
