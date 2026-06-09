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
package com.svenruppert.vaadin.security.dx.bootstrap;

import com.svenruppert.vaadin.security.authorization.api.JSentinelServiceResolver;
import com.svenruppert.vaadin.security.authorization.api.SubjectIdResolver;
import com.svenruppert.vaadin.security.dx.internal.AbstractJSentinelBootstrap;
import com.svenruppert.vaadin.security.dx.runtime.RegisteredJSentinelService;
import com.svenruppert.vaadin.security.dx.runtime.JSentinelBootstrapMode;
import com.svenruppert.vaadin.security.dx.runtime.JSentinelBootstrapWarning;
import com.svenruppert.vaadin.security.dx.runtime.JSentinelRuntime;
import com.svenruppert.vaadin.security.dx.runtime.Severity;
import com.svenruppert.vaadin.security.logout.SubjectId;
import com.svenruppert.vaadin.security.session.InMemorySessionStore;
import com.svenruppert.vaadin.security.session.JSentinelVersion;
import com.svenruppert.vaadin.security.session.JSentinelVersionKey;
import com.svenruppert.vaadin.security.session.JSentinelVersionStore;
import com.svenruppert.vaadin.security.session.SessionPolicy;
import com.svenruppert.vaadin.security.session.SessionStore;
import com.svenruppert.vaadin.security.session.TimeoutSessionPolicy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * V00.73 session-bootstrap behaviour tests. Tests run against real
 * implementations of {@link SessionStore} / {@link SessionPolicy}
 * etc.; no Mockito.
 */
@DisplayName("SessionBootstrap real surface (V00.73)")
class SessionBootstrapTest {

  @BeforeEach
  @AfterEach
  void resetResolver() {
    JSentinelServiceResolver.resetAll();
  }

  @Test
  @DisplayName("timeout + storeBacked constructs and registers a TimeoutSessionPolicy")
  void timeoutAndStoreConstructsTimeoutPolicy() {
    SessionStore store = new InMemorySessionStore();
    JSentinelRuntime runtime = new VaadinTestBootstrap()
        .sessions(s -> s.storeBacked(store).timeout(Duration.ofMinutes(15)))
        .install();

    SessionPolicy<?> policy = JSentinelServiceResolver.findSessionPolicy().orElseThrow();
    assertInstanceOf(TimeoutSessionPolicy.class, policy);
    assertTrue(runtime.services().stream()
        .anyMatch(s -> SessionPolicy.class.equals(s.spi())));
    assertTrue(runtime.services().stream()
        .anyMatch(s -> SessionStore.class.equals(s.spi())
            && InMemorySessionStore.class.equals(s.impl())));
  }

  @Test
  @DisplayName("custom .policy(...) wins over timeout-derived construction")
  void customPolicyWinsOverTimeout() {
    SessionPolicy<?> custom = new TimeoutSessionPolicy<>();
    new VaadinTestBootstrap()
        .sessions(s -> s.policy(custom).timeout(Duration.ofHours(1)))
        .install();
    SessionPolicy<?> registered = JSentinelServiceResolver.findSessionPolicy().orElseThrow();
    assertSame(custom, registered, "custom policy must not be wrapped or replaced");
  }

  @Test
  @DisplayName(".securityVersion(...) + .subjectIdResolver(...) register both via resolver")
  void securityVersionAndSubjectIdResolverRegister() {
    JSentinelVersionStore vstore = new RecordingVersionStore();
    SubjectIdResolver<String> resolver = subject -> SubjectId.of(subject);
    new VaadinTestBootstrap()
        .sessions(s -> s.securityVersion(vstore).subjectIdResolver(resolver))
        .install();
    assertSame(vstore, JSentinelServiceResolver.findJSentinelVersionStore().orElseThrow());
    Optional<SubjectIdResolver<Object>> found = JSentinelServiceResolver.findSubjectIdResolver();
    assertTrue(found.isPresent());
  }

  @Test
  @DisplayName("STRICT timeout without store throws sessions/missing-store")
  void strictTimeoutWithoutStoreThrows() {
    JSentinelBootstrapException ex = assertThrows(
        JSentinelBootstrapException.class,
        () -> new VaadinTestBootstrap()
            .mode(JSentinelBootstrapMode.STRICT)
            .sessions(s -> s.timeout(Duration.ofMinutes(5)))
            .install());
    assertTrue(ex.warnings().stream()
        .anyMatch(w -> "sessions/missing-store".equals(w.code())));
  }

  @Test
  @DisplayName("STRICT invalid timeout (zero) throws sessions/invalid-timeout")
  void strictInvalidTimeoutThrows() {
    JSentinelBootstrapException ex = assertThrows(
        JSentinelBootstrapException.class,
        () -> new VaadinTestBootstrap()
            .mode(JSentinelBootstrapMode.STRICT)
            .sessions(s -> s.storeBacked(new InMemorySessionStore()).timeout(Duration.ZERO))
            .install());
    assertTrue(ex.warnings().stream()
        .anyMatch(w -> "sessions/invalid-timeout".equals(w.code())));
  }

  @Test
  @DisplayName("STRICT securityVersion without subjectIdResolver throws security-version-without-subject-id-resolver")
  void strictJSentinelVersionWithoutResolverThrows() {
    JSentinelBootstrapException ex = assertThrows(
        JSentinelBootstrapException.class,
        () -> new VaadinTestBootstrap()
            .mode(JSentinelBootstrapMode.STRICT)
            .sessions(s -> s.securityVersion(new RecordingVersionStore()))
            .install());
    assertTrue(ex.warnings().stream()
        .anyMatch(w -> "security-version-without-subject-id-resolver".equals(w.code())));
  }

  @Test
  @DisplayName("standalone .sessions(...) records INFO standalone/sessions-not-applicable")
  void standaloneSessionsRecordsInfo() {
    JSentinelRuntime runtime = new StandaloneTestBootstrap()
        .sessions(s -> s.storeBacked(new InMemorySessionStore()))
        .install();
    assertTrue(runtime.warnings().stream()
        .anyMatch(w -> "standalone/sessions-not-applicable".equals(w.code())
            && w.severity() == Severity.INFO));
    // resolver must not be touched
    assertFalse(JSentinelServiceResolver.findSessionPolicy().isPresent());
  }

  @Test
  @DisplayName("REST .storeBacked(...) records INFO rest/session-store-unused but still wires policy/version")
  void restStoreBackedUnusedButOthersWired() {
    SessionStore store = new InMemorySessionStore();
    JSentinelVersionStore vstore = new RecordingVersionStore();
    SubjectIdResolver<String> resolver = s -> SubjectId.of(s);
    JSentinelRuntime runtime = new RestTestBootstrap()
        .sessions(s -> s.storeBacked(store).securityVersion(vstore).subjectIdResolver(resolver)
            .timeout(Duration.ofMinutes(10)))
        .install();
    assertTrue(runtime.warnings().stream()
        .anyMatch(w -> "rest/session-store-unused".equals(w.code())
            && w.severity() == Severity.INFO));
    assertTrue(JSentinelServiceResolver.findSessionPolicy().isPresent(),
        "REST still wires SessionPolicy/JSentinelVersion/SubjectIdResolver");
  }

  // ── adapter test doubles ─────────────────────────────────────────

  /**
   * Shared install routine for the three test bootstraps. Lives as a
   * static method that subclasses dispatch to via `super`-protected
   * access to the package-private aggregate; the {@link AdapterKind}
   * is the only thing that varies across them.
   */
  private abstract static class BaseTestBootstrap<B extends BaseTestBootstrap<B>>
      extends AbstractJSentinelBootstrap<B> {

    abstract AdapterKind adapterKind();

    @Override
    public JSentinelRuntime install() {
      List<RegisteredJSentinelService> services = new ArrayList<>();
      List<JSentinelBootstrapWarning> warnings = new ArrayList<>();
      applyAuditConfiguration(services, warnings);
      applySessionConfiguration(adapterKind(), services, warnings);
      JSentinelBootstrapMode mode = state.mode();
      boolean strictError = mode == JSentinelBootstrapMode.STRICT
          && warnings.stream().anyMatch(w -> w.severity() == Severity.ERROR);
      if (strictError) {
        throw new JSentinelBootstrapException(warnings);
      }
      return new JSentinelRuntime(services, warnings, mode);
    }
  }

  private static final class VaadinTestBootstrap extends BaseTestBootstrap<VaadinTestBootstrap> {
    @Override AdapterKind adapterKind() { return AdapterKind.VAADIN; }
  }

  private static final class RestTestBootstrap extends BaseTestBootstrap<RestTestBootstrap> {
    @Override AdapterKind adapterKind() { return AdapterKind.REST; }
  }

  private static final class StandaloneTestBootstrap extends BaseTestBootstrap<StandaloneTestBootstrap> {
    @Override AdapterKind adapterKind() { return AdapterKind.STANDALONE; }
  }

  /** Empty JSentinelVersionStore stub — just needs to be a real instance. */
  private static final class RecordingVersionStore implements JSentinelVersionStore {
    private JSentinelVersion version = JSentinelVersion.INITIAL;
    @Override public JSentinelVersion current(JSentinelVersionKey key) { return version; }
    @Override public JSentinelVersion increment(JSentinelVersionKey key) {
      version = version.next();
      return version;
    }
    @Override public void reset(JSentinelVersionKey key) {
      version = JSentinelVersion.INITIAL;
    }
  }
}
