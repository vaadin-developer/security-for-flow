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

import com.svenruppert.vaadin.security.audit.AuditEnvelope;
import com.svenruppert.vaadin.security.audit.AuditEvent;
import com.svenruppert.vaadin.security.audit.AuditEventStore;
import com.svenruppert.vaadin.security.audit.AuditQuery;
import com.svenruppert.vaadin.security.audit.CompositeAuditService;
import com.svenruppert.vaadin.security.audit.LoginSucceeded;
import com.svenruppert.vaadin.security.audit.SecurityAuditService;
import com.svenruppert.vaadin.security.audit.StoreBackedSecurityAuditService;
import com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver;
import com.svenruppert.vaadin.security.authorization.api.tenant.TenantId;
import com.svenruppert.vaadin.security.dx.internal.AbstractSecurityBootstrap;
import com.svenruppert.vaadin.security.dx.runtime.RegisteredSecurityService;
import com.svenruppert.vaadin.security.dx.runtime.SecurityBootstrapMode;
import com.svenruppert.vaadin.security.dx.runtime.SecurityBootstrapWarning;
import com.svenruppert.vaadin.security.dx.runtime.SecurityRuntime;
import com.svenruppert.vaadin.security.dx.runtime.Severity;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * V00.73 audit-bootstrap behaviour tests. Drives the real adapter
 * (concrete subclass {@link TestAuditOnlyBootstrap} below) so audit
 * state actually reaches the {@code SecurityServiceResolver}. No
 * Mockito — fake stores are real implementations.
 */
@DisplayName("AuditBootstrap real surface (V00.73)")
class AuditBootstrapTest {

  @BeforeEach
  @AfterEach
  void resetResolver() {
    SecurityServiceResolver.resetAll();
  }

  @Test
  @DisplayName(".storeBacked(store) registers a StoreBackedSecurityAuditService")
  void storeBackedRegistersStoreBackedService() {
    AuditEventStore store = new InMemoryAuditEventStore();
    SecurityRuntime runtime = new TestAuditOnlyBootstrap()
        .audit(a -> a.storeBacked(store))
        .install();

    SecurityAuditService registered = SecurityServiceResolver
        .findSecurityAuditService().orElseThrow();
    assertInstanceOf(StoreBackedSecurityAuditService.class, registered);
    assertRuntimeHasAuditEntry(runtime, StoreBackedSecurityAuditService.class);
  }

  @Test
  @DisplayName("sinks-only (logging only) registers a CompositeAuditService with a default ring buffer")
  void loggingOnlyComposes() {
    SecurityRuntime runtime = new TestAuditOnlyBootstrap()
        .audit(a -> a.logging())
        .install();

    SecurityAuditService registered = SecurityServiceResolver
        .findSecurityAuditService().orElseThrow();
    assertInstanceOf(CompositeAuditService.class, registered);
    assertRuntimeHasAuditEntry(runtime, CompositeAuditService.class);
  }

  @Test
  @DisplayName("logging + ringBuffer composes into a single CompositeAuditService")
  void loggingPlusRingBufferComposes() {
    SecurityRuntime runtime = new TestAuditOnlyBootstrap()
        .audit(a -> a.logging().ringBuffer(64))
        .install();

    SecurityAuditService registered = SecurityServiceResolver
        .findSecurityAuditService().orElseThrow();
    assertInstanceOf(CompositeAuditService.class, registered);
    CompositeAuditService composite = (CompositeAuditService) registered;
    assertEquals(64, composite.ringBuffer().capacity());
    assertEquals(1, composite.extraSinks().size());
    assertRuntimeHasAuditEntry(runtime, CompositeAuditService.class);
  }

  @Test
  @DisplayName("storeBacked + sinks → TeeingSecurityAuditService")
  void storeBackedPlusSinksTees() {
    AuditEventStore store = new InMemoryAuditEventStore();
    SecurityRuntime runtime = new TestAuditOnlyBootstrap()
        .audit(a -> a.storeBacked(store).ringBuffer(32).logging())
        .install();

    SecurityAuditService registered = SecurityServiceResolver
        .findSecurityAuditService().orElseThrow();
    assertEquals("TeeingSecurityAuditService", registered.getClass().getSimpleName());
    assertRuntimeHasAuditEntry(runtime, registered.getClass());

    AuditEvent event = new LoginSucceeded(Instant.EPOCH, "alice", "127.0.0.1", null);
    registered.publish(event);
    assertEquals(1, ((InMemoryAuditEventStore) store).events.size(),
        "tee forwards publish to store-backed primary");
  }

  @Test
  @DisplayName(".securityAuditService(svc) registers svc directly without wrapping")
  void directServiceWinsWithoutWrapping() {
    SecurityAuditService direct = new RecordingAuditService();
    new TestAuditOnlyBootstrap()
        .audit(a -> a.securityAuditService(direct))
        .install();

    SecurityAuditService registered = SecurityServiceResolver
        .findSecurityAuditService().orElseThrow();
    assertEquals(direct, registered, "direct service must not be wrapped");
  }

  @Test
  @DisplayName("STRICT empty .audit(a -> {}) throws audit/missing-service")
  void strictEmptyAuditThrows() {
    SecurityBootstrapException ex = assertThrows(
        SecurityBootstrapException.class,
        () -> new TestAuditOnlyBootstrap()
            .mode(SecurityBootstrapMode.STRICT)
            .audit(a -> { })
            .install());
    assertTrue(ex.warnings().stream()
        .anyMatch(w -> "audit/missing-service".equals(w.code())));
  }

  @Test
  @DisplayName("PRODUCTION empty .audit(a -> {}) records ERROR warning but does not throw")
  void productionEmptyAuditWarns() {
    SecurityRuntime runtime = new TestAuditOnlyBootstrap()
        .mode(SecurityBootstrapMode.PRODUCTION)
        .audit(a -> { })
        .install();
    assertTrue(runtime.warnings().stream()
        .anyMatch(w -> "audit/missing-service".equals(w.code())
            && w.severity() == Severity.ERROR));
  }

  @Test
  @DisplayName("STRICT .storeBacked(null) throws audit/store-backed-without-store")
  void strictStoreBackedNullThrows() {
    SecurityBootstrapException ex = assertThrows(
        SecurityBootstrapException.class,
        () -> new TestAuditOnlyBootstrap()
            .mode(SecurityBootstrapMode.STRICT)
            .audit(a -> a.storeBacked(null))
            .install());
    assertTrue(ex.warnings().stream()
        .anyMatch(w -> "audit/store-backed-without-store".equals(w.code())));
  }

  @Test
  @DisplayName("STRICT .ringBuffer(0) throws audit/invalid-ring-buffer-capacity")
  void strictRingBufferZeroThrows() {
    SecurityBootstrapException ex = assertThrows(
        SecurityBootstrapException.class,
        () -> new TestAuditOnlyBootstrap()
            .mode(SecurityBootstrapMode.STRICT)
            .audit(a -> a.ringBuffer(0))
            .install());
    assertTrue(ex.warnings().stream()
        .anyMatch(w -> "audit/invalid-ring-buffer-capacity".equals(w.code())));
  }

  @Test
  @DisplayName("STRICT direct + composition throws audit/conflicting-direct-service")
  void strictDirectPlusCompositionThrows() {
    SecurityBootstrapException ex = assertThrows(
        SecurityBootstrapException.class,
        () -> new TestAuditOnlyBootstrap()
            .mode(SecurityBootstrapMode.STRICT)
            .audit(a -> a.securityAuditService(new RecordingAuditService())
                .ringBuffer(16))
            .install());
    assertTrue(ex.warnings().stream()
        .anyMatch(w -> "audit/conflicting-direct-service".equals(w.code())));
  }

  @Test
  @DisplayName(".credentialEvents(true) is recorded but does not change audit wiring")
  void credentialEventsRecordedNotWired() {
    AuditEventStore store = new InMemoryAuditEventStore();
    SecurityRuntime runtime = new TestAuditOnlyBootstrap()
        .audit(a -> a.storeBacked(store).credentialEvents(true))
        .install();

    SecurityAuditService registered = SecurityServiceResolver
        .findSecurityAuditService().orElseThrow();
    assertInstanceOf(StoreBackedSecurityAuditService.class, registered);
    // SecurityRuntime surfaces the flag through a synthetic SPI entry
    boolean flagEntryPresent = runtime.services().stream()
        .anyMatch(s -> s.spi().getSimpleName().equals("CredentialEventsFlag"));
    assertTrue(flagEntryPresent, "credentialEvents flag must appear in runtime");
  }

  // ── helpers ──────────────────────────────────────────────────────

  private static void assertRuntimeHasAuditEntry(SecurityRuntime runtime, Class<?> implClass) {
    boolean found = runtime.services().stream()
        .anyMatch(s -> SecurityAuditService.class.equals(s.spi())
            && implClass.equals(s.impl()));
    assertTrue(found,
        "runtime.services() expected to contain SecurityAuditService impl=" + implClass);
    assertFalse(runtime.services().isEmpty());
  }

  /**
   * Minimal adapter that drives only audit configuration. No authn/
   * authz wiring — the tests don't need it, and the audit pipeline
   * must remain independent of those.
   */
  private static final class TestAuditOnlyBootstrap
      extends AbstractSecurityBootstrap<TestAuditOnlyBootstrap> {

    @Override
    public SecurityRuntime install() {
      java.util.List<RegisteredSecurityService> services = new java.util.ArrayList<>();
      java.util.List<SecurityBootstrapWarning> warnings = new java.util.ArrayList<>();
      applyAuditConfiguration(services, warnings);
      SecurityBootstrapMode mode = state.mode();
      if (mode == SecurityBootstrapMode.STRICT && warningsContainError(warnings)) {
        throw new SecurityBootstrapException(warnings);
      }
      return new SecurityRuntime(services, warnings, mode);
    }
  }

  /** Minimal AuditEventStore that just collects events in-memory. */
  private static final class InMemoryAuditEventStore implements AuditEventStore {
    final List<AuditEnvelope> events = new java.util.ArrayList<>();
    @Override public AuditEnvelope append(TenantId tenant, AuditEvent event) {
      assertNotNull(event);
      AuditEnvelope env = new AuditEnvelope(
          "evt-" + (events.size() + 1),
          tenant != null ? tenant : TenantId.DEFAULT,
          event);
      events.add(env);
      return env;
    }
    @Override public List<AuditEnvelope> query(TenantId tenant, AuditQuery query) {
      return List.copyOf(events);
    }
    @Override public int purgeOlderThan(Instant cutoff) {
      events.removeIf(e -> e.event().timestamp().isBefore(cutoff));
      return 0;
    }
  }

  /** Pass-through audit service used to verify direct-wiring. */
  private static final class RecordingAuditService implements SecurityAuditService {
    @Override public void publish(AuditEvent event) { }
    @Override public List<AuditEvent> query(AuditQuery query) { return List.of(); }
  }
}
