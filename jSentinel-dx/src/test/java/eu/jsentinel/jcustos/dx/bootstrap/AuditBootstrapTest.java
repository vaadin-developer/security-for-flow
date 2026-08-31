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
package eu.jsentinel.jcustos.dx.bootstrap;

import eu.jsentinel.jcustos.audit.AuditEnvelope;
import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditEventStore;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.CompositeAuditService;
import eu.jsentinel.jcustos.audit.LoginSucceeded;
import eu.jsentinel.jcustos.audit.JSentinelAuditService;
import eu.jsentinel.jcustos.audit.StoreBackedJSentinelAuditService;
import eu.jsentinel.jcustos.authorization.api.JSentinelServiceResolver;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.dx.internal.AbstractJSentinelBootstrap;
import eu.jsentinel.jcustos.dx.runtime.RegisteredJSentinelService;
import eu.jsentinel.jcustos.dx.runtime.JSentinelBootstrapMode;
import eu.jsentinel.jcustos.dx.runtime.JSentinelBootstrapWarning;
import eu.jsentinel.jcustos.dx.runtime.JSentinelRuntime;
import eu.jsentinel.jcustos.dx.runtime.Severity;
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
 * state actually reaches the {@code JSentinelServiceResolver}. No
 * Mockito — fake stores are real implementations.
 */
@DisplayName("AuditBootstrap real surface (V00.73)")
class AuditBootstrapTest {

  @BeforeEach
  @AfterEach
  void resetResolver() {
    JSentinelServiceResolver.resetAll();
  }

  @Test
  @DisplayName(".storeBacked(store) registers a StoreBackedJSentinelAuditService")
  void storeBackedRegistersStoreBackedService() {
    AuditEventStore store = new InMemoryAuditEventStore();
    JSentinelRuntime runtime = new TestAuditOnlyBootstrap()
        .audit(a -> a.storeBacked(store))
        .install();

    JSentinelAuditService registered = JSentinelServiceResolver
        .findJSentinelAuditService().orElseThrow();
    assertInstanceOf(StoreBackedJSentinelAuditService.class, registered);
    assertRuntimeHasAuditEntry(runtime, StoreBackedJSentinelAuditService.class);
  }

  @Test
  @DisplayName("sinks-only (logging only) registers a CompositeAuditService with a default ring buffer")
  void loggingOnlyComposes() {
    JSentinelRuntime runtime = new TestAuditOnlyBootstrap()
        .audit(a -> a.logging())
        .install();

    JSentinelAuditService registered = JSentinelServiceResolver
        .findJSentinelAuditService().orElseThrow();
    assertInstanceOf(CompositeAuditService.class, registered);
    assertRuntimeHasAuditEntry(runtime, CompositeAuditService.class);
  }

  @Test
  @DisplayName("logging + ringBuffer composes into a single CompositeAuditService")
  void loggingPlusRingBufferComposes() {
    JSentinelRuntime runtime = new TestAuditOnlyBootstrap()
        .audit(a -> a.logging().ringBuffer(64))
        .install();

    JSentinelAuditService registered = JSentinelServiceResolver
        .findJSentinelAuditService().orElseThrow();
    assertInstanceOf(CompositeAuditService.class, registered);
    CompositeAuditService composite = (CompositeAuditService) registered;
    assertEquals(64, composite.ringBuffer().capacity());
    assertEquals(1, composite.extraSinks().size());
    assertRuntimeHasAuditEntry(runtime, CompositeAuditService.class);
  }

  @Test
  @DisplayName("storeBacked + sinks → TeeingJSentinelAuditService")
  void storeBackedPlusSinksTees() {
    AuditEventStore store = new InMemoryAuditEventStore();
    JSentinelRuntime runtime = new TestAuditOnlyBootstrap()
        .audit(a -> a.storeBacked(store).ringBuffer(32).logging())
        .install();

    JSentinelAuditService registered = JSentinelServiceResolver
        .findJSentinelAuditService().orElseThrow();
    assertEquals("TeeingJSentinelAuditService", registered.getClass().getSimpleName());
    assertRuntimeHasAuditEntry(runtime, registered.getClass());

    AuditEvent event = new LoginSucceeded(Instant.EPOCH, "alice", "127.0.0.1", null);
    registered.publish(event);
    assertEquals(1, ((InMemoryAuditEventStore) store).events.size(),
        "tee forwards publish to store-backed primary");
  }

  @Test
  @DisplayName(".securityAuditService(svc) registers svc directly without wrapping")
  void directServiceWinsWithoutWrapping() {
    JSentinelAuditService direct = new RecordingAuditService();
    new TestAuditOnlyBootstrap()
        .audit(a -> a.securityAuditService(direct))
        .install();

    JSentinelAuditService registered = JSentinelServiceResolver
        .findJSentinelAuditService().orElseThrow();
    assertEquals(direct, registered, "direct service must not be wrapped");
  }

  @Test
  @DisplayName("STRICT empty .audit(a -> {}) throws audit/missing-service")
  void strictEmptyAuditThrows() {
    JSentinelBootstrapException ex = assertThrows(
        JSentinelBootstrapException.class,
        () -> new TestAuditOnlyBootstrap()
            .mode(JSentinelBootstrapMode.STRICT)
            .audit(a -> { })
            .install());
    assertTrue(ex.warnings().stream()
        .anyMatch(w -> "audit/missing-service".equals(w.code())));
  }

  @Test
  @DisplayName("PRODUCTION empty .audit(a -> {}) records ERROR warning but does not throw")
  void productionEmptyAuditWarns() {
    JSentinelRuntime runtime = new TestAuditOnlyBootstrap()
        .mode(JSentinelBootstrapMode.PRODUCTION)
        .audit(a -> { })
        .install();
    assertTrue(runtime.warnings().stream()
        .anyMatch(w -> "audit/missing-service".equals(w.code())
            && w.severity() == Severity.ERROR));
  }

  @Test
  @DisplayName("STRICT .storeBacked(null) throws audit/store-backed-without-store")
  void strictStoreBackedNullThrows() {
    JSentinelBootstrapException ex = assertThrows(
        JSentinelBootstrapException.class,
        () -> new TestAuditOnlyBootstrap()
            .mode(JSentinelBootstrapMode.STRICT)
            .audit(a -> a.storeBacked(null))
            .install());
    assertTrue(ex.warnings().stream()
        .anyMatch(w -> "audit/store-backed-without-store".equals(w.code())));
  }

  @Test
  @DisplayName("STRICT .ringBuffer(0) throws audit/invalid-ring-buffer-capacity")
  void strictRingBufferZeroThrows() {
    JSentinelBootstrapException ex = assertThrows(
        JSentinelBootstrapException.class,
        () -> new TestAuditOnlyBootstrap()
            .mode(JSentinelBootstrapMode.STRICT)
            .audit(a -> a.ringBuffer(0))
            .install());
    assertTrue(ex.warnings().stream()
        .anyMatch(w -> "audit/invalid-ring-buffer-capacity".equals(w.code())));
  }

  @Test
  @DisplayName("STRICT direct + composition throws audit/conflicting-direct-service")
  void strictDirectPlusCompositionThrows() {
    JSentinelBootstrapException ex = assertThrows(
        JSentinelBootstrapException.class,
        () -> new TestAuditOnlyBootstrap()
            .mode(JSentinelBootstrapMode.STRICT)
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
    JSentinelRuntime runtime = new TestAuditOnlyBootstrap()
        .audit(a -> a.storeBacked(store).credentialEvents(true))
        .install();

    JSentinelAuditService registered = JSentinelServiceResolver
        .findJSentinelAuditService().orElseThrow();
    assertInstanceOf(StoreBackedJSentinelAuditService.class, registered);
    // JSentinelRuntime surfaces the flag through a synthetic SPI entry
    boolean flagEntryPresent = runtime.services().stream()
        .anyMatch(s -> s.spi().getSimpleName().equals("CredentialEventsFlag"));
    assertTrue(flagEntryPresent, "credentialEvents flag must appear in runtime");
  }

  // ── helpers ──────────────────────────────────────────────────────

  private static void assertRuntimeHasAuditEntry(JSentinelRuntime runtime, Class<?> implClass) {
    boolean found = runtime.services().stream()
        .anyMatch(s -> JSentinelAuditService.class.equals(s.spi())
            && implClass.equals(s.impl()));
    assertTrue(found,
        "runtime.services() expected to contain JSentinelAuditService impl=" + implClass);
    assertFalse(runtime.services().isEmpty());
  }

  /**
   * Minimal adapter that drives only audit configuration. No authn/
   * authz wiring — the tests don't need it, and the audit pipeline
   * must remain independent of those.
   */
  private static final class TestAuditOnlyBootstrap
      extends AbstractJSentinelBootstrap<TestAuditOnlyBootstrap> {

    @Override
    public JSentinelRuntime install() {
      java.util.List<RegisteredJSentinelService> services = new java.util.ArrayList<>();
      java.util.List<JSentinelBootstrapWarning> warnings = new java.util.ArrayList<>();
      applyAuditConfiguration(services, warnings);
      JSentinelBootstrapMode mode = state.mode();
      if (mode == JSentinelBootstrapMode.STRICT && warningsContainError(warnings)) {
        throw new JSentinelBootstrapException(warnings);
      }
      return new JSentinelRuntime(services, warnings, mode);
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
  private static final class RecordingAuditService implements JSentinelAuditService {
    @Override public void publish(AuditEvent event) { }
    @Override public List<AuditEvent> query(AuditQuery query) { return List.of(); }
  }
}
