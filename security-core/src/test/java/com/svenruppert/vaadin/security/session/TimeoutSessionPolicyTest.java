/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package com.svenruppert.vaadin.security.session;

import com.svenruppert.vaadin.security.audit.AuditEvent;
import com.svenruppert.vaadin.security.audit.AuditQuery;
import com.svenruppert.vaadin.security.audit.SessionCreated;
import com.svenruppert.vaadin.security.audit.SessionExpired;
import com.svenruppert.vaadin.security.audit.SessionInvalidated;
import com.svenruppert.vaadin.security.audit.SecurityAuditService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("TimeoutSessionPolicy")
class TimeoutSessionPolicyTest {

  private static final TimeoutSessionPolicy.Config CONFIG =
      new TimeoutSessionPolicy.Config(
          Duration.ofMinutes(15), Duration.ofHours(1), false, "/login");

  private static SessionContext<String> ctx(Instant created, Instant lastActivity) {
    return new SessionContext<>(
        "alice", "sess-1", created, lastActivity, "10.0.0.1", Map.of());
  }

  // ── Config validation ────────────────────────────────────────

  @Test
  @DisplayName("Config rejects null parts")
  void configRejectsNulls() {
    assertThrows(NullPointerException.class,
        () -> new TimeoutSessionPolicy.Config(null, Duration.ofHours(1), false, "/login"));
    assertThrows(NullPointerException.class,
        () -> new TimeoutSessionPolicy.Config(Duration.ofMinutes(15), null, false, "/login"));
    assertThrows(NullPointerException.class,
        () -> new TimeoutSessionPolicy.Config(Duration.ofMinutes(15), Duration.ofHours(1), false, null));
  }

  @Test
  @DisplayName("Config rejects blank loginRoute and non-positive durations")
  void configRejectsInvalidValues() {
    assertThrows(IllegalArgumentException.class,
        () -> new TimeoutSessionPolicy.Config(
            Duration.ofMinutes(15), Duration.ofHours(1), false, "  "));
    assertThrows(IllegalArgumentException.class,
        () -> new TimeoutSessionPolicy.Config(
            Duration.ZERO, Duration.ofHours(1), false, "/login"));
    assertThrows(IllegalArgumentException.class,
        () -> new TimeoutSessionPolicy.Config(
            Duration.ofMinutes(15), Duration.ZERO, false, "/login"));
  }

  // ── Decisions ────────────────────────────────────────────────

  @Test
  @DisplayName("beforeNavigation returns Continue while neither timeout has tripped")
  void continueWithinThresholds() {
    Instant t0 = Instant.parse("2026-05-08T10:00:00Z");
    TimeoutSessionPolicy<String> policy = new TimeoutSessionPolicy<>(
        CONFIG, Clock.fixed(t0.plus(Duration.ofMinutes(5)), ZoneOffset.UTC), null);

    SessionDecision decision = policy.beforeNavigation(ctx(t0, t0.plus(Duration.ofMinutes(4))));

    assertSame(SessionDecision.Continue.INSTANCE, decision);
  }

  @Test
  @DisplayName("Idle timeout produces Invalidate with IDLE_TIMEOUT audit")
  void idleTimeoutInvalidates() {
    Instant t0 = Instant.parse("2026-05-08T10:00:00Z");
    Instant lastActivity = t0.plusSeconds(60);
    Instant now = lastActivity.plus(CONFIG.idleTimeout()).plusSeconds(1);

    RecordingAudit audit = new RecordingAudit();
    TimeoutSessionPolicy<String> policy = new TimeoutSessionPolicy<>(
        CONFIG, Clock.fixed(now, ZoneOffset.UTC), audit);

    SessionDecision decision = policy.beforeNavigation(ctx(t0, lastActivity));

    assertInstanceOf(SessionDecision.Invalidate.class, decision);
    SessionDecision.Invalidate inv = (SessionDecision.Invalidate) decision;
    assertEquals("/login", inv.loginRoute());
    assertEquals(1, audit.events.size());
    SessionExpired event = (SessionExpired) audit.events.get(0);
    assertEquals("IdleTimeout", event.reason());
  }

  @Test
  @DisplayName("Absolute lifetime trumps idle timeout — emits ABSOLUTE_LIFETIME audit")
  void absoluteLifetimeWinsOverIdle() {
    Instant t0 = Instant.parse("2026-05-08T10:00:00Z");
    Instant now = t0.plus(CONFIG.absoluteLifetime()).plusSeconds(1);

    RecordingAudit audit = new RecordingAudit();
    TimeoutSessionPolicy<String> policy = new TimeoutSessionPolicy<>(
        CONFIG, Clock.fixed(now, ZoneOffset.UTC), audit);

    // last activity is "now" — would be fine for idle alone, but absolute
    // lifetime has already expired
    SessionDecision decision = policy.beforeNavigation(ctx(t0, now));

    assertInstanceOf(SessionDecision.Invalidate.class, decision);
    assertEquals(1, audit.events.size());
    assertEquals("AbsoluteLifetimeExceeded",
        ((SessionExpired) audit.events.get(0)).reason());
  }

  @Test
  @DisplayName("null lastActivity is treated as createdAt")
  void nullLastActivityFallsBackToCreatedAt() {
    Instant t0 = Instant.parse("2026-05-08T10:00:00Z");
    Instant now = t0.plus(CONFIG.idleTimeout()).plusSeconds(1);

    TimeoutSessionPolicy<String> policy = new TimeoutSessionPolicy<>(
        CONFIG, Clock.fixed(now, ZoneOffset.UTC), null);

    SessionDecision decision = policy.beforeNavigation(ctx(t0, null));

    assertInstanceOf(SessionDecision.Invalidate.class, decision);
  }

  // ── onLogin / onLogout ───────────────────────────────────────

  @Test
  @DisplayName("onLogin without rotation returns Continue and emits SESSION_CREATED")
  void onLoginWithoutRotation() {
    Instant t0 = Instant.parse("2026-05-08T10:00:00Z");
    RecordingAudit audit = new RecordingAudit();
    TimeoutSessionPolicy<String> policy = new TimeoutSessionPolicy<>(
        CONFIG, Clock.fixed(t0, ZoneOffset.UTC), audit);

    SessionDecision decision = policy.onLogin(ctx(t0, t0));

    assertSame(SessionDecision.Continue.INSTANCE, decision);
    assertEquals(1, audit.events.size());
    assertInstanceOf(SessionCreated.class, audit.events.get(0));
  }

  @Test
  @DisplayName("onLogin with rotation returns Invalidate so the adapter rotates the session id")
  void onLoginWithRotation() {
    TimeoutSessionPolicy.Config rotating = new TimeoutSessionPolicy.Config(
        Duration.ofMinutes(15), Duration.ofHours(1), true, "/login");
    Instant t0 = Instant.parse("2026-05-08T10:00:00Z");
    TimeoutSessionPolicy<String> policy = new TimeoutSessionPolicy<>(
        rotating, Clock.fixed(t0, ZoneOffset.UTC), null);

    SessionDecision decision = policy.onLogin(ctx(t0, t0));

    assertInstanceOf(SessionDecision.Invalidate.class, decision);
    assertEquals("/login", ((SessionDecision.Invalidate) decision).loginRoute());
  }

  @Test
  @DisplayName("onLogout emits SESSION_INVALIDATED")
  void onLogoutEmitsAudit() {
    Instant t0 = Instant.parse("2026-05-08T10:00:00Z");
    RecordingAudit audit = new RecordingAudit();
    TimeoutSessionPolicy<String> policy = new TimeoutSessionPolicy<>(
        CONFIG, Clock.fixed(t0, ZoneOffset.UTC), audit);

    policy.onLogout(ctx(t0, t0));

    assertEquals(1, audit.events.size());
    SessionInvalidated event = (SessionInvalidated) audit.events.get(0);
    assertEquals("Logout", event.reason());
  }

  @Test
  @DisplayName("Audit-sink failure does not propagate from beforeNavigation")
  void auditFailureSwallowed() {
    Instant t0 = Instant.parse("2026-05-08T10:00:00Z");
    Instant now = t0.plus(CONFIG.absoluteLifetime()).plusSeconds(1);
    SecurityAuditService throwingAudit = new SecurityAuditService() {
      @Override public void publish(AuditEvent event) {
        throw new RuntimeException("audit boom");
      }

      @Override public java.util.List<AuditEvent> query(AuditQuery query) {
        return java.util.List.of();
      }
    };
    TimeoutSessionPolicy<String> policy = new TimeoutSessionPolicy<>(
        CONFIG, Clock.fixed(now, ZoneOffset.UTC), throwingAudit);

    SessionDecision decision = policy.beforeNavigation(ctx(t0, t0));

    assertInstanceOf(SessionDecision.Invalidate.class, decision);
  }

  // ── Noop default ─────────────────────────────────────────────

  @Test
  @DisplayName("NoopSessionPolicy.instance() returns the singleton across calls")
  void noopSingleton() {
    NoopSessionPolicy<String> a = NoopSessionPolicy.instance();
    NoopSessionPolicy<Integer> b = NoopSessionPolicy.instance();
    assertSame(a, b);
  }

  @Test
  @DisplayName("NoopSessionPolicy returns Continue for every navigation and login")
  void noopAlwaysContinue() {
    NoopSessionPolicy<String> noop = NoopSessionPolicy.instance();
    Instant t0 = Instant.parse("2026-05-08T10:00:00Z");
    SessionContext<String> context = ctx(t0, t0);

    assertSame(SessionDecision.Continue.INSTANCE, noop.beforeNavigation(context));
    assertSame(SessionDecision.Continue.INSTANCE, noop.onLogin(context));
    noop.onLogout(context);
  }

  // ── evaluate(SessionMetadata) ────────────────────────────────

  @Test
  @DisplayName("evaluate returns Active when neither bound has tripped")
  void evaluateActive() {
    Instant t0 = Instant.parse("2026-05-08T10:00:00Z");
    TimeoutSessionPolicy<String> policy = new TimeoutSessionPolicy<>(
        CONFIG, Clock.fixed(t0.plus(Duration.ofMinutes(5)), ZoneOffset.UTC), null);

    SessionPolicyDecision decision = policy.evaluate(
        new SessionMetadata("alice", t0, t0.plus(Duration.ofMinutes(4))));

    assertSame(SessionPolicyDecision.Active.INSTANCE, decision);
  }

  @Test
  @DisplayName("evaluate returns IdleTimeout when only the idle bound has tripped")
  void evaluateIdleTimeout() {
    Instant t0 = Instant.parse("2026-05-08T10:00:00Z");
    Instant lastActivity = t0.plusSeconds(60);
    Instant now = lastActivity.plus(CONFIG.idleTimeout()).plusSeconds(1);

    TimeoutSessionPolicy<String> policy = new TimeoutSessionPolicy<>(
        CONFIG, Clock.fixed(now, ZoneOffset.UTC), null);

    SessionPolicyDecision decision = policy.evaluate(
        new SessionMetadata("alice", t0, lastActivity));

    assertSame(SessionPolicyDecision.IdleTimeout.INSTANCE, decision);
  }

  @Test
  @DisplayName("evaluate returns AbsoluteLifetimeExceeded when the absolute bound trumps idle")
  void evaluateAbsoluteLifetimeWins() {
    Instant t0 = Instant.parse("2026-05-08T10:00:00Z");
    Instant now = t0.plus(CONFIG.absoluteLifetime()).plusSeconds(1);

    TimeoutSessionPolicy<String> policy = new TimeoutSessionPolicy<>(
        CONFIG, Clock.fixed(now, ZoneOffset.UTC), null);

    // last activity is "now" — fine for idle alone, but absolute has expired
    SessionPolicyDecision decision = policy.evaluate(
        new SessionMetadata("alice", t0, now));

    assertSame(SessionPolicyDecision.AbsoluteLifetimeExceeded.INSTANCE, decision);
  }

  @Test
  @DisplayName("evaluate does not emit audit events (audit is the lifecycle hook's job)")
  void evaluateDoesNotEmitAudit() {
    Instant t0 = Instant.parse("2026-05-08T10:00:00Z");
    Instant now = t0.plus(CONFIG.absoluteLifetime()).plusSeconds(1);
    RecordingAudit audit = new RecordingAudit();

    TimeoutSessionPolicy<String> policy = new TimeoutSessionPolicy<>(
        CONFIG, Clock.fixed(now, ZoneOffset.UTC), audit);

    policy.evaluate(new SessionMetadata("alice", t0, t0));

    assertSame(0, audit.events.size());
  }

  @Test
  @DisplayName("evaluate rejects null metadata")
  void evaluateRejectsNull() {
    Instant t0 = Instant.parse("2026-05-08T10:00:00Z");
    TimeoutSessionPolicy<String> policy = new TimeoutSessionPolicy<>(
        CONFIG, Clock.fixed(t0, ZoneOffset.UTC), null);

    assertThrows(NullPointerException.class, () -> policy.evaluate(null));
  }

  @Test
  @DisplayName("Default SessionPolicy.evaluate returns Active for any metadata")
  void defaultEvaluateActive() {
    SessionPolicy<String> defaultPolicy = new SessionPolicy<>() {
      @Override
      public SessionDecision beforeNavigation(SessionContext<String> context) {
        return SessionDecision.Continue.INSTANCE;
      }
    };

    Instant t0 = Instant.parse("2026-05-08T10:00:00Z");
    SessionPolicyDecision decision = defaultPolicy.evaluate(
        new SessionMetadata("alice", t0, t0));

    assertSame(SessionPolicyDecision.Active.INSTANCE, decision);
  }

  // ── Test fixtures ────────────────────────────────────────────

  static final class RecordingAudit implements SecurityAuditService {
    final List<AuditEvent> events = new ArrayList<>();

    @Override
    public void publish(AuditEvent event) {
      events.add(event);
    }

    @Override
    public List<AuditEvent> query(AuditQuery query) {
      return List.of();
    }
  }
}
