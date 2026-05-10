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
package com.svenruppert.vaadin.security.bruteforce;

import com.svenruppert.vaadin.security.audit.SecurityAuditEvent;
import com.svenruppert.vaadin.security.audit.SecurityAuditEventType;
import com.svenruppert.vaadin.security.audit.SecurityAuditService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("InMemoryLoginAttemptPolicy")
class InMemoryLoginAttemptPolicyTest {

  private static final LoginAttemptConfiguration FAST_CONFIG =
      new LoginAttemptConfiguration(
          3,
          Duration.ofMinutes(5),
          Duration.ofSeconds(60),
          Duration.ofMinutes(10));

  private static LoginAttemptContext ctx(String user, String client, Instant t) {
    return new LoginAttemptContext(user, client, "sess", t);
  }

  private static InMemoryLoginAttemptPolicy policyAt(Instant fixed, RecordingAudit audit) {
    return new InMemoryLoginAttemptPolicy(
        FAST_CONFIG, Clock.fixed(fixed, ZoneOffset.UTC), audit);
  }

  // ── Config validation ────────────────────────────────────────

  @Test
  @DisplayName("Config rejects threshold < 1")
  void configRejectsZeroThreshold() {
    assertThrows(IllegalArgumentException.class,
        () -> new LoginAttemptConfiguration(
            0, Duration.ofMinutes(1), Duration.ofMinutes(1), Duration.ofMinutes(1)));
  }

  @Test
  @DisplayName("Config rejects non-positive durations")
  void configRejectsZeroDurations() {
    assertThrows(IllegalArgumentException.class,
        () -> new LoginAttemptConfiguration(
            3, Duration.ZERO, Duration.ofMinutes(1), Duration.ofMinutes(1)));
    assertThrows(IllegalArgumentException.class,
        () -> new LoginAttemptConfiguration(
            3, Duration.ofMinutes(1), Duration.ZERO, Duration.ofMinutes(1)));
  }

  @Test
  @DisplayName("Config rejects maxLockout < initialLockout")
  void configRejectsInverseLockoutBounds() {
    assertThrows(IllegalArgumentException.class,
        () -> new LoginAttemptConfiguration(
            3, Duration.ofMinutes(5),
            Duration.ofMinutes(10),
            Duration.ofMinutes(5)));
  }

  @Test
  @DisplayName("Config.defaults() is consistent")
  void configDefaultsAreReasonable() {
    LoginAttemptConfiguration c = LoginAttemptConfiguration.defaults();
    assertEquals(5, c.failureThreshold());
    assertEquals(Duration.ofMinutes(15), c.window());
    assertEquals(Duration.ofMinutes(15), c.initialLockout());
    assertEquals(Duration.ofHours(4), c.maxLockout());
  }

  // ── Allowed-by-default behaviour ─────────────────────────────

  @Test
  @DisplayName("Fresh policy lets every attempt through")
  void freshPolicyAllowsAllAttempts() {
    Instant t0 = Instant.parse("2026-05-08T10:00:00Z");
    InMemoryLoginAttemptPolicy policy = policyAt(t0, new RecordingAudit());

    assertInstanceOf(LoginAttemptDecision.Allowed.class,
        policy.beforeAttempt(ctx("alice", "127.0.0.1", t0)));
  }

  @Test
  @DisplayName("recordSuccess / recordFailure tolerate null fields except timestamp")
  void recordTolerantOfMissingFields() {
    Instant t0 = Instant.parse("2026-05-08T10:00:00Z");
    InMemoryLoginAttemptPolicy policy = policyAt(t0, new RecordingAudit());

    policy.recordFailure(new LoginAttemptContext(null, null, null, t0));
    policy.recordSuccess(new LoginAttemptContext(null, null, null, t0));
  }

  // ── Throttling ───────────────────────────────────────────────

  @Test
  @DisplayName("After threshold-many failures the next beforeAttempt is blocked")
  void blockedAfterThreshold() {
    Instant t0 = Instant.parse("2026-05-08T10:00:00Z");
    InMemoryLoginAttemptPolicy policy = policyAt(t0, new RecordingAudit());

    for (int i = 0; i < FAST_CONFIG.failureThreshold(); i++) {
      policy.recordFailure(ctx("alice", "1.2.3.4", t0.plusSeconds(i)));
    }

    LoginAttemptDecision decision = policy.beforeAttempt(
        ctx("alice", "1.2.3.4", t0.plusSeconds(FAST_CONFIG.failureThreshold())));

    assertInstanceOf(LoginAttemptDecision.LockedOut.class, decision);
    LoginAttemptDecision.LockedOut lockout = (LoginAttemptDecision.LockedOut) decision;
    assertNotNull(lockout.remaining());
    assertEquals(FAST_CONFIG.failureThreshold(), lockout.failedAttempts());
  }

  @Test
  @DisplayName("recordFailure emits LOGIN_FAILURE audit on every call")
  void everyFailureIsAudited() {
    RecordingAudit audit = new RecordingAudit();
    Instant t0 = Instant.parse("2026-05-08T10:00:00Z");
    InMemoryLoginAttemptPolicy policy = policyAt(t0, audit);

    policy.recordFailure(ctx("alice", "1.2.3.4", t0));
    policy.recordFailure(ctx("alice", "1.2.3.4", t0.plusSeconds(1)));

    long failures = audit.events.stream()
        .filter(e -> e.type() == SecurityAuditEventType.LOGIN_FAILURE)
        .count();
    assertEquals(2L, failures);
  }

  @Test
  @DisplayName("Threshold breach emits exactly one BRUTE_FORCE_LIMIT_REACHED audit event")
  void thresholdBreachAuditedOnce() {
    RecordingAudit audit = new RecordingAudit();
    Instant t0 = Instant.parse("2026-05-08T10:00:00Z");
    InMemoryLoginAttemptPolicy policy = policyAt(t0, audit);

    for (int i = 0; i < FAST_CONFIG.failureThreshold(); i++) {
      policy.recordFailure(ctx("alice", "1.2.3.4", t0.plusSeconds(i)));
    }

    long breaches = audit.events.stream()
        .filter(e -> e.type() == SecurityAuditEventType.BRUTE_FORCE_LIMIT_REACHED)
        .count();
    assertEquals(1L, breaches,
        "the threshold breach must be reported exactly once per lockout");
  }

  @Test
  @DisplayName("recordSuccess clears both the combined and the username counter")
  void successResetsCounters() {
    Instant t0 = Instant.parse("2026-05-08T10:00:00Z");
    InMemoryLoginAttemptPolicy policy = policyAt(t0, new RecordingAudit());

    // 1 fewer than threshold so we don't trigger lockout
    for (int i = 0; i < FAST_CONFIG.failureThreshold() - 1; i++) {
      policy.recordFailure(ctx("alice", "1.2.3.4", t0.plusSeconds(i)));
    }
    policy.recordSuccess(ctx("alice", "1.2.3.4", t0.plusSeconds(2)));

    // After success, threshold-1 more failures must NOT lock the account
    for (int i = 0; i < FAST_CONFIG.failureThreshold() - 1; i++) {
      policy.recordFailure(ctx("alice", "1.2.3.4", t0.plusSeconds(10 + i)));
    }
    assertInstanceOf(LoginAttemptDecision.Allowed.class,
        policy.beforeAttempt(ctx("alice", "1.2.3.4", t0.plusSeconds(20))));
  }

  @Test
  @DisplayName("Username-only counter blocks an attacker that cycles client addresses")
  void usernameCounterBlocksClientCycling() {
    RecordingAudit audit = new RecordingAudit();
    Instant t0 = Instant.parse("2026-05-08T10:00:00Z");
    InMemoryLoginAttemptPolicy policy = policyAt(t0, audit);

    for (int i = 0; i < FAST_CONFIG.failureThreshold(); i++) {
      policy.recordFailure(ctx("alice", "1.2.3." + i, t0.plusSeconds(i)));
    }

    assertInstanceOf(LoginAttemptDecision.LockedOut.class,
        policy.beforeAttempt(ctx("alice", "9.9.9.9", t0.plusSeconds(10))),
        "lockout must follow the user across client addresses");
  }

  @Test
  @DisplayName("Username + clientAddress are case- and whitespace-insensitive")
  void caseAndWhitespaceInsensitiveKeys() {
    Instant t0 = Instant.parse("2026-05-08T10:00:00Z");
    InMemoryLoginAttemptPolicy policy = policyAt(t0, new RecordingAudit());

    policy.recordFailure(ctx("Alice", "127.0.0.1", t0));
    policy.recordFailure(ctx(" alice ", "  127.0.0.1  ", t0.plusSeconds(1)));
    policy.recordFailure(ctx("ALICE", "127.0.0.1", t0.plusSeconds(2)));

    assertInstanceOf(LoginAttemptDecision.LockedOut.class,
        policy.beforeAttempt(ctx("alice", "127.0.0.1", t0.plusSeconds(3))));
  }

  // ── Window / unlock ──────────────────────────────────────────

  @Test
  @DisplayName("Lockout expires after retryAfter — the next attempt is allowed again")
  void lockoutExpires() {
    Instant t0 = Instant.parse("2026-05-08T10:00:00Z");
    MutableClock clock = new MutableClock(t0);
    InMemoryLoginAttemptPolicy policy =
        new InMemoryLoginAttemptPolicy(FAST_CONFIG, clock, new RecordingAudit());

    // Drive the lockout
    for (int i = 0; i < FAST_CONFIG.failureThreshold(); i++) {
      policy.recordFailure(ctx("alice", "1.2.3.4", clock.instant()));
      clock.advance(Duration.ofSeconds(1));
    }
    assertInstanceOf(LoginAttemptDecision.LockedOut.class,
        policy.beforeAttempt(ctx("alice", "1.2.3.4", clock.instant())),
        "precondition: the policy must currently be locked");

    // Advance past the lockout duration
    clock.advance(FAST_CONFIG.initialLockout().plusSeconds(1));

    assertInstanceOf(LoginAttemptDecision.Allowed.class,
        policy.beforeAttempt(ctx("alice", "1.2.3.4", clock.instant())),
        "after retryAfter the lockout must be released");
  }

  // ── Audit failure isolation ──────────────────────────────────

  @Test
  @DisplayName("Throwing audit sink does not propagate from recordFailure")
  void auditFailureSwallowed() {
    SecurityAuditService throwingAudit = e -> {
      throw new RuntimeException("audit boom");
    };
    Instant t0 = Instant.parse("2026-05-08T10:00:00Z");
    InMemoryLoginAttemptPolicy policy = new InMemoryLoginAttemptPolicy(
        FAST_CONFIG, Clock.fixed(t0, ZoneOffset.UTC), throwingAudit);

    policy.recordFailure(ctx("alice", "1.2.3.4", t0));
  }

  // ── Noop default ─────────────────────────────────────────────

  @Test
  @DisplayName("NoopLoginAttemptPolicy.INSTANCE always allows")
  void noopAlwaysAllows() {
    LoginAttemptPolicy noop = NoopLoginAttemptPolicy.INSTANCE;
    Instant t0 = Instant.parse("2026-05-08T10:00:00Z");

    for (int i = 0; i < 10; i++) {
      noop.recordFailure(ctx("alice", "1.2.3.4", t0.plusSeconds(i)));
    }

    assertInstanceOf(LoginAttemptDecision.Allowed.class,
        noop.beforeAttempt(ctx("alice", "1.2.3.4", t0.plusSeconds(10))));
  }

  @Test
  @DisplayName("NoopLoginAttemptPolicy is the same singleton on repeated reads")
  void noopSingleton() {
    assertSame(NoopLoginAttemptPolicy.INSTANCE, NoopLoginAttemptPolicy.INSTANCE);
  }

  // ── Test fixtures ────────────────────────────────────────────

  static final class RecordingAudit implements SecurityAuditService {
    final List<SecurityAuditEvent> events = new ArrayList<>();

    @Override
    public void record(SecurityAuditEvent event) {
      events.add(event);
    }
  }

  /** Test clock whose instant can be advanced manually. */
  static final class MutableClock extends Clock {
    private Instant now;

    MutableClock(Instant start) {
      this.now = start;
    }

    void advance(Duration delta) {
      this.now = now.plus(delta);
    }

    @Override public Instant instant() {
      return now;
    }

    @Override public java.time.ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override public Clock withZone(java.time.ZoneId zone) {
      return this;
    }
  }
}
