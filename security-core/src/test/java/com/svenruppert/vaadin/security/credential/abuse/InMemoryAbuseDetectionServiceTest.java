/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * http://ec.europa.eu/idabc/eupl5
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */
package com.svenruppert.vaadin.security.credential.abuse;

import com.svenruppert.vaadin.security.audit.AuditEvent;
import com.svenruppert.vaadin.security.audit.AuditQuery;
import com.svenruppert.vaadin.security.audit.RateLimitExceeded;
import com.svenruppert.vaadin.security.audit.SecurityAuditService;
import com.svenruppert.vaadin.security.authorization.api.tenant.TenantId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class InMemoryAbuseDetectionServiceTest {

  private static final Instant T0 = Instant.parse("2026-06-01T12:00:00Z");

  private static final class RecordingAudit implements SecurityAuditService {
    final List<AuditEvent> events = new ArrayList<>();
    @Override public void publish(AuditEvent event) { events.add(event); }
    @Override public List<AuditEvent> query(AuditQuery q) { return List.copyOf(events); }
  }

  private static AbuseAttemptContext loginAttempt(
      String username, String ip, Instant at) {
    return new AbuseAttemptContext(
        AbuseAttemptType.LOGIN,
        Optional.ofNullable(username),
        Optional.ofNullable(ip),
        TenantId.DEFAULT,
        at);
  }

  @Test
  @DisplayName("Empty state allows the first attempt")
  void firstAttemptAllowed() {
    InMemoryAbuseDetectionService svc = new InMemoryAbuseDetectionService(
        AbuseLimitsPolicy.defaults(), new RecordingAudit());
    assertSame(AbuseDecision.Allow.INSTANCE,
        svc.evaluate(loginAttempt("alice", "10.0.0.1", T0)));
  }

  @Test
  @DisplayName("Per-username failure counter triggers Delay then Block")
  void perUsernameEscalation() {
    InMemoryAbuseDetectionService svc = new InMemoryAbuseDetectionService(
        AbuseLimitsPolicy.defaults(), new RecordingAudit());
    AbuseAttemptContext ctx = loginAttempt("alice", null, T0);

    for (int i = 0; i < 5; i++) {
      svc.recordOutcome(ctx, AttemptOutcome.FAILURE);
    }
    AbuseDecision afterFive = svc.evaluate(ctx);
    assertInstanceOf(AbuseDecision.Delay.class, afterFive);
    assertEquals(AbuseDimension.USERNAME,
        ((AbuseDecision.Delay) afterFive).dimension());

    // five more failures push us past the step-up + block thresholds
    for (int i = 0; i < 10; i++) {
      svc.recordOutcome(ctx, AttemptOutcome.FAILURE);
    }
    AbuseDecision afterFifteen = svc.evaluate(ctx);
    assertInstanceOf(AbuseDecision.Block.class, afterFifteen);
  }

  @Test
  @DisplayName("Successful attempt resets the per-username failure counter")
  void successResetsUsernameCounter() {
    InMemoryAbuseDetectionService svc = new InMemoryAbuseDetectionService(
        AbuseLimitsPolicy.defaults(), new RecordingAudit());
    AbuseAttemptContext ctx = loginAttempt("alice", null, T0);
    for (int i = 0; i < 6; i++) {
      svc.recordOutcome(ctx, AttemptOutcome.FAILURE);
    }
    // Threshold was 5 → Delay at this point.
    assertInstanceOf(AbuseDecision.Delay.class, svc.evaluate(ctx));

    svc.recordOutcome(ctx, AttemptOutcome.SUCCESS);
    assertSame(AbuseDecision.Allow.INSTANCE, svc.evaluate(ctx));
  }

  @Test
  @DisplayName("Per-IP volume counter triggers even when each user has very few attempts")
  void perIpVolumeTriggersAlone() {
    AbuseLimitsPolicy tight = AbuseLimitsPolicy.builder()
        .with(AbuseAttemptType.LOGIN, AbuseDimension.CLIENT_ADDRESS,
            new AbuseLimitsPolicy.Limit(
                Duration.ofMinutes(5), 3, 0, 5,
                Duration.ofSeconds(1), Duration.ofMinutes(10)))
        .build();
    InMemoryAbuseDetectionService svc = new InMemoryAbuseDetectionService(
        tight, new RecordingAudit());

    for (int i = 0; i < 5; i++) {
      svc.recordOutcome(
          loginAttempt("user" + i, "10.0.0.99", T0),
          AttemptOutcome.SUCCESS);
    }
    AbuseDecision decision = svc.evaluate(
        loginAttempt("anyone", "10.0.0.99", T0));
    assertInstanceOf(AbuseDecision.Block.class, decision);
    assertEquals(AbuseDimension.CLIENT_ADDRESS,
        ((AbuseDecision.Block) decision).dimension());
  }

  @Test
  @DisplayName("Strongest dimension wins when multiple dimensions trigger")
  void strongestDimensionWins() {
    AbuseLimitsPolicy policy = AbuseLimitsPolicy.builder()
        .with(AbuseAttemptType.LOGIN, AbuseDimension.USERNAME,
            new AbuseLimitsPolicy.Limit(
                Duration.ofMinutes(15), 2, 0, 0,
                Duration.ofSeconds(1), Duration.ofMinutes(15)))
        .with(AbuseAttemptType.LOGIN, AbuseDimension.CLIENT_ADDRESS,
            new AbuseLimitsPolicy.Limit(
                Duration.ofMinutes(15), 1, 0, 2,
                Duration.ofSeconds(1), Duration.ofMinutes(15)))
        .build();
    InMemoryAbuseDetectionService svc = new InMemoryAbuseDetectionService(
        policy, new RecordingAudit());
    AbuseAttemptContext ctx = loginAttempt("alice", "10.0.0.1", T0);
    svc.recordOutcome(ctx, AttemptOutcome.FAILURE);
    svc.recordOutcome(ctx, AttemptOutcome.FAILURE);
    // username count = 2 → Delay; ip volume = 2 → Block. Block wins.
    AbuseDecision decision = svc.evaluate(ctx);
    assertInstanceOf(AbuseDecision.Block.class, decision);
  }

  @Test
  @DisplayName("Sliding window: old events fall out and decisions revert to Allow")
  void slidingWindowEviction() {
    InMemoryAbuseDetectionService svc = new InMemoryAbuseDetectionService(
        AbuseLimitsPolicy.defaults(), new RecordingAudit());
    AbuseAttemptContext ctx = loginAttempt("alice", null, T0);
    for (int i = 0; i < 6; i++) {
      svc.recordOutcome(ctx, AttemptOutcome.FAILURE);
    }
    assertInstanceOf(AbuseDecision.Delay.class, svc.evaluate(ctx));
    // Forward T by 16 minutes — outside the 15-minute window.
    Instant future = T0.plus(Duration.ofMinutes(16));
    assertSame(AbuseDecision.Allow.INSTANCE,
        svc.evaluate(loginAttempt("alice", null, future)));
  }

  @Test
  @DisplayName("Block decision publishes a RateLimitExceeded audit event")
  void blockEmitsAudit() {
    RecordingAudit audit = new RecordingAudit();
    InMemoryAbuseDetectionService svc = new InMemoryAbuseDetectionService(
        AbuseLimitsPolicy.defaults(), audit);
    AbuseAttemptContext ctx = loginAttempt("alice", null, T0);
    for (int i = 0; i < 15; i++) {
      svc.recordOutcome(ctx, AttemptOutcome.FAILURE);
    }
    AbuseDecision decision = svc.evaluate(ctx);
    assertInstanceOf(AbuseDecision.Block.class, decision);
    assertFalse(audit.events.isEmpty(),
        "Block must publish a RateLimitExceeded audit event");
    RateLimitExceeded event = assertInstanceOf(
        RateLimitExceeded.class, audit.events.get(0));
    assertTrue(event.scope().startsWith("LOGIN/USERNAME"));
  }

  @Test
  @DisplayName("Allow does not publish an audit event")
  void allowDoesNotAudit() {
    RecordingAudit audit = new RecordingAudit();
    InMemoryAbuseDetectionService svc = new InMemoryAbuseDetectionService(
        AbuseLimitsPolicy.defaults(), audit);
    svc.evaluate(loginAttempt("alice", "10.0.0.1", T0));
    assertTrue(audit.events.isEmpty());
  }

  @Test
  @DisplayName("Reset request limits are independent of login limits")
  void resetIsIndependent() {
    InMemoryAbuseDetectionService svc = new InMemoryAbuseDetectionService(
        AbuseLimitsPolicy.defaults(), new RecordingAudit());
    AbuseAttemptContext login = loginAttempt("alice", null, T0);
    // Fill up login failure counter.
    for (int i = 0; i < 5; i++) {
      svc.recordOutcome(login, AttemptOutcome.FAILURE);
    }
    // A reset request for the same user is independent.
    AbuseAttemptContext resetReq = new AbuseAttemptContext(
        AbuseAttemptType.RESET_REQUEST,
        Optional.of("alice"), Optional.empty(),
        TenantId.DEFAULT, T0);
    assertSame(AbuseDecision.Allow.INSTANCE, svc.evaluate(resetReq));
  }

  @Test
  @DisplayName("AbuseDecision.Delay rejects zero / negative durations")
  void delayDurationInvariants() {
    org.junit.jupiter.api.Assertions.assertThrows(
        IllegalArgumentException.class,
        () -> new AbuseDecision.Delay(Duration.ZERO, AbuseDimension.USERNAME));
    org.junit.jupiter.api.Assertions.assertThrows(
        NullPointerException.class,
        () -> new AbuseDecision.Delay(Duration.ofSeconds(1), null));
  }

  @Test
  @DisplayName("stepUpAt threshold below blockAt produces RequireAdditionalCheck")
  void stepUpTriggersBeforeBlock() {
    AbuseLimitsPolicy policy = AbuseLimitsPolicy.builder()
        .with(AbuseAttemptType.LOGIN, AbuseDimension.USERNAME,
            new AbuseLimitsPolicy.Limit(
                Duration.ofMinutes(15), 0, 3, 10,
                Duration.ofSeconds(1), Duration.ofMinutes(15)))
        .build();
    InMemoryAbuseDetectionService svc = new InMemoryAbuseDetectionService(
        policy, new RecordingAudit());
    AbuseAttemptContext ctx = loginAttempt("alice", null, T0);
    for (int i = 0; i < 3; i++) {
      svc.recordOutcome(ctx, AttemptOutcome.FAILURE);
    }
    AbuseDecision decision = svc.evaluate(ctx);
    AbuseDecision.RequireAdditionalCheck check = assertInstanceOf(
        AbuseDecision.RequireAdditionalCheck.class, decision);
    assertEquals(AbuseDimension.USERNAME, check.dimension());
  }

  @Test
  @DisplayName("Block out-ranks RequireAdditionalCheck when both fire simultaneously")
  void blockOutranksRequireCheck() {
    AbuseLimitsPolicy policy = AbuseLimitsPolicy.builder()
        .with(AbuseAttemptType.LOGIN, AbuseDimension.USERNAME,
            new AbuseLimitsPolicy.Limit(
                Duration.ofMinutes(15), 0, 1, 0,
                Duration.ofSeconds(1), Duration.ofMinutes(15)))
        .with(AbuseAttemptType.LOGIN, AbuseDimension.CLIENT_ADDRESS,
            new AbuseLimitsPolicy.Limit(
                Duration.ofMinutes(15), 0, 0, 1,
                Duration.ofSeconds(1), Duration.ofMinutes(15)))
        .build();
    InMemoryAbuseDetectionService svc = new InMemoryAbuseDetectionService(
        policy, new RecordingAudit());
    AbuseAttemptContext ctx = loginAttempt("alice", "10.0.0.1", T0);
    svc.recordOutcome(ctx, AttemptOutcome.FAILURE);
    // username = 1 → RequireAdditionalCheck; client = 1 → Block.
    // Block (rank 3) must win over RequireAdditionalCheck (rank 2).
    AbuseDecision decision = svc.evaluate(ctx);
    assertInstanceOf(AbuseDecision.Block.class, decision);
    assertEquals(AbuseDimension.CLIENT_ADDRESS,
        ((AbuseDecision.Block) decision).dimension());
  }

  @Test
  @DisplayName("RequireAdditionalCheck out-ranks Delay")
  void requireCheckOutranksDelay() {
    AbuseLimitsPolicy policy = AbuseLimitsPolicy.builder()
        .with(AbuseAttemptType.LOGIN, AbuseDimension.USERNAME,
            new AbuseLimitsPolicy.Limit(
                Duration.ofMinutes(15), 1, 0, 0,
                Duration.ofSeconds(1), Duration.ofMinutes(15)))
        .with(AbuseAttemptType.LOGIN, AbuseDimension.CLIENT_ADDRESS,
            new AbuseLimitsPolicy.Limit(
                Duration.ofMinutes(15), 0, 1, 0,
                Duration.ofSeconds(1), Duration.ofMinutes(15)))
        .build();
    InMemoryAbuseDetectionService svc = new InMemoryAbuseDetectionService(
        policy, new RecordingAudit());
    AbuseAttemptContext ctx = loginAttempt("alice", "10.0.0.1", T0);
    svc.recordOutcome(ctx, AttemptOutcome.FAILURE);
    AbuseDecision decision = svc.evaluate(ctx);
    assertInstanceOf(AbuseDecision.RequireAdditionalCheck.class, decision);
  }

  @Test
  @DisplayName("Tenant-dimensional limit fires on aggregated tenant traffic")
  void tenantDimensionalLimit() {
    AbuseLimitsPolicy policy = AbuseLimitsPolicy.builder()
        .with(AbuseAttemptType.LOGIN, AbuseDimension.TENANT,
            new AbuseLimitsPolicy.Limit(
                Duration.ofMinutes(15), 0, 0, 3,
                Duration.ofSeconds(1), Duration.ofMinutes(15)))
        .build();
    InMemoryAbuseDetectionService svc = new InMemoryAbuseDetectionService(
        policy, new RecordingAudit());
    // Three different usernames in the same tenant
    for (int i = 0; i < 3; i++) {
      svc.recordOutcome(loginAttempt("user-" + i, null, T0),
          AttemptOutcome.FAILURE);
    }
    AbuseDecision decision = svc.evaluate(
        loginAttempt("user-X", null, T0));
    AbuseDecision.Block block = assertInstanceOf(
        AbuseDecision.Block.class, decision);
    assertEquals(AbuseDimension.TENANT, block.dimension());
  }

  @Test
  @DisplayName("Global-dimensional limit counts every attempt regardless of subject")
  void globalDimensionalLimit() {
    AbuseLimitsPolicy policy = AbuseLimitsPolicy.builder()
        .with(AbuseAttemptType.LOGIN, AbuseDimension.GLOBAL,
            new AbuseLimitsPolicy.Limit(
                Duration.ofMinutes(15), 0, 0, 2,
                Duration.ofSeconds(1), Duration.ofMinutes(15)))
        .build();
    InMemoryAbuseDetectionService svc = new InMemoryAbuseDetectionService(
        policy, new RecordingAudit());
    svc.recordOutcome(loginAttempt("alice", null, T0),
        AttemptOutcome.FAILURE);
    svc.recordOutcome(loginAttempt("bob", null, T0),
        AttemptOutcome.FAILURE);
    AbuseDecision decision = svc.evaluate(
        loginAttempt("carol", null, T0));
    AbuseDecision.Block block = assertInstanceOf(
        AbuseDecision.Block.class, decision);
    assertEquals(AbuseDimension.GLOBAL, block.dimension());
  }

  @Test
  @DisplayName("Anonymous reset requests (no username, no IP) fall through to Allow")
  void anonymousAttemptAllowed() {
    InMemoryAbuseDetectionService svc = new InMemoryAbuseDetectionService(
        AbuseLimitsPolicy.defaults(), new RecordingAudit());
    AbuseAttemptContext ctx = new AbuseAttemptContext(
        AbuseAttemptType.RESET_REQUEST,
        Optional.empty(), Optional.empty(),
        TenantId.DEFAULT, T0);
    // No counters can match — the request is allowed and audit is empty.
    assertSame(AbuseDecision.Allow.INSTANCE, svc.evaluate(ctx));
  }
}
