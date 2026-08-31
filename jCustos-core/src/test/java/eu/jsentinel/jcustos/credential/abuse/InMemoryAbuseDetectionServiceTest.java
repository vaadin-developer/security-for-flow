/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */
package eu.jsentinel.jcustos.credential.abuse;

import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.RateLimitExceeded;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class InMemoryAbuseDetectionServiceTest {

  private static final Instant T0 = Instant.parse("2026-06-01T12:00:00Z");

  private static final class RecordingAudit implements JCustosAuditService {
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
  @DisplayName("JS-SEC-030: the counter map stays bounded under a distinct-username flood")
  void counterMapBoundedUnderUsernameFlood() {
    int cap = 100;
    InMemoryAbuseDetectionService svc = new InMemoryAbuseDetectionService(
        AbuseLimitsPolicy.defaults(), new RecordingAudit(), cap);
    // an unauthenticated spray across 5000 distinct usernames — each mints a per-username
    // counter key that was previously never reclaimed (CWE-770 memory-exhaustion).
    for (int i = 0; i < 5000; i++) {
      svc.recordOutcome(loginAttempt("user-" + i, null, T0), AttemptOutcome.FAILURE);
    }
    int tracked = svc.trackedCounterCount();
    assertTrue(tracked <= cap + 2,
        "counter map must stay bounded (<= " + (cap + 2) + " for cap " + cap + "), was " + tracked);
  }

  @Test
  @DisplayName("RF (exit-review): a distinct-username spray cannot evict a victim's in-force block")
  void sprayDoesNotEvictActiveBlock() {
    // USERNAME-only policy: blocks after 3 failures. No volume-dimension limits, so
    // evaluate() consults only the per-username counter and the assertion is unambiguous.
    AbuseLimitsPolicy usernameOnly = AbuseLimitsPolicy.builder()
        .with(AbuseAttemptType.LOGIN, AbuseDimension.USERNAME,
            // (window, delayAt, stepUpAt, blockAt, delayLen, blockLen): block after 3,
            // no delay/step-up so the victim goes straight to Block.
            new AbuseLimitsPolicy.Limit(
                Duration.ofMinutes(15), 0, 0, 3,
                Duration.ofSeconds(1), Duration.ofMinutes(15)))
        .build();
    int cap = 20;
    InMemoryAbuseDetectionService svc = new InMemoryAbuseDetectionService(
        usernameOnly, new RecordingAudit(), cap);

    AbuseAttemptContext victim = loginAttempt("victim", null, T0);
    for (int i = 0; i < 3; i++) {
      svc.recordOutcome(victim, AttemptOutcome.FAILURE);
    }
    assertInstanceOf(AbuseDecision.Block.class, svc.evaluate(victim),
        "victim must be blocked after reaching blockAt");

    // Spray far past the cap across distinct throwaway usernames (each a size-1,
    // non-blocking counter). With arbitrary eviction this would drop the victim's
    // block before it is lifted — the lockout-bypass this fix closes.
    for (int i = 0; i < cap * 3; i++) {
      svc.recordOutcome(loginAttempt("spray-" + i, null, T0), AttemptOutcome.FAILURE);
    }

    assertInstanceOf(AbuseDecision.Block.class, svc.evaluate(victim),
        "the in-force block must survive the eviction pressure of the spray");
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
  @DisplayName("R039: the sliding window is half-open — an event exactly `window` old has expired")
  void slidingWindowBoundaryIsHalfOpen() {
    InMemoryAbuseDetectionService svc = new InMemoryAbuseDetectionService(
        AbuseLimitsPolicy.defaults(), new RecordingAudit());
    for (int i = 0; i < 6; i++) {
      svc.recordOutcome(loginAttempt("alice", null, T0), AttemptOutcome.FAILURE);
    }
    Duration window = Duration.ofMinutes(15); // default USERNAME login window

    // one tick before the boundary: the events still count → Delay
    assertInstanceOf(AbuseDecision.Delay.class,
        svc.evaluate(loginAttempt("alice", null, T0.plus(window).minusNanos(1))),
        "events one tick younger than `window` must still count");
    // exactly `window` later: the boundary events have expired → Allow
    assertSame(AbuseDecision.Allow.INSTANCE,
        svc.evaluate(loginAttempt("alice", null, T0.plus(window))),
        "an event exactly `window` old must be evicted (half-open window)");
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
  @DisplayName("Concurrent failure records are never lost — no under-count under contention (R014)")
  void concurrentFailuresAreAllCounted() throws InterruptedException {
    // USERNAME failure-only counter, long window, and blockAt set EXACTLY to the
    // total number of failures recorded. If even one concurrent append is lost the
    // count stays below the threshold and the decision is Allow instead of Block.
    int threads = 16;
    int perThread = 500;
    int total = threads * perThread;
    // Limit fields are (window, delayAt, stepUpAt, blockAt, delayLen, blockLen):
    // only blockAt is set, exactly to the total, so the decision is Block iff
    // every concurrent failure was counted.
    AbuseLimitsPolicy policy = AbuseLimitsPolicy.builder()
        .with(AbuseAttemptType.LOGIN, AbuseDimension.USERNAME,
            new AbuseLimitsPolicy.Limit(
                Duration.ofHours(1), 0, 0, total,
                Duration.ofSeconds(1), Duration.ofMinutes(1)))
        .build();
    InMemoryAbuseDetectionService svc = new InMemoryAbuseDetectionService(
        policy, new RecordingAudit());
    AbuseAttemptContext ctx = loginAttempt("victim", null, T0);

    CountDownLatch start = new CountDownLatch(1);
    Thread[] pool = new Thread[threads];
    for (int i = 0; i < threads; i++) {
      pool[i] = new Thread(() -> {
        try {
          start.await();
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
          return;
        }
        for (int j = 0; j < perThread; j++) {
          svc.recordOutcome(ctx, AttemptOutcome.FAILURE);
        }
      });
    }
    for (Thread t : pool) {
      t.start();
    }
    start.countDown();
    for (Thread t : pool) {
      t.join();
    }

    // Exactly `total` failures were recorded — the counter must observe all of
    // them (blockAt == total → Block iff nothing was lost).
    assertInstanceOf(AbuseDecision.Block.class, svc.evaluate(ctx),
        "every concurrent failure append must be counted; a lost update would "
            + "leave the count below blockAt and bypass the block");
  }

  @Test
  @DisplayName("A success-reset clears the counter in place and it remains usable afterwards (R014)")
  void successResetClearsInPlaceAndCounterStaysUsable() {
    // Regression guard for the R014 fix: the success path clears the deque in
    // place instead of removing the map entry, so the counter keeps working for
    // the same (type, dimension, key) after a reset — re-accumulating to Block.
    InMemoryAbuseDetectionService svc = new InMemoryAbuseDetectionService(
        AbuseLimitsPolicy.defaults(), new RecordingAudit());
    AbuseAttemptContext ctx = loginAttempt("alice", null, T0);

    for (int i = 0; i < 15; i++) {
      svc.recordOutcome(ctx, AttemptOutcome.FAILURE);
    }
    assertInstanceOf(AbuseDecision.Block.class, svc.evaluate(ctx));

    svc.recordOutcome(ctx, AttemptOutcome.SUCCESS);
    assertSame(AbuseDecision.Allow.INSTANCE, svc.evaluate(ctx));

    // Re-accumulate on the very same key — proves the deque was cleared, not
    // orphaned/removed in a way that would drop subsequent failures.
    for (int i = 0; i < 15; i++) {
      svc.recordOutcome(ctx, AttemptOutcome.FAILURE);
    }
    assertInstanceOf(AbuseDecision.Block.class, svc.evaluate(ctx));
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
