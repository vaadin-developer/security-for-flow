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
package com.svenruppert.vaadin.security.accountlifecycle;

import com.svenruppert.vaadin.security.audit.AuditEvent;
import com.svenruppert.vaadin.security.audit.AuditQuery;
import com.svenruppert.vaadin.security.audit.PasswordResetCompleted;
import com.svenruppert.vaadin.security.audit.PasswordResetRequested;
import com.svenruppert.vaadin.security.audit.JSentinelAuditService;
import com.svenruppert.vaadin.security.authentication.PasswordHasher;
import com.svenruppert.vaadin.security.authorization.api.tenant.TenantId;
import com.svenruppert.vaadin.security.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("PasswordResetService")
class PasswordResetServiceTest {

  private static final SubjectId ALICE = new SubjectId("alice");
  private static final SubjectId BOB = new SubjectId("bob");
  private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");

  /** Deterministic hasher mirroring StoreBackedRememberMeServiceTest. */
  private static final class FakeHasher implements PasswordHasher {
    @Override public String hash(char[] raw) {
      return "h:" + HexFormat.of().formatHex(new String(raw).getBytes());
    }
    @Override public boolean verify(char[] raw, String stored) {
      return hash(raw).equals(stored);
    }
  }

  private static Supplier<String> sequentialSource(String prefix) {
    AtomicLong counter = new AtomicLong();
    return () -> prefix + counter.incrementAndGet();
  }

  private static Clock fixed(Instant at) { return Clock.fixed(at, ZoneOffset.UTC); }

  /**
   * Clock that advances by {@code step} on every {@code instant()} call —
   * lets consume() see a later instant than request() under a deterministic
   * test setup, satisfying the record's "consumedAt > createdAt" invariant.
   */
  private static Clock steppingClock(Instant start, Duration step) {
    return new Clock() {
      private Instant cursor = start.minus(step);
      @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
      @Override public Clock withZone(java.time.ZoneId zone) { return this; }
      @Override public synchronized Instant instant() {
        cursor = cursor.plus(step);
        return cursor;
      }
    };
  }

  @Test
  @DisplayName("request issues a token, stores only the hash, emits audit + notification")
  void requestStoresHashAndNotifies() {
    InMemoryPasswordResetTokenStore store = new InMemoryPasswordResetTokenStore();
    CollectingAuditService audit = new CollectingAuditService();
    RecordingNotificationSender sender = new RecordingNotificationSender();
    PasswordHasher hasher = new FakeHasher();

    PasswordResetService service = new PasswordResetService(
        store, hasher, audit, sender, TenantId.DEFAULT, fixed(T0),
        sequentialSource("tok-"));

    PasswordResetService.IssuedToken issued = service.request(ALICE, Duration.ofMinutes(15));
    assertEquals("tok-1", issued.plainToken());
    assertEquals(hasher.hash("tok-1".toCharArray()), issued.record().tokenHash());

    // hash is stored, plain is not
    assertTrue(store.findByHash("tok-1").isEmpty());
    assertTrue(store.findByHash(hasher.hash("tok-1".toCharArray())).isPresent());

    // audit
    assertEquals(1, audit.published.size());
    PasswordResetRequested event = (PasswordResetRequested) audit.published.get(0);
    assertEquals("alice", event.subjectId());
    assertEquals(T0, event.timestamp());

    // notification with plain token
    assertEquals(1, sender.received.size());
    JSentinelNotification n = sender.received.get(0);
    assertEquals(JSentinelNotification.Kind.PASSWORD_RESET_REQUESTED, n.kind());
    assertEquals("tok-1", n.attributes().get("tokenPlain"));
    assertEquals(issued.record().expiresAt().toString(), n.attributes().get("expiresAt"));
  }

  @Test
  @DisplayName("validate accepts a live token and rejects unknown / wrong-tenant / consumed / expired")
  void validateNegativeCases() {
    InMemoryPasswordResetTokenStore store = new InMemoryPasswordResetTokenStore();
    PasswordHasher hasher = new FakeHasher();
    PasswordResetService defaultSvc = new PasswordResetService(
        store, hasher, new CollectingAuditService(), new RecordingNotificationSender(),
        TenantId.DEFAULT, fixed(T0), sequentialSource("def-"));
    PasswordResetService acmeSvc = new PasswordResetService(
        store, hasher, new CollectingAuditService(), new RecordingNotificationSender(),
        new TenantId("acme"), fixed(T0), sequentialSource("acme-"));

    String good = defaultSvc.request(ALICE, Duration.ofMinutes(15)).plainToken();
    assertTrue(defaultSvc.validate(good).isPresent());

    // unknown / blank
    assertTrue(defaultSvc.validate(null).isEmpty());
    assertTrue(defaultSvc.validate("").isEmpty());
    assertTrue(defaultSvc.validate("ghost").isEmpty());

    // wrong tenant
    String acmePlain = acmeSvc.request(ALICE, Duration.ofMinutes(15)).plainToken();
    assertTrue(defaultSvc.validate(acmePlain).isEmpty(),
        "validate must be tenant-scoped");

    // expired: advance the clock past expiry
    PasswordResetService shortLived = new PasswordResetService(
        store, hasher, new CollectingAuditService(), new RecordingNotificationSender(),
        TenantId.DEFAULT, fixed(T0), sequentialSource("short-"));
    String shortPlain = shortLived.request(ALICE, Duration.ofMinutes(1)).plainToken();
    PasswordResetService future = new PasswordResetService(
        store, hasher, new CollectingAuditService(), new RecordingNotificationSender(),
        TenantId.DEFAULT, fixed(T0.plus(Duration.ofMinutes(2))), sequentialSource("unused-"));
    assertTrue(future.validate(shortPlain).isEmpty());
  }

  @Test
  @DisplayName("consume marks the record consumed exactly once and emits PasswordResetCompleted")
  void consumeIsSingleUse() {
    InMemoryPasswordResetTokenStore store = new InMemoryPasswordResetTokenStore();
    PasswordHasher hasher = new FakeHasher();
    CollectingAuditService audit = new CollectingAuditService();
    RecordingNotificationSender sender = new RecordingNotificationSender();
    PasswordResetService service = new PasswordResetService(
        store, hasher, audit, sender, TenantId.DEFAULT,
        steppingClock(T0, Duration.ofSeconds(1)),
        sequentialSource("tok-"));

    String plain = service.request(ALICE, Duration.ofMinutes(15)).plainToken();

    Optional<PasswordResetTokenRecord> first = service.consume(plain);
    assertTrue(first.isPresent());
    assertTrue(first.get().isConsumed());

    Optional<PasswordResetTokenRecord> second = service.consume(plain);
    assertTrue(second.isEmpty(), "second consume must yield empty (single-use)");

    // 1 Requested + 1 Completed
    assertEquals(2, audit.published.size());
    assertTrue(audit.published.get(1) instanceof PasswordResetCompleted);
    PasswordResetCompleted completed = (PasswordResetCompleted) audit.published.get(1);
    assertEquals("alice", completed.subjectId());

    // request notification + completion notification
    assertEquals(2, sender.received.size());
    assertEquals(JSentinelNotification.Kind.PASSWORD_RESET_COMPLETED,
        sender.received.get(1).kind());
  }

  @Test
  @DisplayName("revokeAll removes only the subject's tokens within the tenant")
  void revokeAllScoped() {
    InMemoryPasswordResetTokenStore store = new InMemoryPasswordResetTokenStore();
    PasswordHasher hasher = new FakeHasher();
    PasswordResetService service = new PasswordResetService(
        store, hasher, new CollectingAuditService(), new RecordingNotificationSender(),
        TenantId.DEFAULT, fixed(T0), sequentialSource("tok-"));

    String a1 = service.request(ALICE, Duration.ofMinutes(15)).plainToken();
    String a2 = service.request(ALICE, Duration.ofMinutes(15)).plainToken();
    String b1 = service.request(BOB, Duration.ofMinutes(15)).plainToken();
    assertNotEquals(a1, a2);

    int removed = service.revokeAll(ALICE);
    assertEquals(2, removed);
    assertTrue(service.validate(a1).isEmpty());
    assertTrue(service.validate(a2).isEmpty());
    assertTrue(service.validate(b1).isPresent());
  }

  @Test
  @DisplayName("purgeExpired removes expired records")
  void purgeExpired() {
    InMemoryPasswordResetTokenStore store = new InMemoryPasswordResetTokenStore();
    PasswordHasher hasher = new FakeHasher();
    Supplier<String> source = sequentialSource("tok-");
    PasswordResetService shortLived = new PasswordResetService(
        store, hasher, new CollectingAuditService(), new RecordingNotificationSender(),
        TenantId.DEFAULT, fixed(T0), source);
    shortLived.request(ALICE, Duration.ofMinutes(1));

    PasswordResetService future = new PasswordResetService(
        store, hasher, new CollectingAuditService(), new RecordingNotificationSender(),
        TenantId.DEFAULT, fixed(T0.plus(Duration.ofMinutes(2))), source);
    String live = future.request(BOB, Duration.ofDays(1)).plainToken();

    int purged = future.purgeExpired();
    assertEquals(1, purged);
    assertTrue(future.validate(live).isPresent());
  }

  @Test
  @DisplayName("audit + notification failures do not block the lifecycle flow")
  void sinkFailuresSwallowed() {
    InMemoryPasswordResetTokenStore store = new InMemoryPasswordResetTokenStore();
    JSentinelAuditService throwingAudit = new JSentinelAuditService() {
      @Override public void publish(AuditEvent event) { throw new RuntimeException("boom"); }
      @Override public List<AuditEvent> query(AuditQuery query) { return List.of(); }
    };
    JSentinelNotificationSender throwingSender = n -> { throw new RuntimeException("boom"); };
    PasswordResetService service = new PasswordResetService(
        store, new FakeHasher(), throwingAudit, throwingSender,
        TenantId.DEFAULT, steppingClock(T0, Duration.ofSeconds(1)),
        sequentialSource("tok-"));

    PasswordResetService.IssuedToken issued = service.request(ALICE, Duration.ofMinutes(15));
    assertEquals("tok-1", issued.plainToken());
    Optional<PasswordResetTokenRecord> consumed = service.consume(issued.plainToken());
    assertTrue(consumed.isPresent(), "consume must complete even when audit/notify throw");
  }

  @Test
  @DisplayName("null arguments / non-positive TTL / blank token source are rejected")
  void rejectNulls() {
    InMemoryPasswordResetTokenStore store = new InMemoryPasswordResetTokenStore();
    PasswordHasher hasher = new FakeHasher();
    CollectingAuditService audit = new CollectingAuditService();
    RecordingNotificationSender sender = new RecordingNotificationSender();

    assertThrows(NullPointerException.class,
        () -> new PasswordResetService(null, hasher, audit, sender));
    assertThrows(NullPointerException.class,
        () -> new PasswordResetService(store, null, audit, sender));
    assertThrows(NullPointerException.class,
        () -> new PasswordResetService(store, hasher, null, sender));
    assertThrows(NullPointerException.class,
        () -> new PasswordResetService(store, hasher, audit, null));

    PasswordResetService service = new PasswordResetService(
        store, hasher, audit, sender, TenantId.DEFAULT, fixed(T0), sequentialSource("tok-"));
    assertThrows(NullPointerException.class,
        () -> service.request(null, Duration.ofMinutes(1)));
    assertThrows(NullPointerException.class,
        () -> service.request(ALICE, null));
    assertThrows(IllegalArgumentException.class,
        () -> service.request(ALICE, Duration.ZERO));
    assertThrows(IllegalArgumentException.class,
        () -> service.request(ALICE, Duration.ofSeconds(-1)));
    assertThrows(NullPointerException.class, () -> service.revokeAll(null));

    PasswordResetService bad = new PasswordResetService(
        store, hasher, audit, sender, TenantId.DEFAULT, fixed(T0), () -> " ");
    assertThrows(IllegalStateException.class,
        () -> bad.request(ALICE, Duration.ofMinutes(1)));
  }

  @Test
  @DisplayName("default constructor uses TenantId.DEFAULT and a 256-bit token source")
  void defaultConstructorSmoke() {
    InMemoryPasswordResetTokenStore store = new InMemoryPasswordResetTokenStore();
    PasswordResetService service = new PasswordResetService(
        store, new FakeHasher(), new CollectingAuditService(),
        new RecordingNotificationSender());

    PasswordResetService.IssuedToken issued = service.request(ALICE, Duration.ofMinutes(5));
    assertEquals(TenantId.DEFAULT, issued.record().tenant());
    // 32 bytes → base64-url unpadded → 43 chars
    assertEquals(43, issued.plainToken().length());
    assertNotEquals(issued.plainToken(),
        service.request(ALICE, Duration.ofMinutes(5)).plainToken());
    assertFalse(issued.record().isConsumed());
  }

  private static final class CollectingAuditService implements JSentinelAuditService {
    final List<AuditEvent> published = new ArrayList<>();
    @Override public void publish(AuditEvent event) { published.add(event); }
    @Override public List<AuditEvent> query(AuditQuery query) { return List.copyOf(published); }
  }

  private static final class RecordingNotificationSender implements JSentinelNotificationSender {
    final List<JSentinelNotification> received = new ArrayList<>();
    @Override public void send(JSentinelNotification n) { received.add(n); }
  }
}
