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
package com.svenruppert.jsentinel.accountlifecycle;

import com.svenruppert.jsentinel.audit.AuditEvent;
import com.svenruppert.jsentinel.audit.AuditQuery;
import com.svenruppert.jsentinel.audit.EmailVerificationRequested;
import com.svenruppert.jsentinel.audit.EmailVerified;
import com.svenruppert.jsentinel.audit.JSentinelAuditService;
import com.svenruppert.jsentinel.authentication.PasswordHasher;
import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import com.svenruppert.jsentinel.logout.SubjectId;
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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("EmailVerificationService")
class EmailVerificationServiceTest {

  private static final SubjectId ALICE = new SubjectId("alice");
  private static final SubjectId BOB = new SubjectId("bob");
  private static final String ALICE_EMAIL = "alice@example.com";
  private static final String BOB_EMAIL = "bob@example.com";
  private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");

  private static final class FakeHasher implements PasswordHasher {
    @Override public String hash(char[] raw) {
      return "h:" + HexFormat.of().formatHex(new String(raw).getBytes());
    }
    @Override public boolean verify(char[] raw, String stored) {
      return hash(raw).equals(stored);
    }
  }

  private static Supplier<String> sequentialSource(String prefix) {
    AtomicLong c = new AtomicLong();
    return () -> prefix + c.incrementAndGet();
  }

  private static Clock fixed(Instant at) { return Clock.fixed(at, ZoneOffset.UTC); }

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
  @DisplayName("request stores only the hash, emits audit + notification with email + tokenPlain")
  void requestHashesAndNotifies() {
    InMemoryEmailVerificationTokenStore store = new InMemoryEmailVerificationTokenStore();
    CollectingAuditService audit = new CollectingAuditService();
    RecordingNotificationSender sender = new RecordingNotificationSender();
    PasswordHasher hasher = new FakeHasher();

    EmailVerificationService service = new EmailVerificationService(
        store, hasher, audit, sender, TenantId.DEFAULT, fixed(T0),
        sequentialSource("tok-"));

    EmailVerificationService.IssuedToken issued =
        service.request(ALICE, ALICE_EMAIL, Duration.ofHours(24));

    assertEquals("tok-1", issued.plainToken());
    assertEquals(ALICE_EMAIL, issued.record().email());
    assertEquals(hasher.hash("tok-1".toCharArray()), issued.record().tokenHash());
    assertTrue(store.findByHash("tok-1").isEmpty());
    assertTrue(store.findByHash(hasher.hash("tok-1".toCharArray())).isPresent());

    EmailVerificationRequested event = (EmailVerificationRequested) audit.published.get(0);
    assertEquals("alice", event.subjectId());
    assertEquals(ALICE_EMAIL, event.email());

    JSentinelNotification n = sender.received.get(0);
    assertEquals(JSentinelNotification.Kind.EMAIL_VERIFICATION_REQUESTED, n.kind());
    assertEquals("tok-1", n.attributes().get("tokenPlain"));
    assertEquals(ALICE_EMAIL, n.attributes().get("email"));
  }

  @Test
  @DisplayName("validate rejects unknown / wrong tenant / expired tokens")
  void validateNegativeCases() {
    InMemoryEmailVerificationTokenStore store = new InMemoryEmailVerificationTokenStore();
    PasswordHasher hasher = new FakeHasher();
    EmailVerificationService defaultSvc = new EmailVerificationService(
        store, hasher, new CollectingAuditService(), new RecordingNotificationSender(),
        TenantId.DEFAULT, fixed(T0), sequentialSource("def-"));
    EmailVerificationService acmeSvc = new EmailVerificationService(
        store, hasher, new CollectingAuditService(), new RecordingNotificationSender(),
        new TenantId("acme"), fixed(T0), sequentialSource("acme-"));

    String good = defaultSvc.request(ALICE, ALICE_EMAIL, Duration.ofMinutes(15)).plainToken();
    assertTrue(defaultSvc.validate(good).isPresent());

    assertTrue(defaultSvc.validate(null).isEmpty());
    assertTrue(defaultSvc.validate("").isEmpty());
    assertTrue(defaultSvc.validate("ghost").isEmpty());

    String acmePlain = acmeSvc.request(ALICE, ALICE_EMAIL, Duration.ofMinutes(15)).plainToken();
    assertTrue(defaultSvc.validate(acmePlain).isEmpty());

    EmailVerificationService shortLived = new EmailVerificationService(
        store, hasher, new CollectingAuditService(), new RecordingNotificationSender(),
        TenantId.DEFAULT, fixed(T0), sequentialSource("short-"));
    String shortPlain = shortLived.request(ALICE, ALICE_EMAIL, Duration.ofMinutes(1)).plainToken();
    EmailVerificationService future = new EmailVerificationService(
        store, hasher, new CollectingAuditService(), new RecordingNotificationSender(),
        TenantId.DEFAULT, fixed(T0.plus(Duration.ofMinutes(2))), sequentialSource("unused-"));
    assertTrue(future.validate(shortPlain).isEmpty());
  }

  @Test
  @DisplayName("consume is single-use and emits EmailVerified")
  void consumeIsSingleUse() {
    InMemoryEmailVerificationTokenStore store = new InMemoryEmailVerificationTokenStore();
    PasswordHasher hasher = new FakeHasher();
    CollectingAuditService audit = new CollectingAuditService();
    RecordingNotificationSender sender = new RecordingNotificationSender();
    EmailVerificationService service = new EmailVerificationService(
        store, hasher, audit, sender, TenantId.DEFAULT,
        steppingClock(T0, Duration.ofSeconds(1)), sequentialSource("tok-"));

    String plain = service.request(ALICE, ALICE_EMAIL, Duration.ofMinutes(15)).plainToken();

    Optional<EmailVerificationTokenRecord> first = service.consume(plain);
    assertTrue(first.isPresent());
    assertTrue(first.get().isConsumed());

    Optional<EmailVerificationTokenRecord> second = service.consume(plain);
    assertTrue(second.isEmpty(), "second consume must yield empty");

    assertEquals(2, audit.published.size());
    EmailVerified verified = (EmailVerified) audit.published.get(1);
    assertEquals("alice", verified.subjectId());
    assertEquals(ALICE_EMAIL, verified.email());

    assertEquals(2, sender.received.size());
    assertEquals(JSentinelNotification.Kind.EMAIL_VERIFIED, sender.received.get(1).kind());
    assertEquals(ALICE_EMAIL, sender.received.get(1).attributes().get("email"));
  }

  @Test
  @DisplayName("revokeAll removes only the subject's tokens within the tenant")
  void revokeAllScoped() {
    InMemoryEmailVerificationTokenStore store = new InMemoryEmailVerificationTokenStore();
    PasswordHasher hasher = new FakeHasher();
    EmailVerificationService service = new EmailVerificationService(
        store, hasher, new CollectingAuditService(), new RecordingNotificationSender(),
        TenantId.DEFAULT, fixed(T0), sequentialSource("tok-"));

    String a1 = service.request(ALICE, ALICE_EMAIL, Duration.ofMinutes(15)).plainToken();
    String a2 = service.request(ALICE, ALICE_EMAIL, Duration.ofMinutes(15)).plainToken();
    String b1 = service.request(BOB, BOB_EMAIL, Duration.ofMinutes(15)).plainToken();
    assertNotEquals(a1, a2);

    assertEquals(2, service.revokeAll(ALICE));
    assertTrue(service.validate(a1).isEmpty());
    assertTrue(service.validate(a2).isEmpty());
    assertTrue(service.validate(b1).isPresent());
  }

  @Test
  @DisplayName("audit + notification failures do not block the lifecycle flow")
  void sinkFailuresSwallowed() {
    InMemoryEmailVerificationTokenStore store = new InMemoryEmailVerificationTokenStore();
    JSentinelAuditService throwingAudit = new JSentinelAuditService() {
      @Override public void publish(AuditEvent event) { throw new RuntimeException("boom"); }
      @Override public List<AuditEvent> query(AuditQuery query) { return List.of(); }
    };
    JSentinelNotificationSender throwingSender = n -> { throw new RuntimeException("boom"); };
    EmailVerificationService service = new EmailVerificationService(
        store, new FakeHasher(), throwingAudit, throwingSender,
        TenantId.DEFAULT, steppingClock(T0, Duration.ofSeconds(1)),
        sequentialSource("tok-"));

    var issued = service.request(ALICE, ALICE_EMAIL, Duration.ofMinutes(15));
    assertEquals("tok-1", issued.plainToken());
    Optional<EmailVerificationTokenRecord> consumed = service.consume(issued.plainToken());
    assertTrue(consumed.isPresent());
  }

  @Test
  @DisplayName("null / blank arguments + non-positive TTL are rejected")
  void rejectNulls() {
    InMemoryEmailVerificationTokenStore store = new InMemoryEmailVerificationTokenStore();
    PasswordHasher hasher = new FakeHasher();
    CollectingAuditService audit = new CollectingAuditService();
    RecordingNotificationSender sender = new RecordingNotificationSender();

    assertThrows(NullPointerException.class,
        () -> new EmailVerificationService(null, hasher, audit, sender));
    assertThrows(NullPointerException.class,
        () -> new EmailVerificationService(store, null, audit, sender));

    EmailVerificationService service = new EmailVerificationService(
        store, hasher, audit, sender, TenantId.DEFAULT, fixed(T0), sequentialSource("tok-"));

    assertThrows(NullPointerException.class,
        () -> service.request(null, ALICE_EMAIL, Duration.ofMinutes(1)));
    assertThrows(IllegalArgumentException.class,
        () -> service.request(ALICE, "", Duration.ofMinutes(1)));
    assertThrows(IllegalArgumentException.class,
        () -> service.request(ALICE, null, Duration.ofMinutes(1)));
    assertThrows(NullPointerException.class,
        () -> service.request(ALICE, ALICE_EMAIL, null));
    assertThrows(IllegalArgumentException.class,
        () -> service.request(ALICE, ALICE_EMAIL, Duration.ZERO));
    assertThrows(NullPointerException.class, () -> service.revokeAll(null));

    EmailVerificationService bad = new EmailVerificationService(
        store, hasher, audit, sender, TenantId.DEFAULT, fixed(T0), () -> "");
    assertThrows(IllegalStateException.class,
        () -> bad.request(ALICE, ALICE_EMAIL, Duration.ofMinutes(1)));
  }

  @Test
  @DisplayName("default constructor uses TenantId.DEFAULT and 256-bit token source")
  void defaultConstructorSmoke() {
    InMemoryEmailVerificationTokenStore store = new InMemoryEmailVerificationTokenStore();
    EmailVerificationService service = new EmailVerificationService(
        store, new FakeHasher(), new CollectingAuditService(),
        new RecordingNotificationSender());
    var issued = service.request(ALICE, ALICE_EMAIL, Duration.ofMinutes(5));
    assertEquals(TenantId.DEFAULT, issued.record().tenant());
    assertEquals(43, issued.plainToken().length());
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
