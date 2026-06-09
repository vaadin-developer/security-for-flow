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
package com.svenruppert.jsentinel.authentication;

import com.svenruppert.jsentinel.audit.AuditEvent;
import com.svenruppert.jsentinel.audit.AuditQuery;
import com.svenruppert.jsentinel.audit.JSentinelAuditService;
import com.svenruppert.jsentinel.audit.TokenRotated;
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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("TokenService")
class TokenServiceTest {

  private static final SubjectId ALICE = new SubjectId("alice");
  private static final SubjectId BOB = new SubjectId("bob");
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
    AtomicLong counter = new AtomicLong();
    return () -> prefix + counter.incrementAndGet();
  }

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
  @DisplayName("issue stores only the refresh-token hash; access token is not persisted")
  void issueStoresOnlyRefreshHash() {
    InMemoryRefreshTokenStore store = new InMemoryRefreshTokenStore();
    CollectingAuditService audit = new CollectingAuditService();
    FakeHasher hasher = new FakeHasher();
    TokenService service = new TokenService(
        store, hasher, audit, TenantId.DEFAULT,
        steppingClock(T0, Duration.ofSeconds(1)), sequentialSource("t-"),
        Duration.ofMinutes(15), Duration.ofDays(30));

    TokenService.TokenPair pair = service.issue(ALICE);

    assertEquals("t-1", pair.accessToken());
    assertEquals("t-2", pair.refreshToken());
    assertEquals(ALICE, pair.subjectId());

    // Access token's hash must NOT be in the refresh store.
    assertTrue(store.findByHash(hasher.hash("t-1".toCharArray())).isEmpty());
    // Refresh token's hash IS in the store.
    assertTrue(store.findByHash(hasher.hash("t-2".toCharArray())).isPresent());

    // No audit emitted on issue (only rotation emits audit events).
    assertTrue(audit.published.isEmpty());
  }

  @Test
  @DisplayName("rotate consumes the old refresh, issues a new pair, emits TokenRotated")
  void rotateHappyPath() {
    InMemoryRefreshTokenStore store = new InMemoryRefreshTokenStore();
    CollectingAuditService audit = new CollectingAuditService();
    FakeHasher hasher = new FakeHasher();
    TokenService service = new TokenService(
        store, hasher, audit, TenantId.DEFAULT,
        steppingClock(T0, Duration.ofSeconds(1)), sequentialSource("t-"),
        Duration.ofMinutes(15), Duration.ofDays(30));

    TokenService.TokenPair initial = service.issue(ALICE);
    Optional<TokenService.TokenPair> rotated = service.rotate(initial.refreshToken());

    assertTrue(rotated.isPresent());
    assertNotEquals(initial.refreshToken(), rotated.get().refreshToken());
    assertNotEquals(initial.accessToken(), rotated.get().accessToken());
    assertEquals(ALICE, rotated.get().subjectId());

    // The old refresh is replaced
    assertTrue(store.findByHash(hasher.hash(initial.refreshToken().toCharArray()))
        .orElseThrow().isReplaced());
    // The new refresh is active
    assertTrue(store.findByHash(hasher.hash(rotated.get().refreshToken().toCharArray()))
        .orElseThrow().isActive(T0.plus(Duration.ofDays(1))));

    // A single TokenRotated audit event
    assertEquals(1, audit.published.size());
    TokenRotated event = (TokenRotated) audit.published.get(0);
    assertEquals("alice", event.subjectId());
    assertEquals(hasher.hash(initial.refreshToken().toCharArray()), event.oldHash());
    assertEquals(hasher.hash(rotated.get().refreshToken().toCharArray()), event.newHash());
  }

  @Test
  @DisplayName("rotate on an already-rotated refresh token is refused")
  void rotateOnReplayedRefuses() {
    InMemoryRefreshTokenStore store = new InMemoryRefreshTokenStore();
    CollectingAuditService audit = new CollectingAuditService();
    FakeHasher hasher = new FakeHasher();
    TokenService service = new TokenService(
        store, hasher, audit, TenantId.DEFAULT,
        steppingClock(T0, Duration.ofSeconds(1)), sequentialSource("t-"),
        Duration.ofMinutes(15), Duration.ofDays(30));

    TokenService.TokenPair initial = service.issue(ALICE);
    assertTrue(service.rotate(initial.refreshToken()).isPresent());

    Optional<TokenService.TokenPair> replay = service.rotate(initial.refreshToken());
    assertTrue(replay.isEmpty(), "replay must be refused");
  }

  @Test
  @DisplayName("rotate is tenant-scoped, refuses revoked and expired refreshes, blank input returns empty")
  void rotateNegativeCases() {
    InMemoryRefreshTokenStore store = new InMemoryRefreshTokenStore();
    FakeHasher hasher = new FakeHasher();
    Supplier<String> source = sequentialSource("t-");

    TokenService defaultSvc = new TokenService(
        store, hasher, new CollectingAuditService(), TenantId.DEFAULT,
        steppingClock(T0, Duration.ofSeconds(1)), source,
        Duration.ofMinutes(15), Duration.ofDays(30));
    TokenService acmeSvc = new TokenService(
        store, hasher, new CollectingAuditService(), new TenantId("acme"),
        steppingClock(T0, Duration.ofSeconds(1)), source,
        Duration.ofMinutes(15), Duration.ofDays(30));

    // foreign tenant
    TokenService.TokenPair acmePair = acmeSvc.issue(ALICE);
    assertTrue(defaultSvc.rotate(acmePair.refreshToken()).isEmpty());

    // revoked
    TokenService.TokenPair defaultPair = defaultSvc.issue(ALICE);
    assertTrue(defaultSvc.revoke(defaultPair.refreshToken()));
    assertTrue(defaultSvc.rotate(defaultPair.refreshToken()).isEmpty());

    // unknown / blank
    assertTrue(defaultSvc.rotate(null).isEmpty());
    assertTrue(defaultSvc.rotate("").isEmpty());
    assertTrue(defaultSvc.rotate("ghost").isEmpty());

    // expired: short-TTL service issues, future-clock service tries to rotate
    TokenService shortLived = new TokenService(
        store, hasher, new CollectingAuditService(), TenantId.DEFAULT,
        steppingClock(T0, Duration.ofSeconds(1)), source,
        Duration.ofMinutes(15), Duration.ofMinutes(1));
    String shortRefresh = shortLived.issue(BOB).refreshToken();
    TokenService future = new TokenService(
        store, hasher, new CollectingAuditService(), TenantId.DEFAULT,
        steppingClock(T0.plus(Duration.ofMinutes(5)), Duration.ofSeconds(1)),
        source, Duration.ofMinutes(15), Duration.ofDays(30));
    assertTrue(future.rotate(shortRefresh).isEmpty());
  }

  @Test
  @DisplayName("revoke marks a still-active refresh revoked exactly once; null/blank → false")
  void revokeIdempotent() {
    InMemoryRefreshTokenStore store = new InMemoryRefreshTokenStore();
    FakeHasher hasher = new FakeHasher();
    TokenService service = new TokenService(
        store, hasher, new CollectingAuditService(), TenantId.DEFAULT,
        steppingClock(T0, Duration.ofSeconds(1)), sequentialSource("t-"),
        Duration.ofMinutes(15), Duration.ofDays(30));

    TokenService.TokenPair pair = service.issue(ALICE);
    assertTrue(service.revoke(pair.refreshToken()));
    assertFalse(service.revoke(pair.refreshToken()), "second revoke is a no-op");
    assertFalse(service.revoke(""));
    assertFalse(service.revoke(null));
    assertFalse(service.revoke("ghost"));
  }

  @Test
  @DisplayName("revokeAll drops every refresh token of the subject within the tenant")
  void revokeAllScoped() {
    InMemoryRefreshTokenStore store = new InMemoryRefreshTokenStore();
    FakeHasher hasher = new FakeHasher();
    TokenService service = new TokenService(
        store, hasher, new CollectingAuditService(), TenantId.DEFAULT,
        steppingClock(T0, Duration.ofSeconds(1)), sequentialSource("t-"),
        Duration.ofMinutes(15), Duration.ofDays(30));

    service.issue(ALICE);
    service.issue(ALICE);
    service.issue(BOB);

    assertEquals(2, service.revokeAll(ALICE));
  }

  @Test
  @DisplayName("purgeExpired removes only past-expiry records")
  void purgeExpired() {
    InMemoryRefreshTokenStore store = new InMemoryRefreshTokenStore();
    FakeHasher hasher = new FakeHasher();
    Supplier<String> source = sequentialSource("t-");

    TokenService shortLived = new TokenService(
        store, hasher, new CollectingAuditService(), TenantId.DEFAULT,
        steppingClock(T0, Duration.ofSeconds(1)), source,
        Duration.ofMinutes(15), Duration.ofMinutes(1));
    shortLived.issue(ALICE);

    TokenService future = new TokenService(
        store, hasher, new CollectingAuditService(), TenantId.DEFAULT,
        steppingClock(T0.plus(Duration.ofMinutes(5)), Duration.ofSeconds(1)),
        source, Duration.ofMinutes(15), Duration.ofDays(30));
    TokenService.TokenPair live = future.issue(BOB);

    assertEquals(1, future.purgeExpired());
    assertTrue(future.rotate(live.refreshToken()).isPresent());
  }

  @Test
  @DisplayName("audit failures are swallowed during rotation")
  void auditFailuresSwallowed() {
    InMemoryRefreshTokenStore store = new InMemoryRefreshTokenStore();
    JSentinelAuditService throwing = new JSentinelAuditService() {
      @Override public void publish(AuditEvent event) { throw new RuntimeException("boom"); }
      @Override public List<AuditEvent> query(AuditQuery query) { return List.of(); }
    };
    TokenService service = new TokenService(
        store, new FakeHasher(), throwing, TenantId.DEFAULT,
        steppingClock(T0, Duration.ofSeconds(1)), sequentialSource("t-"),
        Duration.ofMinutes(15), Duration.ofDays(30));

    TokenService.TokenPair pair = service.issue(ALICE);
    assertTrue(service.rotate(pair.refreshToken()).isPresent());
  }

  @Test
  @DisplayName("null arguments and non-positive TTLs are rejected; blank token source fails on issue")
  void rejectNulls() {
    InMemoryRefreshTokenStore store = new InMemoryRefreshTokenStore();
    FakeHasher hasher = new FakeHasher();
    CollectingAuditService audit = new CollectingAuditService();

    assertThrows(NullPointerException.class,
        () -> new TokenService(null, hasher, audit));
    assertThrows(NullPointerException.class,
        () -> new TokenService(store, null, audit));
    assertThrows(NullPointerException.class,
        () -> new TokenService(store, hasher, null));
    assertThrows(IllegalArgumentException.class,
        () -> new TokenService(store, hasher, audit, TenantId.DEFAULT,
            Clock.systemUTC(), sequentialSource("t-"),
            Duration.ZERO, Duration.ofDays(1)));
    assertThrows(IllegalArgumentException.class,
        () -> new TokenService(store, hasher, audit, TenantId.DEFAULT,
            Clock.systemUTC(), sequentialSource("t-"),
            Duration.ofMinutes(1), Duration.ofSeconds(-1)));

    TokenService service = new TokenService(
        store, hasher, audit, TenantId.DEFAULT,
        steppingClock(T0, Duration.ofSeconds(1)), sequentialSource("t-"),
        Duration.ofMinutes(15), Duration.ofDays(30));
    assertThrows(NullPointerException.class, () -> service.issue(null));
    assertThrows(NullPointerException.class, () -> service.revokeAll(null));

    TokenService bad = new TokenService(
        store, hasher, audit, TenantId.DEFAULT,
        steppingClock(T0, Duration.ofSeconds(1)), () -> "  ",
        Duration.ofMinutes(15), Duration.ofDays(30));
    assertThrows(IllegalStateException.class, () -> bad.issue(ALICE));
  }

  @Test
  @DisplayName("default constructor uses TenantId.DEFAULT and 256-bit token source")
  void defaultConstructorSmoke() {
    InMemoryRefreshTokenStore store = new InMemoryRefreshTokenStore();
    TokenService service = new TokenService(
        store, new FakeHasher(), new CollectingAuditService());
    TokenService.TokenPair pair = service.issue(ALICE);
    assertEquals(43, pair.accessToken().length());
    assertEquals(43, pair.refreshToken().length());
    assertNotEquals(pair.accessToken(), pair.refreshToken());
  }

  private static final class CollectingAuditService implements JSentinelAuditService {
    final List<AuditEvent> published = new ArrayList<>();
    @Override public void publish(AuditEvent event) { published.add(event); }
    @Override public List<AuditEvent> query(AuditQuery query) { return List.copyOf(published); }
  }
}
