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
package com.svenruppert.vaadin.security.authentication;

import com.svenruppert.vaadin.security.authorization.api.tenant.TenantId;
import com.svenruppert.vaadin.security.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("StoreBackedRememberMeService")
class StoreBackedRememberMeServiceTest {

  private static final SubjectId ALICE = new SubjectId("alice");
  private static final SubjectId BOB = new SubjectId("bob");
  private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");

  /** Trivial hasher — sha-1-style with raw chars; deterministic and reversible enough for tests. */
  private static final class FakeHasher implements PasswordHasher {
    @Override public String hash(char[] raw) {
      return "h:" + HexFormat.of().formatHex(new String(raw).getBytes());
    }
    @Override public boolean verify(char[] raw, String stored) {
      return hash(raw).equals(stored);
    }
  }

  /** Counter-based token supplier so tests can predict the issued plaintext. */
  private static Supplier<String> sequentialSource(String prefix) {
    AtomicLong counter = new AtomicLong();
    return () -> prefix + counter.incrementAndGet();
  }

  private static Clock fixed(Instant at) {
    return Clock.fixed(at, ZoneOffset.UTC);
  }

  @Test
  @DisplayName("issue stores only the hash; plain token is returned exactly once")
  void issueStoresHash() {
    InMemoryRememberMeTokenStore store = new InMemoryRememberMeTokenStore();
    PasswordHasher hasher = new FakeHasher();
    StoreBackedRememberMeService service = new StoreBackedRememberMeService(
        store, hasher, TenantId.DEFAULT, fixed(T0), sequentialSource("tok-"));

    StoreBackedRememberMeService.IssuedToken issued =
        service.issue(ALICE, Duration.ofDays(7));

    assertEquals("tok-1", issued.plainToken());
    assertEquals(hasher.hash("tok-1".toCharArray()), issued.record().tokenHash());
    assertEquals(T0, issued.record().createdAt());
    assertEquals(T0.plus(Duration.ofDays(7)), issued.record().expiresAt());
    // Plain token must not be stored — only the hash is queryable
    assertTrue(store.findByHash("tok-1").isEmpty());
    assertTrue(store.findByHash(hasher.hash("tok-1".toCharArray())).isPresent());
  }

  @Test
  @DisplayName("validate returns the record for a known, unexpired token")
  void validateHappyPath() {
    InMemoryRememberMeTokenStore store = new InMemoryRememberMeTokenStore();
    PasswordHasher hasher = new FakeHasher();
    StoreBackedRememberMeService service = new StoreBackedRememberMeService(
        store, hasher, TenantId.DEFAULT, fixed(T0), sequentialSource("tok-"));

    String plain = service.issue(ALICE, Duration.ofDays(7)).plainToken();
    Optional<RememberMeTokenRecord> match = service.validate(plain);

    assertTrue(match.isPresent());
    assertEquals(ALICE, match.get().subjectId());
  }

  @Test
  @DisplayName("validate rejects unknown / blank / wrong-tenant / expired tokens")
  void validateNegativeCases() {
    InMemoryRememberMeTokenStore store = new InMemoryRememberMeTokenStore();
    PasswordHasher hasher = new FakeHasher();

    StoreBackedRememberMeService defaultSvc = new StoreBackedRememberMeService(
        store, hasher, TenantId.DEFAULT, fixed(T0), sequentialSource("def-"));
    StoreBackedRememberMeService acmeSvc = new StoreBackedRememberMeService(
        store, hasher, new TenantId("acme"), fixed(T0), sequentialSource("acme-"));

    // unknown / blank
    assertTrue(defaultSvc.validate("ghost").isEmpty());
    assertTrue(defaultSvc.validate("").isEmpty());
    assertTrue(defaultSvc.validate(null).isEmpty());

    // foreign tenant: token issued by acme must NOT validate via default
    String acmePlain = acmeSvc.issue(ALICE, Duration.ofDays(7)).plainToken();
    assertTrue(defaultSvc.validate(acmePlain).isEmpty(),
        "validate is tenant-scoped");

    // expired: advance the clock past expiry
    StoreBackedRememberMeService shortLived = new StoreBackedRememberMeService(
        store, hasher, TenantId.DEFAULT, fixed(T0), sequentialSource("short-"));
    String shortPlain = shortLived.issue(ALICE, Duration.ofMinutes(1)).plainToken();

    StoreBackedRememberMeService future = new StoreBackedRememberMeService(
        store, hasher, TenantId.DEFAULT, fixed(T0.plus(Duration.ofMinutes(2))),
        sequentialSource("unused-"));
    assertTrue(future.validate(shortPlain).isEmpty());
    // Side effect: expired record is purged
    assertTrue(store.findByHash(hasher.hash(shortPlain.toCharArray())).isEmpty(),
        "validate must purge an expired match");
  }

  @Test
  @DisplayName("revoke is idempotent and only the matching token is removed")
  void revokeIdempotent() {
    InMemoryRememberMeTokenStore store = new InMemoryRememberMeTokenStore();
    PasswordHasher hasher = new FakeHasher();
    StoreBackedRememberMeService service = new StoreBackedRememberMeService(
        store, hasher, TenantId.DEFAULT, fixed(T0), sequentialSource("tok-"));

    String a = service.issue(ALICE, Duration.ofDays(1)).plainToken();
    String b = service.issue(BOB, Duration.ofDays(1)).plainToken();
    assertNotEquals(a, b);

    assertTrue(service.revoke(a));
    assertFalse(service.revoke(a), "second revoke is a no-op");
    assertTrue(service.validate(a).isEmpty());
    assertTrue(service.validate(b).isPresent());
    assertFalse(service.revoke(""));
    assertFalse(service.revoke(null));
  }

  @Test
  @DisplayName("revokeAll removes every token of the subject within the tenant")
  void revokeAllScoped() {
    InMemoryRememberMeTokenStore store = new InMemoryRememberMeTokenStore();
    PasswordHasher hasher = new FakeHasher();
    StoreBackedRememberMeService service = new StoreBackedRememberMeService(
        store, hasher, TenantId.DEFAULT, fixed(T0), sequentialSource("tok-"));

    String alice1 = service.issue(ALICE, Duration.ofDays(1)).plainToken();
    String alice2 = service.issue(ALICE, Duration.ofDays(1)).plainToken();
    String bobTok = service.issue(BOB, Duration.ofDays(1)).plainToken();

    int removed = service.revokeAll(ALICE);
    assertEquals(2, removed);
    assertTrue(service.validate(alice1).isEmpty());
    assertTrue(service.validate(alice2).isEmpty());
    assertTrue(service.validate(bobTok).isPresent());
  }

  @Test
  @DisplayName("purgeExpired clears expired records and leaves live ones")
  void purgeExpired() {
    InMemoryRememberMeTokenStore store = new InMemoryRememberMeTokenStore();
    PasswordHasher hasher = new FakeHasher();
    Supplier<String> source = sequentialSource("tok-");

    StoreBackedRememberMeService shortLived = new StoreBackedRememberMeService(
        store, hasher, TenantId.DEFAULT, fixed(T0), source);
    shortLived.issue(ALICE, Duration.ofMinutes(1));

    StoreBackedRememberMeService future = new StoreBackedRememberMeService(
        store, hasher, TenantId.DEFAULT, fixed(T0.plus(Duration.ofMinutes(2))),
        source);
    String live = future.issue(BOB, Duration.ofDays(1)).plainToken();

    int purged = future.purgeExpired();
    assertEquals(1, purged);
    assertTrue(future.validate(live).isPresent());
  }

  @Test
  @DisplayName("null arguments, non-positive TTL, blank token source are rejected")
  void rejectNulls() {
    InMemoryRememberMeTokenStore store = new InMemoryRememberMeTokenStore();
    PasswordHasher hasher = new FakeHasher();
    StoreBackedRememberMeService service = new StoreBackedRememberMeService(
        store, hasher, TenantId.DEFAULT, fixed(T0), sequentialSource("tok-"));

    assertThrows(NullPointerException.class,
        () -> new StoreBackedRememberMeService(null, hasher));
    assertThrows(NullPointerException.class,
        () -> new StoreBackedRememberMeService(store, null));
    assertThrows(NullPointerException.class,
        () -> service.issue(null, Duration.ofMinutes(1)));
    assertThrows(NullPointerException.class,
        () -> service.issue(ALICE, null));
    assertThrows(IllegalArgumentException.class,
        () -> service.issue(ALICE, Duration.ZERO));
    assertThrows(IllegalArgumentException.class,
        () -> service.issue(ALICE, Duration.ofSeconds(-1)));
    assertThrows(NullPointerException.class,
        () -> service.revokeAll(null));

    StoreBackedRememberMeService bad = new StoreBackedRememberMeService(
        store, hasher, TenantId.DEFAULT, fixed(T0), () -> " ");
    assertThrows(IllegalStateException.class,
        () -> bad.issue(ALICE, Duration.ofMinutes(1)));
  }

  @Test
  @DisplayName("default constructor uses TenantId.DEFAULT and a 256-bit token source")
  void defaultConstructorSmokeTest() {
    InMemoryRememberMeTokenStore store = new InMemoryRememberMeTokenStore();
    PasswordHasher hasher = new FakeHasher();
    StoreBackedRememberMeService service = new StoreBackedRememberMeService(store, hasher);

    var issued = service.issue(ALICE, Duration.ofMinutes(5));
    assertSame(TenantId.DEFAULT, issued.record().tenant());
    // 32 random bytes → base64-url unpadded → 43 chars
    assertEquals(43, issued.plainToken().length());
    // Second issue should differ — almost certainly
    var second = service.issue(ALICE, Duration.ofMinutes(5));
    assertNotEquals(issued.plainToken(), second.plainToken());
    // Touch unused HexFormat import via no-op — keeps the import set lean
    Arrays.fill(new char[1], 'x');
  }
}
