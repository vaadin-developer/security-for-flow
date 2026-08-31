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
package eu.jsentinel.jcustos.accountlifecycle;

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("InMemoryEmailVerificationTokenStore + EmailVerificationTokenRecord")
class InMemoryEmailVerificationTokenStoreTest {

  private static final SubjectId ALICE = new SubjectId("alice");
  private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");
  private static final Instant EXPIRY = T0.plusSeconds(900);

  private final InMemoryEmailVerificationTokenStore store =
      new InMemoryEmailVerificationTokenStore();

  private static EmailVerificationTokenRecord token(String hash, String email) {
    return new EmailVerificationTokenRecord(
        hash, TenantId.DEFAULT, ALICE, email, T0, EXPIRY, Optional.empty());
  }

  // ── Record invariants ───────────────────────────────────────────

  @Nested
  @DisplayName("EmailVerificationTokenRecord invariants")
  class RecordInvariants {

    @Test
    @DisplayName("blank email rejected")
    void blankEmailRejected() {
      assertThrows(IllegalArgumentException.class,
          () -> new EmailVerificationTokenRecord("h", TenantId.DEFAULT, ALICE,
              null, T0, EXPIRY, Optional.empty()));
      assertThrows(IllegalArgumentException.class,
          () -> new EmailVerificationTokenRecord("h", TenantId.DEFAULT, ALICE,
              "  ", T0, EXPIRY, Optional.empty()));
    }

    @Test
    @DisplayName("email exposed verbatim through the accessor")
    void emailExposed() {
      EmailVerificationTokenRecord r = token("h", "alice@example.org");
      assertEquals("alice@example.org", r.email());
    }

    @Test
    @DisplayName("withConsumedAt sets the timestamp; isConsumed flips to true")
    void withConsumedAt() {
      EmailVerificationTokenRecord pending = token("h", "alice@example.org");
      assertFalse(pending.isConsumed());
      EmailVerificationTokenRecord consumed = pending.withConsumedAt(T0.plusSeconds(60));
      assertTrue(consumed.isConsumed());
      assertEquals(Optional.of(T0.plusSeconds(60)), consumed.consumedAt());
    }

    @Test
    @DisplayName("withConsumedAt rejects null")
    void withConsumedAtRejectsNull() {
      assertThrows(NullPointerException.class,
          () -> token("h", "a@b").withConsumedAt(null));
    }

    @Test
    @DisplayName("consumedAt at or before createdAt rejected")
    void consumedBeforeCreatedRejected() {
      assertThrows(IllegalArgumentException.class,
          () -> new EmailVerificationTokenRecord("h", TenantId.DEFAULT, ALICE,
              "a@b", T0, EXPIRY, Optional.of(T0)));
    }

    @Test
    @DisplayName("expiresAt at or before createdAt rejected")
    void expiresMustBeAfterCreated() {
      assertThrows(IllegalArgumentException.class,
          () -> new EmailVerificationTokenRecord("h", TenantId.DEFAULT, ALICE,
              "a@b", T0, T0, Optional.empty()));
    }

    @Test
    @DisplayName("null tenant normalised to DEFAULT")
    void nullTenant() {
      EmailVerificationTokenRecord r = new EmailVerificationTokenRecord(
          "h", null, ALICE, "a@b", T0, EXPIRY, Optional.empty());
      assertEquals(TenantId.DEFAULT, r.tenant());
    }
  }

  // ── Store operations ────────────────────────────────────────────

  @Test
  @DisplayName("save + findByHash round-trip; markConsumed flips isConsumed")
  void storeLifecycle() {
    store.save(token("h1", "alice@example.org"));
    assertTrue(store.markConsumed("h1", T0.plusSeconds(30)));
    EmailVerificationTokenRecord found = store.findByHash("h1").orElseThrow();
    assertTrue(found.isConsumed());
    assertEquals("alice@example.org", found.email());
  }

  @Test
  @DisplayName("markConsumed twice on the same hash returns false the second time")
  void markConsumedIdempotent() {
    store.save(token("h1", "alice@example.org"));
    store.markConsumed("h1", T0.plusSeconds(30));
    assertFalse(store.markConsumed("h1", T0.plusSeconds(60)));
  }

  @Test
  @DisplayName("markConsumed on an unknown hash returns false")
  void markConsumedUnknown() {
    assertFalse(store.markConsumed("ghost", T0.plusSeconds(30)));
  }

  @Test
  @DisplayName("deleteBySubject drops both pending and consumed records for the subject")
  void deleteBySubject() {
    store.save(token("h1", "alice@example.org"));
    store.save(token("h2", "alice.alt@example.org"));
    store.markConsumed("h2", T0.plusSeconds(30));
    store.save(new EmailVerificationTokenRecord(
        "h3", TenantId.DEFAULT, new SubjectId("bob"),
        "bob@example.org", T0, EXPIRY, Optional.empty()));

    int removed = store.deleteBySubject(TenantId.DEFAULT, ALICE);

    assertEquals(2, removed);
    assertTrue(store.findByHash("h3").isPresent());
  }

  @Test
  @DisplayName("purgeExpired drops every record whose expiresAt <= now")
  void purgeExpired() {
    store.save(new EmailVerificationTokenRecord(
        "early", TenantId.DEFAULT, ALICE, "a@b", T0, T0.plusSeconds(60), Optional.empty()));
    store.save(new EmailVerificationTokenRecord(
        "late", TenantId.DEFAULT, ALICE, "a@b", T0, T0.plusSeconds(3600), Optional.empty()));

    int removed = store.purgeExpired(T0.plusSeconds(60));

    assertEquals(1, removed);
    assertTrue(store.findByHash("late").isPresent());
  }

  @Test
  @DisplayName("save and markConsumed reject invalid arguments")
  void storeRejectsInvalidArgs() {
    assertThrows(NullPointerException.class, () -> store.save(null));
    assertThrows(IllegalArgumentException.class, () -> store.findByHash(""));
    assertThrows(IllegalArgumentException.class,
        () -> store.markConsumed("", T0.plusSeconds(30)));
    assertThrows(NullPointerException.class,
        () -> store.markConsumed("h1", null));
  }
}
