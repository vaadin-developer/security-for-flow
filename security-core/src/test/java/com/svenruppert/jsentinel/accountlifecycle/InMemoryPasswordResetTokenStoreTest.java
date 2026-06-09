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

import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import com.svenruppert.jsentinel.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("InMemoryPasswordResetTokenStore + PasswordResetTokenRecord")
class InMemoryPasswordResetTokenStoreTest {

  private static final SubjectId ALICE = new SubjectId("alice");
  private static final SubjectId BOB = new SubjectId("bob");
  private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");
  private static final Instant EXPIRY = T0.plusSeconds(900);

  private final InMemoryPasswordResetTokenStore store = new InMemoryPasswordResetTokenStore();

  private static PasswordResetTokenRecord token(String hash, SubjectId subject) {
    return new PasswordResetTokenRecord(
        hash, TenantId.DEFAULT, subject, T0, EXPIRY, Optional.empty());
  }

  // ── Record invariants ───────────────────────────────────────────

  @Nested
  @DisplayName("PasswordResetTokenRecord invariants")
  class RecordInvariants {

    @Test
    @DisplayName("withConsumedAt sets the timestamp; isConsumed flips to true")
    void withConsumedAt() {
      PasswordResetTokenRecord pending = token("h", ALICE);
      assertFalse(pending.isConsumed());
      PasswordResetTokenRecord consumed = pending.withConsumedAt(T0.plusSeconds(60));
      assertTrue(consumed.isConsumed());
      assertEquals(Optional.of(T0.plusSeconds(60)), consumed.consumedAt());
    }

    @Test
    @DisplayName("consumedAt at or before createdAt is rejected")
    void consumedBeforeCreatedRejected() {
      assertThrows(IllegalArgumentException.class,
          () -> new PasswordResetTokenRecord("h", TenantId.DEFAULT, ALICE,
              T0, EXPIRY, Optional.of(T0)));
      assertThrows(IllegalArgumentException.class,
          () -> new PasswordResetTokenRecord("h", TenantId.DEFAULT, ALICE,
              T0, EXPIRY, Optional.of(T0.minusSeconds(1))));
    }

    @Test
    @DisplayName("blank tokenHash rejected")
    void blankTokenHashRejected() {
      assertThrows(IllegalArgumentException.class,
          () -> new PasswordResetTokenRecord("", TenantId.DEFAULT, ALICE,
              T0, EXPIRY, Optional.empty()));
    }

    @Test
    @DisplayName("null consumedAt becomes empty Optional")
    void nullConsumedBecomesEmpty() {
      PasswordResetTokenRecord r = new PasswordResetTokenRecord(
          "h", TenantId.DEFAULT, ALICE, T0, EXPIRY, null);
      assertTrue(r.consumedAt().isEmpty());
    }

    @Test
    @DisplayName("withConsumedAt rejects null instant")
    void withConsumedAtRejectsNull() {
      assertThrows(NullPointerException.class,
          () -> token("h", ALICE).withConsumedAt(null));
    }
  }

  // ── findByHash / save / markConsumed ────────────────────────────

  @Test
  @DisplayName("markConsumed flips a pending token and returns true")
  void markConsumedSucceeds() {
    store.save(token("h1", ALICE));
    assertTrue(store.markConsumed("h1", T0.plusSeconds(30)));

    PasswordResetTokenRecord found = store.findByHash("h1").orElseThrow();
    assertTrue(found.isConsumed());
  }

  @Test
  @DisplayName("markConsumed on an already-consumed token returns false (idempotent)")
  void markConsumedIdempotent() {
    store.save(token("h1", ALICE));
    store.markConsumed("h1", T0.plusSeconds(30));
    assertFalse(store.markConsumed("h1", T0.plusSeconds(60)),
        "marking the same token consumed twice must return false");
  }

  @Test
  @DisplayName("markConsumed on an unknown hash returns false")
  void markConsumedUnknownHash() {
    assertFalse(store.markConsumed("ghost", T0.plusSeconds(30)));
  }

  @Test
  @DisplayName("findByHash returns consumed records as well — distinguishes 'consumed' from 'never existed'")
  void findByHashReturnsConsumedRecords() {
    store.save(token("h1", ALICE));
    store.markConsumed("h1", T0.plusSeconds(30));
    PasswordResetTokenRecord r = store.findByHash("h1").orElseThrow();
    assertTrue(r.isConsumed());
  }

  @Test
  @DisplayName("findByHash and markConsumed reject blank hashes / null instants")
  void blankAndNullsRejected() {
    assertThrows(IllegalArgumentException.class, () -> store.findByHash(""));
    assertThrows(IllegalArgumentException.class,
        () -> store.markConsumed("", T0.plusSeconds(30)));
    assertThrows(NullPointerException.class,
        () -> store.markConsumed("h1", null));
  }

  @Test
  @DisplayName("save rejects null record")
  void saveRejectsNull() {
    assertThrows(NullPointerException.class, () -> store.save(null));
  }

  // ── deleteBySubject ─────────────────────────────────────────────

  @Test
  @DisplayName("deleteBySubject drops both pending and consumed tokens for the subject")
  void deleteBySubjectDropsBoth() {
    store.save(token("h1", ALICE));
    store.save(token("h2", ALICE));
    store.markConsumed("h2", T0.plusSeconds(30));
    store.save(token("h3", BOB));

    int removed = store.deleteBySubject(TenantId.DEFAULT, ALICE);

    assertEquals(2, removed);
    assertTrue(store.findByHash("h1").isEmpty());
    assertTrue(store.findByHash("h2").isEmpty());
    assertTrue(store.findByHash("h3").isPresent());
  }

  // ── purgeExpired ────────────────────────────────────────────────

  @Test
  @DisplayName("purgeExpired drops every token whose expiresAt is at or before now")
  void purgeExpiredAtOrBefore() {
    PasswordResetTokenRecord early = new PasswordResetTokenRecord(
        "early", TenantId.DEFAULT, ALICE, T0, T0.plusSeconds(60), Optional.empty());
    PasswordResetTokenRecord late = new PasswordResetTokenRecord(
        "late", TenantId.DEFAULT, ALICE, T0, T0.plusSeconds(3600), Optional.empty());
    store.save(early);
    store.save(late);

    int removed = store.purgeExpired(T0.plusSeconds(60));

    assertEquals(1, removed);
    assertTrue(store.findByHash("early").isEmpty());
    assertTrue(store.findByHash("late").isPresent());
  }
}
