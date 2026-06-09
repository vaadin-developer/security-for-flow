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

@DisplayName("InMemoryRememberMeTokenStore + RememberMeTokenRecord")
class InMemoryRememberMeTokenStoreTest {

  private static final TenantId ACME = new TenantId("acme");
  private static final SubjectId ALICE = new SubjectId("alice");
  private static final SubjectId BOB = new SubjectId("bob");
  private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");
  private static final Instant EXPIRY = T0.plusSeconds(3600);

  private final InMemoryRememberMeTokenStore store = new InMemoryRememberMeTokenStore();

  private static RememberMeTokenRecord token(String hash, TenantId tenant, SubjectId subject) {
    return new RememberMeTokenRecord(hash, tenant, subject, T0, EXPIRY);
  }

  // ── Record invariants ───────────────────────────────────────────

  @Nested
  @DisplayName("RememberMeTokenRecord invariants")
  class RecordInvariants {

    @Test
    @DisplayName("blank tokenHash rejected")
    void blankTokenHash() {
      assertThrows(IllegalArgumentException.class,
          () -> new RememberMeTokenRecord(null, TenantId.DEFAULT, ALICE, T0, EXPIRY));
      assertThrows(IllegalArgumentException.class,
          () -> new RememberMeTokenRecord("", TenantId.DEFAULT, ALICE, T0, EXPIRY));
      assertThrows(IllegalArgumentException.class,
          () -> new RememberMeTokenRecord("   ", TenantId.DEFAULT, ALICE, T0, EXPIRY));
    }

    @Test
    @DisplayName("null subjectId / createdAt / expiresAt rejected")
    void nullsRejected() {
      assertThrows(NullPointerException.class,
          () -> new RememberMeTokenRecord("h", TenantId.DEFAULT, null, T0, EXPIRY));
      assertThrows(NullPointerException.class,
          () -> new RememberMeTokenRecord("h", TenantId.DEFAULT, ALICE, null, EXPIRY));
      assertThrows(NullPointerException.class,
          () -> new RememberMeTokenRecord("h", TenantId.DEFAULT, ALICE, T0, null));
    }

    @Test
    @DisplayName("null tenant normalised to DEFAULT")
    void nullTenant() {
      RememberMeTokenRecord r = new RememberMeTokenRecord("h", null, ALICE, T0, EXPIRY);
      assertEquals(TenantId.DEFAULT, r.tenant());
    }

    @Test
    @DisplayName("expiresAt not after createdAt rejected (equal or before)")
    void expiresMustBeAfterCreated() {
      assertThrows(IllegalArgumentException.class,
          () -> new RememberMeTokenRecord("h", TenantId.DEFAULT, ALICE, T0, T0));
      assertThrows(IllegalArgumentException.class,
          () -> new RememberMeTokenRecord("h", TenantId.DEFAULT, ALICE, T0, T0.minusSeconds(1)));
    }

    @Test
    @DisplayName("isExpired returns true at or after expiresAt, false strictly before")
    void isExpiredBoundary() {
      RememberMeTokenRecord r = token("h", TenantId.DEFAULT, ALICE);
      assertFalse(r.isExpired(EXPIRY.minusNanos(1)));
      assertTrue(r.isExpired(EXPIRY), "isExpired must return true at the boundary itself");
      assertTrue(r.isExpired(EXPIRY.plusSeconds(1)));
    }

    @Test
    @DisplayName("isExpired rejects null instant")
    void isExpiredRejectsNull() {
      assertThrows(NullPointerException.class,
          () -> token("h", TenantId.DEFAULT, ALICE).isExpired(null));
    }
  }

  // ── findByHash / save / deleteByHash ────────────────────────────

  @Test
  @DisplayName("save persists; findByHash retrieves; deleteByHash drops")
  void crudByHash() {
    RememberMeTokenRecord r = token("h1", TenantId.DEFAULT, ALICE);
    store.save(r);
    assertEquals(Optional.of(r), store.findByHash("h1"));

    assertTrue(store.deleteByHash("h1"));
    assertTrue(store.findByHash("h1").isEmpty());
  }

  @Test
  @DisplayName("save upserts when the hash already exists")
  void saveUpserts() {
    RememberMeTokenRecord first = token("h1", TenantId.DEFAULT, ALICE);
    store.save(first);
    RememberMeTokenRecord later = new RememberMeTokenRecord(
        "h1", TenantId.DEFAULT, ALICE, T0, EXPIRY.plusSeconds(60));
    store.save(later);
    assertEquals(Optional.of(later), store.findByHash("h1"),
        "save must replace the previous record under the same hash");
  }

  @Test
  @DisplayName("findByHash and deleteByHash reject blank hashes")
  void blankHashRejected() {
    assertThrows(IllegalArgumentException.class, () -> store.findByHash(null));
    assertThrows(IllegalArgumentException.class, () -> store.findByHash(""));
    assertThrows(IllegalArgumentException.class, () -> store.deleteByHash(""));
  }

  @Test
  @DisplayName("save rejects null record")
  void saveRejectsNull() {
    assertThrows(NullPointerException.class, () -> store.save(null));
  }

  @Test
  @DisplayName("deleteByHash returns false for an unknown hash")
  void deleteByHashUnknown() {
    assertFalse(store.deleteByHash("ghost"));
  }

  // ── deleteBySubject ─────────────────────────────────────────────

  @Test
  @DisplayName("deleteBySubject removes every (tenant, subject) token")
  void deleteBySubjectDropsTriple() {
    store.save(token("h1", TenantId.DEFAULT, ALICE));
    store.save(token("h2", TenantId.DEFAULT, ALICE));
    store.save(token("h3", TenantId.DEFAULT, BOB));

    int removed = store.deleteBySubject(TenantId.DEFAULT, ALICE);

    assertEquals(2, removed);
    assertTrue(store.findByHash("h1").isEmpty());
    assertTrue(store.findByHash("h2").isEmpty());
    assertTrue(store.findByHash("h3").isPresent(), "bob's token must survive");
  }

  @Test
  @DisplayName("deleteBySubject is tenant-scoped")
  void deleteBySubjectTenantScoped() {
    store.save(token("h1", TenantId.DEFAULT, ALICE));
    store.save(token("h2", ACME, ALICE));

    int removed = store.deleteBySubject(ACME, ALICE);

    assertEquals(1, removed);
    assertTrue(store.findByHash("h1").isPresent(),
        "default-tenant token of alice must survive an ACME-only revoke");
  }

  @Test
  @DisplayName("deleteBySubject on an unknown subject returns 0")
  void deleteBySubjectUnknown() {
    assertEquals(0, store.deleteBySubject(TenantId.DEFAULT, new SubjectId("ghost")));
  }

  @Test
  @DisplayName("deleteBySubject rejects nulls")
  void deleteBySubjectRejectsNulls() {
    assertThrows(NullPointerException.class,
        () -> store.deleteBySubject(null, ALICE));
    assertThrows(NullPointerException.class,
        () -> store.deleteBySubject(TenantId.DEFAULT, null));
  }

  // ── purgeExpired ────────────────────────────────────────────────

  @Test
  @DisplayName("purgeExpired drops every token whose expiresAt is at or before now")
  void purgeExpiredDropsAtOrBefore() {
    Instant expiresEarly = T0.plusSeconds(60);
    Instant expiresLate = T0.plusSeconds(3600);
    store.save(new RememberMeTokenRecord("early", TenantId.DEFAULT, ALICE, T0, expiresEarly));
    store.save(new RememberMeTokenRecord("late", TenantId.DEFAULT, ALICE, T0, expiresLate));

    int removed = store.purgeExpired(expiresEarly);

    assertEquals(1, removed, "the token expiring at exactly the cutoff is purged");
    assertTrue(store.findByHash("early").isEmpty());
    assertTrue(store.findByHash("late").isPresent());
  }

  @Test
  @DisplayName("purgeExpired on an empty store returns 0")
  void purgeExpiredEmpty() {
    assertEquals(0, store.purgeExpired(EXPIRY));
  }

  @Test
  @DisplayName("purgeExpired rejects null instant")
  void purgeExpiredRejectsNull() {
    assertThrows(NullPointerException.class, () -> store.purgeExpired(null));
  }
}
