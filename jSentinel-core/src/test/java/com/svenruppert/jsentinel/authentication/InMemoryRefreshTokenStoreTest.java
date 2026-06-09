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

@DisplayName("InMemoryRefreshTokenStore + RefreshTokenRecord")
class InMemoryRefreshTokenStoreTest {

  private static final SubjectId ALICE = new SubjectId("alice");
  private static final SubjectId BOB = new SubjectId("bob");
  private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");
  private static final Instant EXPIRY = T0.plusSeconds(3600);

  private final InMemoryRefreshTokenStore store = new InMemoryRefreshTokenStore();

  private static RefreshTokenRecord token(String hash, SubjectId subject) {
    return new RefreshTokenRecord(
        hash, TenantId.DEFAULT, subject, T0, EXPIRY,
        Optional.empty(), Optional.empty());
  }

  // ── Record invariants ───────────────────────────────────────────

  @Nested
  @DisplayName("RefreshTokenRecord invariants")
  class RecordInvariants {

    @Test
    @DisplayName("blank tokenHash rejected")
    void blankTokenHash() {
      assertThrows(IllegalArgumentException.class,
          () -> new RefreshTokenRecord("", TenantId.DEFAULT, ALICE, T0, EXPIRY,
              Optional.empty(), Optional.empty()));
    }

    @Test
    @DisplayName("blank replacedByHash rejected when present")
    void blankReplacedByRejected() {
      assertThrows(IllegalArgumentException.class,
          () -> new RefreshTokenRecord("h", TenantId.DEFAULT, ALICE, T0, EXPIRY,
              Optional.of("  "), Optional.empty()));
    }

    @Test
    @DisplayName("revokedAt before createdAt rejected")
    void revokedBeforeCreated() {
      assertThrows(IllegalArgumentException.class,
          () -> new RefreshTokenRecord("h", TenantId.DEFAULT, ALICE, T0, EXPIRY,
              Optional.empty(), Optional.of(T0.minusSeconds(1))));
    }

    @Test
    @DisplayName("withReplacedBy / withRevokedAt are copies (receiver unchanged)")
    void withHelpersAreCopies() {
      RefreshTokenRecord fresh = token("h", ALICE);
      RefreshTokenRecord replaced = fresh.withReplacedBy("h-new");
      assertTrue(fresh.replacedByHash().isEmpty());
      assertEquals(Optional.of("h-new"), replaced.replacedByHash());

      RefreshTokenRecord revoked = fresh.withRevokedAt(T0.plusSeconds(60));
      assertTrue(fresh.revokedAt().isEmpty());
      assertEquals(Optional.of(T0.plusSeconds(60)), revoked.revokedAt());
    }

    @Test
    @DisplayName("isActive: true for fresh, false after revoke / replace / expiry")
    void isActiveLifecycle() {
      RefreshTokenRecord fresh = token("h", ALICE);
      assertTrue(fresh.isActive(T0.plusSeconds(60)));

      assertFalse(fresh.withReplacedBy("h-new").isActive(T0.plusSeconds(60)));
      assertFalse(fresh.withRevokedAt(T0.plusSeconds(60)).isActive(T0.plusSeconds(120)));
      assertFalse(fresh.isActive(EXPIRY));
    }

    @Test
    @DisplayName("withReplacedBy rejects blank successor; withRevokedAt rejects null instant")
    void withHelperRejections() {
      RefreshTokenRecord fresh = token("h", ALICE);
      assertThrows(IllegalArgumentException.class, () -> fresh.withReplacedBy(""));
      assertThrows(NullPointerException.class, () -> fresh.withRevokedAt(null));
    }
  }

  // ── Store operations ────────────────────────────────────────────

  @Test
  @DisplayName("save + findByHash round-trip")
  void saveAndFind() {
    RefreshTokenRecord r = token("h1", ALICE);
    store.save(r);
    assertEquals(Optional.of(r), store.findByHash("h1"));
  }

  @Test
  @DisplayName("markReplaced links the predecessor and returns true")
  void markReplacedSucceeds() {
    store.save(token("h1", ALICE));
    assertTrue(store.markReplaced("h1", "h2", T0.plusSeconds(60)));
    assertEquals(Optional.of("h2"),
        store.findByHash("h1").orElseThrow().replacedByHash());
  }

  @Test
  @DisplayName("markReplaced on an already-replaced record returns false")
  void markReplacedIdempotent() {
    store.save(token("h1", ALICE));
    store.markReplaced("h1", "h2", T0.plusSeconds(60));
    assertFalse(store.markReplaced("h1", "h3", T0.plusSeconds(120)),
        "subsequent rotation requests on the same predecessor are detected via the existing link");
  }

  @Test
  @DisplayName("markReplaced on an unknown hash returns false")
  void markReplacedUnknown() {
    assertFalse(store.markReplaced("ghost", "h-new", T0.plusSeconds(60)));
  }

  @Test
  @DisplayName("markRevoked flips a record and returns true")
  void markRevokedSucceeds() {
    store.save(token("h1", ALICE));
    assertTrue(store.markRevoked("h1", T0.plusSeconds(60)));
    assertTrue(store.findByHash("h1").orElseThrow().isRevoked());
  }

  @Test
  @DisplayName("markRevoked on an already-revoked record returns false")
  void markRevokedIdempotent() {
    store.save(token("h1", ALICE));
    store.markRevoked("h1", T0.plusSeconds(60));
    assertFalse(store.markRevoked("h1", T0.plusSeconds(120)));
  }

  @Test
  @DisplayName("deleteBySubject drops every record (active/replaced/revoked) for the subject")
  void deleteBySubject() {
    store.save(token("h1", ALICE));
    store.save(token("h2", ALICE));
    store.markReplaced("h2", "h3", T0.plusSeconds(60));
    store.save(token("h4", BOB));

    int removed = store.deleteBySubject(TenantId.DEFAULT, ALICE);

    assertEquals(2, removed);
    assertTrue(store.findByHash("h4").isPresent());
  }

  @Test
  @DisplayName("purgeExpired drops every record at or before now")
  void purgeExpired() {
    RefreshTokenRecord shortLived = new RefreshTokenRecord(
        "h-short", TenantId.DEFAULT, ALICE, T0, T0.plusSeconds(60),
        Optional.empty(), Optional.empty());
    store.save(shortLived);
    store.save(token("h-long", ALICE));

    assertEquals(1, store.purgeExpired(T0.plusSeconds(60)));
    assertTrue(store.findByHash("h-short").isEmpty());
    assertTrue(store.findByHash("h-long").isPresent());
  }

  @Test
  @DisplayName("all store methods reject blank / null arguments")
  void invalidArgumentsRejected() {
    assertThrows(IllegalArgumentException.class, () -> store.findByHash(""));
    assertThrows(NullPointerException.class, () -> store.save(null));
    assertThrows(IllegalArgumentException.class,
        () -> store.markReplaced("", "h2", T0.plusSeconds(60)));
    assertThrows(IllegalArgumentException.class,
        () -> store.markReplaced("h1", "", T0.plusSeconds(60)));
    assertThrows(NullPointerException.class,
        () -> store.markReplaced("h1", "h2", null));
    assertThrows(IllegalArgumentException.class,
        () -> store.markRevoked("", T0.plusSeconds(60)));
    assertThrows(NullPointerException.class,
        () -> store.markRevoked("h1", null));
    assertThrows(NullPointerException.class,
        () -> store.deleteBySubject(null, ALICE));
    assertThrows(NullPointerException.class,
        () -> store.deleteBySubject(TenantId.DEFAULT, null));
    assertThrows(NullPointerException.class,
        () -> store.purgeExpired(null));
  }
}
