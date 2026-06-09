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

import com.svenruppert.jsentinel.authorization.api.permissions.PermissionName;
import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import com.svenruppert.jsentinel.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("InMemoryApiKeyStore + ApiKeyRecord")
class InMemoryApiKeyStoreTest {

  private static final SubjectId ALICE = new SubjectId("alice");
  private static final SubjectId BOB = new SubjectId("bob");
  private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");
  private static final Instant LATER = T0.plusSeconds(3600);

  private final InMemoryApiKeyStore store = new InMemoryApiKeyStore();

  private static ApiKeyRecord key(String hash, SubjectId subject, String name) {
    return new ApiKeyRecord(
        hash, TenantId.DEFAULT, subject, name,
        Set.of(new PermissionName("doc:read")),
        T0, Optional.of(LATER), Optional.empty(), Optional.empty());
  }

  // ── Record invariants ───────────────────────────────────────────

  @Nested
  @DisplayName("ApiKeyRecord invariants")
  class RecordInvariants {

    @Test
    @DisplayName("blank keyHash / name rejected")
    void blanks() {
      assertThrows(IllegalArgumentException.class,
          () -> new ApiKeyRecord("", TenantId.DEFAULT, ALICE, "n", Set.of(),
              T0, Optional.empty(), Optional.empty(), Optional.empty()));
      assertThrows(IllegalArgumentException.class,
          () -> new ApiKeyRecord("h", TenantId.DEFAULT, ALICE, "", Set.of(),
              T0, Optional.empty(), Optional.empty(), Optional.empty()));
    }

    @Test
    @DisplayName("null scopes normalised to empty immutable set")
    void nullScopesEmpty() {
      ApiKeyRecord r = new ApiKeyRecord("h", TenantId.DEFAULT, ALICE, "n", null,
          T0, Optional.empty(), Optional.empty(), Optional.empty());
      assertTrue(r.scopes().isEmpty());
      assertThrows(UnsupportedOperationException.class,
          () -> r.scopes().add(new PermissionName("doc:read")));
    }

    @Test
    @DisplayName("scopes are defensively copied — caller mutations don't leak in")
    void scopesDefensiveCopy() {
      Set<PermissionName> input = new java.util.HashSet<>();
      input.add(new PermissionName("doc:read"));
      ApiKeyRecord r = new ApiKeyRecord("h", TenantId.DEFAULT, ALICE, "n", input,
          T0, Optional.empty(), Optional.empty(), Optional.empty());
      input.add(new PermissionName("doc:write"));
      assertEquals(1, r.scopes().size());
    }

    @Test
    @DisplayName("expiresAt at or before createdAt rejected")
    void expiryBeforeCreated() {
      assertThrows(IllegalArgumentException.class,
          () -> new ApiKeyRecord("h", TenantId.DEFAULT, ALICE, "n", Set.of(),
              T0, Optional.of(T0), Optional.empty(), Optional.empty()));
    }

    @Test
    @DisplayName("lastUsedAt before createdAt rejected; at-or-after accepted")
    void lastUsedBoundary() {
      assertThrows(IllegalArgumentException.class,
          () -> new ApiKeyRecord("h", TenantId.DEFAULT, ALICE, "n", Set.of(),
              T0, Optional.empty(), Optional.of(T0.minusSeconds(1)), Optional.empty()));
      // at createdAt is allowed
      new ApiKeyRecord("h", TenantId.DEFAULT, ALICE, "n", Set.of(),
          T0, Optional.empty(), Optional.of(T0), Optional.empty());
    }

    @Test
    @DisplayName("revokedAt before createdAt rejected")
    void revokedBeforeCreated() {
      assertThrows(IllegalArgumentException.class,
          () -> new ApiKeyRecord("h", TenantId.DEFAULT, ALICE, "n", Set.of(),
              T0, Optional.empty(), Optional.empty(), Optional.of(T0.minusSeconds(1))));
    }

    @Test
    @DisplayName("isActive: true for fresh, false after revoke, false after expiry")
    void isActiveLifecycle() {
      ApiKeyRecord fresh = key("h", ALICE, "n");
      assertTrue(fresh.isActive(T0.plusSeconds(60)));

      ApiKeyRecord revoked = fresh.withRevokedAt(T0.plusSeconds(120));
      assertFalse(revoked.isActive(T0.plusSeconds(180)));
      assertTrue(revoked.isRevoked());

      assertTrue(fresh.isExpired(LATER), "isExpired flips at the expiry boundary");
      assertFalse(fresh.isActive(LATER));
    }

    @Test
    @DisplayName("isExpired is always false when expiresAt is empty")
    void noExpiryNeverExpires() {
      ApiKeyRecord r = new ApiKeyRecord("h", TenantId.DEFAULT, ALICE, "n", Set.of(),
          T0, Optional.empty(), Optional.empty(), Optional.empty());
      assertFalse(r.isExpired(T0.plusSeconds(99_999_999L)));
    }

    @Test
    @DisplayName("withLastUsedAt / withRevokedAt return copies (receiver unchanged)")
    void withHelpersAreCopies() {
      ApiKeyRecord fresh = key("h", ALICE, "n");
      ApiKeyRecord used = fresh.withLastUsedAt(T0.plusSeconds(30));
      assertTrue(fresh.lastUsedAt().isEmpty());
      assertEquals(Optional.of(T0.plusSeconds(30)), used.lastUsedAt());
    }

    @Test
    @DisplayName("withLastUsedAt / withRevokedAt reject null")
    void withHelpersRejectNull() {
      ApiKeyRecord r = key("h", ALICE, "n");
      assertThrows(NullPointerException.class, () -> r.withLastUsedAt(null));
      assertThrows(NullPointerException.class, () -> r.withRevokedAt(null));
    }
  }

  // ── Store operations ────────────────────────────────────────────

  @Test
  @DisplayName("save + findByHash round-trip")
  void saveAndFind() {
    ApiKeyRecord r = key("h1", ALICE, "ci");
    store.save(r);
    assertEquals(Optional.of(r), store.findByHash("h1"));
  }

  @Test
  @DisplayName("listBySubject returns insertion-ordered records for the (tenant, subject) pair")
  void listBySubjectInsertionOrder() {
    ApiKeyRecord a = key("h1", ALICE, "ci");
    ApiKeyRecord b = key("h2", ALICE, "report");
    ApiKeyRecord other = key("h3", BOB, "ci");
    store.save(a);
    store.save(b);
    store.save(other);

    assertEquals(List.of(a, b), store.listBySubject(TenantId.DEFAULT, ALICE));
  }

  @Test
  @DisplayName("listBySubject is tenant-scoped")
  void listBySubjectTenantScoped() {
    ApiKeyRecord defaultKey = key("h1", ALICE, "ci");
    ApiKeyRecord acmeKey = new ApiKeyRecord(
        "h2", new TenantId("acme"), ALICE, "ci", Set.of(),
        T0, Optional.of(LATER), Optional.empty(), Optional.empty());
    store.save(defaultKey);
    store.save(acmeKey);

    assertEquals(List.of(acmeKey),
        store.listBySubject(new TenantId("acme"), ALICE));
  }

  @Test
  @DisplayName("markUsed updates lastUsedAt and returns true")
  void markUsedTrue() {
    store.save(key("h1", ALICE, "ci"));
    assertTrue(store.markUsed("h1", T0.plusSeconds(60)));
    assertEquals(Optional.of(T0.plusSeconds(60)),
        store.findByHash("h1").orElseThrow().lastUsedAt());
  }

  @Test
  @DisplayName("markUsed on unknown hash returns false")
  void markUsedUnknown() {
    assertFalse(store.markUsed("ghost", T0.plusSeconds(60)));
  }

  @Test
  @DisplayName("revoke flips a not-yet-revoked record and returns true")
  void revokeSucceeds() {
    store.save(key("h1", ALICE, "ci"));
    assertTrue(store.revoke("h1", T0.plusSeconds(60)));
    assertTrue(store.findByHash("h1").orElseThrow().isRevoked());
  }

  @Test
  @DisplayName("revoke is idempotent — second call returns false")
  void revokeIdempotent() {
    store.save(key("h1", ALICE, "ci"));
    store.revoke("h1", T0.plusSeconds(60));
    assertFalse(store.revoke("h1", T0.plusSeconds(120)));
  }

  @Test
  @DisplayName("deleteByHash drops the record and returns true; unknown hash returns false")
  void deleteByHash() {
    store.save(key("h1", ALICE, "ci"));
    assertTrue(store.deleteByHash("h1"));
    assertTrue(store.findByHash("h1").isEmpty());
    assertFalse(store.deleteByHash("h1"));
  }

  @Test
  @DisplayName("purgeExpired drops records whose expiresAt is at or before now")
  void purgeExpired() {
    ApiKeyRecord shortLived = new ApiKeyRecord(
        "h-short", TenantId.DEFAULT, ALICE, "tmp", Set.of(),
        T0, Optional.of(T0.plusSeconds(60)),
        Optional.empty(), Optional.empty());
    ApiKeyRecord longLived = key("h-long", ALICE, "ci");
    store.save(shortLived);
    store.save(longLived);

    assertEquals(1, store.purgeExpired(T0.plusSeconds(60)));
    assertTrue(store.findByHash("h-short").isEmpty());
    assertTrue(store.findByHash("h-long").isPresent());
  }

  @Test
  @DisplayName("all store methods reject blank / null arguments")
  void invalidArgumentsRejected() {
    assertThrows(IllegalArgumentException.class, () -> store.findByHash(""));
    assertThrows(NullPointerException.class, () -> store.save(null));
    assertThrows(NullPointerException.class,
        () -> store.listBySubject(null, ALICE));
    assertThrows(NullPointerException.class,
        () -> store.listBySubject(TenantId.DEFAULT, null));
    assertThrows(IllegalArgumentException.class,
        () -> store.markUsed("", T0.plusSeconds(60)));
    assertThrows(NullPointerException.class,
        () -> store.markUsed("h1", null));
    assertThrows(IllegalArgumentException.class,
        () -> store.revoke("", T0.plusSeconds(60)));
    assertThrows(IllegalArgumentException.class,
        () -> store.deleteByHash(""));
    assertThrows(NullPointerException.class,
        () -> store.purgeExpired(null));
  }
}
