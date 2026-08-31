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
package eu.jsentinel.jcustos.persistence.testkit;

import eu.jsentinel.jcustos.authentication.ApiKeyRecord;
import eu.jsentinel.jcustos.authentication.ApiKeyStore;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Contract every {@link ApiKeyStore} implementation must satisfy.
 */
@DisplayName("ApiKeyStore — contract")
public interface ApiKeyStoreContract {

  /**
   * @return a fresh, empty {@code ApiKeyStore}
   */
  ApiKeyStore newStore();

  Instant T0 = Instant.parse("2026-01-01T00:00:00Z");
  Instant EXPIRY = T0.plusSeconds(3600);
  SubjectId ALICE = new SubjectId("alice");
  SubjectId BOB = new SubjectId("bob");

  /**
   * Builds a sample API-key record.
   *
   * @param hash    key hash
   * @param subject subject
   * @param name    human-readable label
   * @return new record
   */
  default ApiKeyRecord key(String hash, SubjectId subject, String name) {
    return new ApiKeyRecord(
        hash, TenantId.DEFAULT, subject, name,
        Set.of(new PermissionName("doc:read")),
        T0, Optional.of(EXPIRY), Optional.empty(), Optional.empty());
  }

  @Test
  @DisplayName("save + findByHash round-trip")
  default void saveAndFind() {
    ApiKeyStore store = newStore();
    ApiKeyRecord r = key("h1", ALICE, "ci");
    store.save(r);
    assertEquals(Optional.of(r), store.findByHash("h1"));
  }

  @Test
  @DisplayName("listBySubject returns records in insertion order")
  default void listBySubjectInsertionOrder() {
    ApiKeyStore store = newStore();
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
  default void listBySubjectTenantScoped() {
    ApiKeyStore store = newStore();
    ApiKeyRecord defaultKey = key("h1", ALICE, "ci");
    ApiKeyRecord acmeKey = new ApiKeyRecord(
        "h2", new TenantId("acme"), ALICE, "ci", Set.of(),
        T0, Optional.of(EXPIRY), Optional.empty(), Optional.empty());
    store.save(defaultKey);
    store.save(acmeKey);

    assertEquals(List.of(acmeKey), store.listBySubject(new TenantId("acme"), ALICE));
  }

  @Test
  @DisplayName("markUsed updates lastUsedAt and returns true; unknown returns false")
  default void markUsedLifecycle() {
    ApiKeyStore store = newStore();
    store.save(key("h1", ALICE, "ci"));
    assertTrue(store.markUsed("h1", T0.plusSeconds(60)));
    assertEquals(Optional.of(T0.plusSeconds(60)),
        store.findByHash("h1").orElseThrow().lastUsedAt());
    assertFalse(store.markUsed("ghost", T0.plusSeconds(60)));
  }

  @Test
  @DisplayName("revoke flips a not-yet-revoked record; second call is idempotent")
  default void revokeIdempotent() {
    ApiKeyStore store = newStore();
    store.save(key("h1", ALICE, "ci"));
    assertTrue(store.revoke("h1", T0.plusSeconds(60)));
    assertTrue(store.findByHash("h1").orElseThrow().isRevoked());
    assertFalse(store.revoke("h1", T0.plusSeconds(120)));
  }

  @Test
  @DisplayName("deleteByHash drops the record; unknown returns false")
  default void deleteByHash() {
    ApiKeyStore store = newStore();
    store.save(key("h1", ALICE, "ci"));
    assertTrue(store.deleteByHash("h1"));
    assertTrue(store.findByHash("h1").isEmpty());
    assertFalse(store.deleteByHash("h1"));
  }

  @Test
  @DisplayName("purgeExpired drops records whose expiresAt is at or before now")
  default void purgeExpired() {
    ApiKeyStore store = newStore();
    ApiKeyRecord shortLived = new ApiKeyRecord(
        "h-short", TenantId.DEFAULT, ALICE, "tmp", Set.of(),
        T0, Optional.of(T0.plusSeconds(60)), Optional.empty(), Optional.empty());
    ApiKeyRecord longLived = key("h-long", ALICE, "ci");
    store.save(shortLived);
    store.save(longLived);

    assertEquals(1, store.purgeExpired(T0.plusSeconds(60)));
    assertTrue(store.findByHash("h-long").isPresent());
  }

  @Test
  @DisplayName("blank / null arguments are rejected uniformly")
  default void invalidArgumentsRejected() {
    ApiKeyStore store = newStore();
    assertThrows(IllegalArgumentException.class, () -> store.findByHash(""));
    assertThrows(NullPointerException.class, () -> store.save(null));
    assertThrows(NullPointerException.class, () -> store.listBySubject(null, ALICE));
    assertThrows(NullPointerException.class,
        () -> store.listBySubject(TenantId.DEFAULT, null));
    assertThrows(IllegalArgumentException.class,
        () -> store.markUsed("", T0.plusSeconds(60)));
    assertThrows(NullPointerException.class, () -> store.markUsed("h1", null));
    assertThrows(IllegalArgumentException.class,
        () -> store.revoke("", T0.plusSeconds(60)));
    assertThrows(IllegalArgumentException.class, () -> store.deleteByHash(""));
    assertThrows(NullPointerException.class, () -> store.purgeExpired(null));
  }
}
