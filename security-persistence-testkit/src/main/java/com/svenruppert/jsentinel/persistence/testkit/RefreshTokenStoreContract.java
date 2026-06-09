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
package com.svenruppert.jsentinel.persistence.testkit;

import com.svenruppert.jsentinel.authentication.RefreshTokenRecord;
import com.svenruppert.jsentinel.authentication.RefreshTokenStore;
import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import com.svenruppert.jsentinel.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Contract every {@link RefreshTokenStore} implementation must
 * satisfy.
 */
@DisplayName("RefreshTokenStore — contract")
public interface RefreshTokenStoreContract {

  /**
   * @return a fresh, empty {@code RefreshTokenStore}
   */
  RefreshTokenStore newStore();

  Instant T0 = Instant.parse("2026-01-01T00:00:00Z");
  Instant EXPIRY = T0.plusSeconds(3600);
  SubjectId ALICE = new SubjectId("alice");
  SubjectId BOB = new SubjectId("bob");

  /**
   * Builds a sample fresh token record.
   *
   * @param hash    token hash
   * @param subject subject
   * @return new record
   */
  default RefreshTokenRecord token(String hash, SubjectId subject) {
    return new RefreshTokenRecord(
        hash, TenantId.DEFAULT, subject, T0, EXPIRY,
        Optional.empty(), Optional.empty());
  }

  @Test
  @DisplayName("save + findByHash round-trip")
  default void saveAndFind() {
    RefreshTokenStore store = newStore();
    RefreshTokenRecord r = token("h1", ALICE);
    store.save(r);
    assertEquals(Optional.of(r), store.findByHash("h1"));
  }

  @Test
  @DisplayName("markReplaced links predecessor → successor; second call returns false")
  default void markReplacedLifecycle() {
    RefreshTokenStore store = newStore();
    store.save(token("h1", ALICE));
    assertTrue(store.markReplaced("h1", "h2", T0.plusSeconds(60)));
    assertEquals(Optional.of("h2"),
        store.findByHash("h1").orElseThrow().replacedByHash());
    assertFalse(store.markReplaced("h1", "h3", T0.plusSeconds(120)));
    assertFalse(store.markReplaced("ghost", "h-new", T0.plusSeconds(60)));
  }

  @Test
  @DisplayName("markRevoked flips a not-yet-revoked record; idempotent")
  default void markRevokedIdempotent() {
    RefreshTokenStore store = newStore();
    store.save(token("h1", ALICE));
    assertTrue(store.markRevoked("h1", T0.plusSeconds(60)));
    assertTrue(store.findByHash("h1").orElseThrow().isRevoked());
    assertFalse(store.markRevoked("h1", T0.plusSeconds(120)));
  }

  @Test
  @DisplayName("deleteBySubject drops every record of the subject")
  default void deleteBySubject() {
    RefreshTokenStore store = newStore();
    store.save(token("h1", ALICE));
    store.save(token("h2", ALICE));
    store.markReplaced("h2", "h3", T0.plusSeconds(60));
    store.save(token("h4", BOB));

    assertEquals(2, store.deleteBySubject(TenantId.DEFAULT, ALICE));
    assertTrue(store.findByHash("h4").isPresent());
  }

  @Test
  @DisplayName("purgeExpired drops every record at or before now")
  default void purgeExpired() {
    RefreshTokenStore store = newStore();
    RefreshTokenRecord shortLived = new RefreshTokenRecord(
        "h-short", TenantId.DEFAULT, ALICE, T0, T0.plusSeconds(60),
        Optional.empty(), Optional.empty());
    store.save(shortLived);
    store.save(token("h-long", ALICE));

    assertEquals(1, store.purgeExpired(T0.plusSeconds(60)));
    assertTrue(store.findByHash("h-long").isPresent());
  }

  @Test
  @DisplayName("invalid arguments are rejected uniformly")
  default void invalidArgumentsRejected() {
    RefreshTokenStore store = newStore();
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
    assertThrows(NullPointerException.class, () -> store.markRevoked("h1", null));
    assertThrows(NullPointerException.class, () -> store.deleteBySubject(null, ALICE));
    assertThrows(NullPointerException.class,
        () -> store.deleteBySubject(TenantId.DEFAULT, null));
    assertThrows(NullPointerException.class, () -> store.purgeExpired(null));
  }
}
