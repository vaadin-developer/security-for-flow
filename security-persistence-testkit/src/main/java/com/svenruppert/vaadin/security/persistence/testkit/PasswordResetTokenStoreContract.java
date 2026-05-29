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
package com.svenruppert.vaadin.security.persistence.testkit;

import com.svenruppert.vaadin.security.accountlifecycle.PasswordResetTokenRecord;
import com.svenruppert.vaadin.security.accountlifecycle.PasswordResetTokenStore;
import com.svenruppert.vaadin.security.authorization.api.tenant.TenantId;
import com.svenruppert.vaadin.security.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Contract every {@link PasswordResetTokenStore} implementation must
 * satisfy.
 */
@DisplayName("PasswordResetTokenStore — contract")
public interface PasswordResetTokenStoreContract {

  /**
   * @return a fresh, empty {@code PasswordResetTokenStore}
   */
  PasswordResetTokenStore newStore();

  Instant T0 = Instant.parse("2026-01-01T00:00:00Z");
  Instant EXPIRY = T0.plusSeconds(900);
  SubjectId ALICE = new SubjectId("alice");
  SubjectId BOB = new SubjectId("bob");

  /**
   * Builds a sample pending token record.
   *
   * @param hash    token hash
   * @param subject subject the token is for
   * @return new record
   */
  default PasswordResetTokenRecord token(String hash, SubjectId subject) {
    return new PasswordResetTokenRecord(
        hash, TenantId.DEFAULT, subject, T0, EXPIRY, Optional.empty());
  }

  @Test
  @DisplayName("markConsumed flips a pending token and returns true")
  default void markConsumedSucceeds() {
    PasswordResetTokenStore store = newStore();
    store.save(token("h1", ALICE));
    assertTrue(store.markConsumed("h1", T0.plusSeconds(30)));
    assertTrue(store.findByHash("h1").orElseThrow().isConsumed());
  }

  @Test
  @DisplayName("markConsumed twice on the same hash is idempotent")
  default void markConsumedIdempotent() {
    PasswordResetTokenStore store = newStore();
    store.save(token("h1", ALICE));
    store.markConsumed("h1", T0.plusSeconds(30));
    assertFalse(store.markConsumed("h1", T0.plusSeconds(60)));
  }

  @Test
  @DisplayName("markConsumed on an unknown hash returns false")
  default void markConsumedUnknown() {
    PasswordResetTokenStore store = newStore();
    assertFalse(store.markConsumed("ghost", T0.plusSeconds(30)));
  }

  @Test
  @DisplayName("findByHash returns consumed records — distinguishes consumed from never-existed")
  default void findByHashIncludesConsumed() {
    PasswordResetTokenStore store = newStore();
    store.save(token("h1", ALICE));
    store.markConsumed("h1", T0.plusSeconds(30));
    assertTrue(store.findByHash("h1").orElseThrow().isConsumed());
  }

  @Test
  @DisplayName("findByHash and markConsumed reject blank hashes / null instants")
  default void blanksAndNulls() {
    PasswordResetTokenStore store = newStore();
    assertThrows(IllegalArgumentException.class, () -> store.findByHash(""));
    assertThrows(IllegalArgumentException.class,
        () -> store.markConsumed("", T0.plusSeconds(30)));
    assertThrows(NullPointerException.class,
        () -> store.markConsumed("h1", null));
  }

  @Test
  @DisplayName("save rejects null")
  default void saveRejectsNull() {
    PasswordResetTokenStore store = newStore();
    assertThrows(NullPointerException.class, () -> store.save(null));
  }

  @Test
  @DisplayName("deleteBySubject drops pending and consumed tokens of the subject")
  default void deleteBySubject() {
    PasswordResetTokenStore store = newStore();
    store.save(token("h1", ALICE));
    store.save(token("h2", ALICE));
    store.markConsumed("h2", T0.plusSeconds(30));
    store.save(token("h3", BOB));

    assertEquals(2, store.deleteBySubject(TenantId.DEFAULT, ALICE));
    assertTrue(store.findByHash("h3").isPresent());
  }

  @Test
  @DisplayName("purgeExpired drops every record at or before now")
  default void purgeExpired() {
    PasswordResetTokenStore store = newStore();
    PasswordResetTokenRecord early = new PasswordResetTokenRecord(
        "early", TenantId.DEFAULT, ALICE, T0, T0.plusSeconds(60), Optional.empty());
    PasswordResetTokenRecord late = new PasswordResetTokenRecord(
        "late", TenantId.DEFAULT, ALICE, T0, T0.plusSeconds(3600), Optional.empty());
    store.save(early);
    store.save(late);

    assertEquals(1, store.purgeExpired(T0.plusSeconds(60)));
    assertTrue(store.findByHash("late").isPresent());
  }
}
