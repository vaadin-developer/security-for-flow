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

import com.svenruppert.vaadin.security.authorization.api.tenant.TenantId;
import com.svenruppert.vaadin.security.logout.SubjectId;
import com.svenruppert.vaadin.security.session.SecurityVersion;
import com.svenruppert.vaadin.security.session.SecurityVersionKey;
import com.svenruppert.vaadin.security.session.SecurityVersionStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Contract every {@link SecurityVersionStore} implementation must
 * satisfy.
 */
@DisplayName("SecurityVersionStore — contract")
public interface SecurityVersionStoreContract {

  /**
   * @return a fresh, empty {@code SecurityVersionStore}
   */
  SecurityVersionStore newStore();

  SubjectId ALICE = new SubjectId("alice");
  SubjectId BOB = new SubjectId("bob");
  TenantId ACME = new TenantId("acme");

  /**
   * Builds a key in the default tenant.
   *
   * @param subject subject identifier
   * @return new key
   */
  default SecurityVersionKey key(SubjectId subject) {
    return new SecurityVersionKey(TenantId.DEFAULT, subject);
  }

  @Test
  @DisplayName("current on an unknown key returns INITIAL")
  default void unknownReturnsInitial() {
    SecurityVersionStore store = newStore();
    assertEquals(SecurityVersion.INITIAL, store.current(key(ALICE)));
  }

  @Test
  @DisplayName("first increment transitions INITIAL → 1")
  default void firstIncrementFromInitial() {
    SecurityVersionStore store = newStore();
    SecurityVersion v1 = store.increment(key(ALICE));
    assertEquals(new SecurityVersion(1), v1);
    assertEquals(v1, store.current(key(ALICE)));
  }

  @Test
  @DisplayName("further increments produce monotonic values")
  default void incrementsMonotonic() {
    SecurityVersionStore store = newStore();
    store.increment(key(ALICE));
    store.increment(key(ALICE));
    SecurityVersion v3 = store.increment(key(ALICE));
    assertEquals(new SecurityVersion(3), v3);
    assertEquals(v3, store.current(key(ALICE)));
  }

  @Test
  @DisplayName("reset drops the counter; current returns INITIAL")
  default void resetReturnsToInitial() {
    SecurityVersionStore store = newStore();
    store.increment(key(ALICE));
    store.increment(key(ALICE));
    store.reset(key(ALICE));
    assertEquals(SecurityVersion.INITIAL, store.current(key(ALICE)));
  }

  @Test
  @DisplayName("reset followed by increment restarts at 1")
  default void resetThenIncrement() {
    SecurityVersionStore store = newStore();
    store.increment(key(ALICE));
    store.increment(key(ALICE));
    store.reset(key(ALICE));
    assertEquals(new SecurityVersion(1), store.increment(key(ALICE)));
  }

  @Test
  @DisplayName("reset on an unknown key is a no-op")
  default void resetUnknownIsNoOp() {
    SecurityVersionStore store = newStore();
    store.reset(key(ALICE));
    assertEquals(SecurityVersion.INITIAL, store.current(key(ALICE)));
  }

  @Test
  @DisplayName("versions are independent across subjects")
  default void subjectsIndependent() {
    SecurityVersionStore store = newStore();
    store.increment(key(ALICE));
    store.increment(key(ALICE));
    store.increment(key(BOB));
    assertEquals(new SecurityVersion(2), store.current(key(ALICE)));
    assertEquals(new SecurityVersion(1), store.current(key(BOB)));
  }

  @Test
  @DisplayName("tenant is part of the key — independent versions per tenant for the same subject")
  default void tenantPartOfKey() {
    SecurityVersionStore store = newStore();
    SecurityVersionKey defaultScope = new SecurityVersionKey(TenantId.DEFAULT, ALICE);
    SecurityVersionKey acmeScope = new SecurityVersionKey(ACME, ALICE);
    store.increment(defaultScope);
    store.increment(defaultScope);
    store.increment(acmeScope);
    assertEquals(new SecurityVersion(2), store.current(defaultScope));
    assertEquals(new SecurityVersion(1), store.current(acmeScope));
  }

  @Test
  @DisplayName("all methods reject null key")
  default void rejectNulls() {
    SecurityVersionStore store = newStore();
    assertThrows(NullPointerException.class, () -> store.current(null));
    assertThrows(NullPointerException.class, () -> store.increment(null));
    assertThrows(NullPointerException.class, () -> store.reset(null));
  }
}
