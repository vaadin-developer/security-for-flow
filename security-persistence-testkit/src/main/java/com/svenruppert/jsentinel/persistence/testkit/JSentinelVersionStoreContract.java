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

import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import com.svenruppert.jsentinel.logout.SubjectId;
import com.svenruppert.jsentinel.session.JSentinelVersion;
import com.svenruppert.jsentinel.session.JSentinelVersionKey;
import com.svenruppert.jsentinel.session.JSentinelVersionStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Contract every {@link JSentinelVersionStore} implementation must
 * satisfy.
 */
@DisplayName("JSentinelVersionStore — contract")
public interface JSentinelVersionStoreContract {

  /**
   * @return a fresh, empty {@code JSentinelVersionStore}
   */
  JSentinelVersionStore newStore();

  SubjectId ALICE = new SubjectId("alice");
  SubjectId BOB = new SubjectId("bob");
  TenantId ACME = new TenantId("acme");

  /**
   * Builds a key in the default tenant.
   *
   * @param subject subject identifier
   * @return new key
   */
  default JSentinelVersionKey key(SubjectId subject) {
    return new JSentinelVersionKey(TenantId.DEFAULT, subject);
  }

  @Test
  @DisplayName("current on an unknown key returns INITIAL")
  default void unknownReturnsInitial() {
    JSentinelVersionStore store = newStore();
    assertEquals(JSentinelVersion.INITIAL, store.current(key(ALICE)));
  }

  @Test
  @DisplayName("first increment transitions INITIAL → 1")
  default void firstIncrementFromInitial() {
    JSentinelVersionStore store = newStore();
    JSentinelVersion v1 = store.increment(key(ALICE));
    assertEquals(new JSentinelVersion(1), v1);
    assertEquals(v1, store.current(key(ALICE)));
  }

  @Test
  @DisplayName("further increments produce monotonic values")
  default void incrementsMonotonic() {
    JSentinelVersionStore store = newStore();
    store.increment(key(ALICE));
    store.increment(key(ALICE));
    JSentinelVersion v3 = store.increment(key(ALICE));
    assertEquals(new JSentinelVersion(3), v3);
    assertEquals(v3, store.current(key(ALICE)));
  }

  @Test
  @DisplayName("reset drops the counter; current returns INITIAL")
  default void resetReturnsToInitial() {
    JSentinelVersionStore store = newStore();
    store.increment(key(ALICE));
    store.increment(key(ALICE));
    store.reset(key(ALICE));
    assertEquals(JSentinelVersion.INITIAL, store.current(key(ALICE)));
  }

  @Test
  @DisplayName("reset followed by increment restarts at 1")
  default void resetThenIncrement() {
    JSentinelVersionStore store = newStore();
    store.increment(key(ALICE));
    store.increment(key(ALICE));
    store.reset(key(ALICE));
    assertEquals(new JSentinelVersion(1), store.increment(key(ALICE)));
  }

  @Test
  @DisplayName("reset on an unknown key is a no-op")
  default void resetUnknownIsNoOp() {
    JSentinelVersionStore store = newStore();
    store.reset(key(ALICE));
    assertEquals(JSentinelVersion.INITIAL, store.current(key(ALICE)));
  }

  @Test
  @DisplayName("versions are independent across subjects")
  default void subjectsIndependent() {
    JSentinelVersionStore store = newStore();
    store.increment(key(ALICE));
    store.increment(key(ALICE));
    store.increment(key(BOB));
    assertEquals(new JSentinelVersion(2), store.current(key(ALICE)));
    assertEquals(new JSentinelVersion(1), store.current(key(BOB)));
  }

  @Test
  @DisplayName("tenant is part of the key — independent versions per tenant for the same subject")
  default void tenantPartOfKey() {
    JSentinelVersionStore store = newStore();
    JSentinelVersionKey defaultScope = new JSentinelVersionKey(TenantId.DEFAULT, ALICE);
    JSentinelVersionKey acmeScope = new JSentinelVersionKey(ACME, ALICE);
    store.increment(defaultScope);
    store.increment(defaultScope);
    store.increment(acmeScope);
    assertEquals(new JSentinelVersion(2), store.current(defaultScope));
    assertEquals(new JSentinelVersion(1), store.current(acmeScope));
  }

  @Test
  @DisplayName("all methods reject null key")
  default void rejectNulls() {
    JSentinelVersionStore store = newStore();
    assertThrows(NullPointerException.class, () -> store.current(null));
    assertThrows(NullPointerException.class, () -> store.increment(null));
    assertThrows(NullPointerException.class, () -> store.reset(null));
  }
}
