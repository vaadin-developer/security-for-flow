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
import com.svenruppert.vaadin.security.bruteforce.LoginAttemptKey;
import com.svenruppert.vaadin.security.bruteforce.LoginAttemptStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Contract every {@link LoginAttemptStore} implementation must
 * satisfy.
 */
@DisplayName("LoginAttemptStore — contract")
public interface LoginAttemptStoreContract {

  /**
   * @return a fresh, empty {@code LoginAttemptStore}
   */
  LoginAttemptStore newStore();

  /**
   * Builds a key with {@link TenantId#DEFAULT}.
   *
   * @param user username dimension
   * @param ip   client address
   * @return new key
   */
  default LoginAttemptKey key(String user, String ip) {
    return new LoginAttemptKey(TenantId.DEFAULT, user, ip);
  }

  @Test
  @DisplayName("recordFailure increments the counter and stores the timestamp")
  default void recordFailureIncrements() {
    LoginAttemptStore store = newStore();
    Instant t0 = Instant.parse("2026-01-01T00:00:00Z");
    LoginAttemptKey k = key("alice", "1.1.1.1");

    store.recordFailure(k, t0);
    assertEquals(1, store.failureCount(k));
    assertEquals(Optional.of(t0), store.lastFailureAt(k));

    Instant t1 = t0.plusSeconds(30);
    store.recordFailure(k, t1);
    assertEquals(2, store.failureCount(k));
    assertEquals(Optional.of(t1), store.lastFailureAt(k));
  }

  @Test
  @DisplayName("failureCount / lastFailureAt return 0 / empty for an unknown key")
  default void unknownKeyDefaults() {
    LoginAttemptStore store = newStore();
    assertEquals(0, store.failureCount(key("ghost", "1.1.1.1")));
    assertTrue(store.lastFailureAt(key("ghost", "1.1.1.1")).isEmpty());
  }

  @Test
  @DisplayName("reset drops counter and timestamp")
  default void resetClears() {
    LoginAttemptStore store = newStore();
    LoginAttemptKey k = key("alice", "1.1.1.1");
    store.recordFailure(k, Instant.now());
    store.reset(k);
    assertEquals(0, store.failureCount(k));
    assertTrue(store.lastFailureAt(k).isEmpty());
  }

  @Test
  @DisplayName("reset on an unknown key is a no-op")
  default void resetUnknownIsNoOp() {
    LoginAttemptStore store = newStore();
    store.reset(key("ghost", "1.1.1.1"));
    assertEquals(0, store.failureCount(key("ghost", "1.1.1.1")));
  }

  @Test
  @DisplayName("counters are keyed per (tenant, user, ip)")
  default void countersAreKeyIndependent() {
    LoginAttemptStore store = newStore();
    Instant t = Instant.now();
    store.recordFailure(key("alice", "1.1.1.1"), t);
    store.recordFailure(key("alice", "1.1.1.1"), t);
    store.recordFailure(key("alice", "2.2.2.2"), t);
    store.recordFailure(key("bob", "1.1.1.1"), t);

    assertEquals(2, store.failureCount(key("alice", "1.1.1.1")));
    assertEquals(1, store.failureCount(key("alice", "2.2.2.2")));
    assertEquals(1, store.failureCount(key("bob", "1.1.1.1")));
  }

  @Test
  @DisplayName("tenant is part of the key — same (user,ip) under different tenants are independent")
  default void tenantPartOfKey() {
    LoginAttemptStore store = newStore();
    Instant t = Instant.now();
    LoginAttemptKey defaultScope =
        new LoginAttemptKey(TenantId.DEFAULT, "alice", "1.1.1.1");
    LoginAttemptKey acmeScope =
        new LoginAttemptKey(new TenantId("acme"), "alice", "1.1.1.1");

    store.recordFailure(defaultScope, t);
    store.recordFailure(defaultScope, t);
    store.recordFailure(acmeScope, t);

    assertEquals(2, store.failureCount(defaultScope));
    assertEquals(1, store.failureCount(acmeScope));
  }

  @Test
  @DisplayName("all methods reject null arguments")
  default void rejectNulls() {
    LoginAttemptStore store = newStore();
    Instant t = Instant.now();
    assertThrows(NullPointerException.class, () -> store.recordFailure(null, t));
    assertThrows(NullPointerException.class,
        () -> store.recordFailure(key("alice", "1.1.1.1"), null));
    assertThrows(NullPointerException.class, () -> store.failureCount(null));
    assertThrows(NullPointerException.class, () -> store.lastFailureAt(null));
    assertThrows(NullPointerException.class, () -> store.reset(null));
  }
}
