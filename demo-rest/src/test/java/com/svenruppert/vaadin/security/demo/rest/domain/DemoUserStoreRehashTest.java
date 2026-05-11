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
package com.svenruppert.vaadin.security.demo.rest.domain;

import com.svenruppert.vaadin.security.bootstrap.Pbkdf2PasswordHasher;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("DemoUserStore — rehash on successful login")
class DemoUserStoreRehashTest {

  @Test
  @DisplayName("authenticate with same hasher → no drift → stored hash unchanged")
  void noDrift_noRehash() {
    Pbkdf2PasswordHasher hasher = new Pbkdf2PasswordHasher(1_000, new SecureRandom());
    DemoUserStore store = new DemoUserStore(hasher, false);

    String hashBefore = store.storedPasswordHash("admin").orElseThrow();

    Optional<DemoUser> user = store.authenticate("admin", "admin");

    assertTrue(user.isPresent(), "credentials must verify");
    assertEquals(hashBefore, store.storedPasswordHash("admin").orElseThrow(),
        "no parameter drift → stored hash must not be touched");
  }

  @Test
  @DisplayName("authenticate with hasher whose iteration count drifted → stored hash gets upgraded")
  void driftDetected_rehash() {
    // Bootstrap the store with a low-iteration hasher
    Pbkdf2PasswordHasher older = new Pbkdf2PasswordHasher(1_000, new SecureRandom());
    DemoUserStore store = new DemoUserStore(older, false);
    String hashBefore = store.storedPasswordHash("admin").orElseThrow();

    // Now swap in a hasher with higher iteration count and rerun authenticate
    // by reflectively replacing the hasher in the store. Easier: build a new
    // store with the older hasher, then call authenticate with a *different*
    // hasher via package-private overload — not present.
    // Instead, simulate the drift by registering a user with a different
    // iteration count manually.
    Pbkdf2PasswordHasher newer = new Pbkdf2PasswordHasher(2_000, new SecureRandom());
    DemoUserStore upgradeStore = new DemoUserStore(newer, false);
    // re-register admin with the older hash so the upgradeStore now sees drift
    upgradeStore.register(new DemoUser(
        "drift-user", "Drift User", hashBefore, DemoRole.ROLE_ADMIN));

    String hashBeforeUpgrade = upgradeStore.storedPasswordHash("drift-user").orElseThrow();
    Optional<DemoUser> result = upgradeStore.authenticate("drift-user", "admin");

    assertTrue(result.isPresent(), "verify must still succeed against the older hash");
    String hashAfter = upgradeStore.storedPasswordHash("drift-user").orElseThrow();
    assertNotEquals(hashBeforeUpgrade, hashAfter,
        "drift must trigger a re-hash; stored hash must change");
    assertTrue(hashAfter.contains("$2000$"),
        "fresh hash must reflect the newer iteration count: " + hashAfter);
  }

  @Test
  @DisplayName("authenticate with wrong password → no rehash, no change")
  void wrongPassword_noRehash() {
    Pbkdf2PasswordHasher hasher = new Pbkdf2PasswordHasher(1_000, new SecureRandom());
    DemoUserStore store = new DemoUserStore(hasher, false);
    String hashBefore = store.storedPasswordHash("admin").orElseThrow();

    Optional<DemoUser> user = store.authenticate("admin", "wrong");

    assertTrue(user.isEmpty());
    assertEquals(hashBefore, store.storedPasswordHash("admin").orElseThrow());
  }

  @Test
  @DisplayName("authenticate against unknown user → returns empty without touching the store")
  void unknownUser_noChange() {
    Pbkdf2PasswordHasher hasher = new Pbkdf2PasswordHasher(1_000, new SecureRandom());
    DemoUserStore store = new DemoUserStore(hasher, false);

    Optional<DemoUser> result = store.authenticate("nobody", "anything");

    assertTrue(result.isEmpty());
  }
}
