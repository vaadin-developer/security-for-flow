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
package com.svenruppert.vaadin.security.demo.app.security.model;

import com.svenruppert.vaadin.security.bootstrap.Pbkdf2PasswordHasher;
import com.svenruppert.vaadin.security.demo.app.security.roles.AuthorizationRole;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("InMemoryDemoUserDirectory — rehash on successful login")
class InMemoryDemoUserDirectoryRehashTest {

  @Test
  @DisplayName("findByCredentials with same hasher → no drift → stored hash unchanged")
  void noDrift_noRehash() {
    Pbkdf2PasswordHasher hasher = new Pbkdf2PasswordHasher(1_000, new SecureRandom());
    InMemoryDemoUserDirectory directory = new InMemoryDemoUserDirectory(hasher);

    String before = directory.storedPasswordHash("user").orElseThrow();

    Optional<MyUser> resolved = directory.findByCredentials(new Credentials("user", "user"));

    assertTrue(resolved.isPresent());
    assertEquals(before, directory.storedPasswordHash("user").orElseThrow(),
        "no parameter drift → stored hash must not be touched");
  }

  @Test
  @DisplayName("findByCredentials with drifted hasher → stored hash gets upgraded")
  void driftDetected_rehash() {
    // Pre-stage a hash with the older iteration count
    Pbkdf2PasswordHasher older = new Pbkdf2PasswordHasher(1_000, new SecureRandom());
    String oldHash = older.hash("legacy".toCharArray());

    Pbkdf2PasswordHasher newer = new Pbkdf2PasswordHasher(2_000, new SecureRandom());
    InMemoryDemoUserDirectory directory = new InMemoryDemoUserDirectory(newer);
    HashSet<AuthorizationRole> roles = new HashSet<>();
    roles.add(AuthorizationRole.USER);
    directory.registerWithHashedPassword(
        "legacy", oldHash, new MyUser(99L, "Legacy User", roles));

    String hashBefore = directory.storedPasswordHash("legacy").orElseThrow();

    Optional<MyUser> resolved = directory.findByCredentials(new Credentials("legacy", "legacy"));

    assertTrue(resolved.isPresent(), "verify must still succeed against the legacy hash");
    String hashAfter = directory.storedPasswordHash("legacy").orElseThrow();
    assertNotEquals(hashBefore, hashAfter,
        "drift must trigger a re-hash; stored hash must change");
    assertTrue(hashAfter.contains("$2000$"),
        "fresh hash must reflect the newer iteration count: " + hashAfter);
  }

  @Test
  @DisplayName("findByCredentials with wrong password → no rehash")
  void wrongPassword_noRehash() {
    Pbkdf2PasswordHasher hasher = new Pbkdf2PasswordHasher(1_000, new SecureRandom());
    InMemoryDemoUserDirectory directory = new InMemoryDemoUserDirectory(hasher);
    String before = directory.storedPasswordHash("user").orElseThrow();

    Optional<MyUser> resolved = directory.findByCredentials(new Credentials("user", "wrong"));

    assertTrue(resolved.isEmpty());
    assertEquals(before, directory.storedPasswordHash("user").orElseThrow());
  }

  @Test
  @DisplayName("findByCredentials with unknown username → empty, no side effects")
  void unknownUser_empty() {
    Pbkdf2PasswordHasher hasher = new Pbkdf2PasswordHasher(1_000, new SecureRandom());
    InMemoryDemoUserDirectory directory = new InMemoryDemoUserDirectory(hasher);

    Optional<MyUser> resolved = directory.findByCredentials(new Credentials("nobody", "anything"));

    assertTrue(resolved.isEmpty());
  }
}
