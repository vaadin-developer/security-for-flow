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

import com.svenruppert.vaadin.security.bootstrap.PasswordHasher;
import com.svenruppert.vaadin.security.bootstrap.Pbkdf2PasswordHasher;
import com.svenruppert.vaadin.security.demo.app.security.roles.AuthorizationRole;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;

public class UserStorage {

  private static final PasswordHasher HASHER = new Pbkdf2PasswordHasher();
  private static final Map<String, StoredUser> BY_USERNAME = new ConcurrentHashMap<>();
  private static final Map<Long, MyUser> BY_ID = new ConcurrentHashMap<>();

  static {
    // DEMO ONLY: hard-coded plaintext credentials hashed at startup so the sample is easy to run.
    // The bootstrap demo opt-in (UserStorage.enableBootstrapMode) removes the admin entry so the
    // first administrator must be created via the bootstrap mechanism.
    //addUser("admin", "admin", createMyUser(1L, "Herr Admin", AuthorizationRole.ADMIN));
    addUser("user", "user", createMyUser(2L, "Herr User", AuthorizationRole.USER));
    addUser("demo", "demo", createMyUser(3L, "Herr Demo", AuthorizationRole.NERD));
  }

  private UserStorage() {
  }

  static MyUser createMyUser(Long id, String name, AuthorizationRole... roles) {
    Objects.requireNonNull(id);
    Objects.requireNonNull(name);
    Objects.requireNonNull(roles);
    HashSet<AuthorizationRole> roleHashSet = new HashSet<>();
    Collections.addAll(roleHashSet, roles);
    roleHashSet.add(AuthorizationRole.USER);
    return new MyUser(id, name, roleHashSet);
  }

  /** Demo seam — the bootstrap demo calls this to remove the pre-populated admin entry. */
  public static synchronized void enableBootstrapMode() {
    BY_USERNAME.values().removeIf(stored -> stored.user.roles().contains(AuthorizationRole.ADMIN));
    BY_ID.values().removeIf(user -> user.roles().contains(AuthorizationRole.ADMIN));
  }

  public static synchronized boolean hasAnyAdministrator() {
    return BY_USERNAME.values().stream()
        .anyMatch(stored -> stored.user.roles().contains(AuthorizationRole.ADMIN));
  }

  public static synchronized void deleteUser(Long id) {
    MyUser removed = BY_ID.remove(id);
    if (removed == null) return;
    BY_USERNAME.values().removeIf(stored -> stored.user.equals(removed));
  }

  public static synchronized void addUser(String username, String plaintextPassword, MyUser user) {
    Objects.requireNonNull(username);
    Objects.requireNonNull(plaintextPassword);
    Objects.requireNonNull(user);
    String hash = HASHER.hash(plaintextPassword.toCharArray());
    BY_USERNAME.put(username, new StoredUser(user, hash));
    BY_ID.put(user.id(), user);
  }

  /** Bootstrap entry point — registers a user whose password is already hashed. */
  public static synchronized void registerHashed(String username, String passwordHash, MyUser user) {
    if (BY_USERNAME.containsKey(username)) {
      throw new IllegalStateException("user already exists: " + username);
    }
    BY_USERNAME.put(username, new StoredUser(user, passwordHash));
    BY_ID.put(user.id(), user);
  }

  public static boolean checkCredentials(Credentials credentials) {
    return resolve(credentials).isPresent();
  }

  public static MyUser userByCredentials(Credentials credentials) {
    return resolve(credentials).orElse(null);
  }

  public static MyUser userByID(Long id) {
    return BY_ID.get(id);
  }

  public static Stream<MyUser> allUsers() {
    return BY_USERNAME.values().stream().map(stored -> stored.user);
  }

  private static Optional<MyUser> resolve(Credentials credentials) {
    if (credentials == null || credentials.username() == null || credentials.password() == null) {
      return Optional.empty();
    }
    StoredUser stored = BY_USERNAME.get(credentials.username());
    if (stored == null) return Optional.empty();
    if (!HASHER.verify(credentials.password().toCharArray(), stored.passwordHash)) return Optional.empty();
    return Optional.of(stored.user);
  }

  public static PasswordHasher passwordHasher() {
    return HASHER;
  }

  public record Credentials(String username, String password) {
  }

  private record StoredUser(MyUser user, String passwordHash) {
  }
}