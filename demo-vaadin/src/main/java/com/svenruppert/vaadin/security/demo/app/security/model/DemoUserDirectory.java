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

import java.util.Optional;
import java.util.stream.Stream;

/**
 * Demo-side user directory contract. Decoupled from the concrete
 * {@code InMemoryDemoUserDirectory} implementation so different storage
 * back-ends (database, LDAP, IAM) can plug in without touching the
 * consumers.
 * <p>
 * Lives in {@code demo-vaadin} on purpose — it is demo-specific. The
 * project-neutral abstractions are
 * {@link com.svenruppert.vaadin.security.authentication.AuthenticationService}
 * and {@link com.svenruppert.vaadin.security.bootstrap.AdministratorAccountStore}.
 */
public interface DemoUserDirectory {

  /** @return user matching the credentials, or empty if unknown / wrong password */
  Optional<MyUser> findByCredentials(Credentials credentials);

  /** Convenience boolean counterpart of {@link #findByCredentials(Credentials)}. */
  default boolean checkCredentials(Credentials credentials) {
    return findByCredentials(credentials).isPresent();
  }

  /** @return user with the given id, if present */
  Optional<MyUser> findById(Long id);

  /** All known users. The returned stream is independent of the directory state. */
  Stream<MyUser> all();

  /** @return {@code true} if at least one user has the {@code ADMIN} role */
  boolean hasAnyAdministrator();

  /**
   * Adds a user with a plaintext password. Demo-only — the password is
   * hashed at storage time but never stored as plaintext.
   */
  void addUser(String username, String plaintextPassword, MyUser user);

  /**
   * Adds a user whose password is already hashed by the bootstrap service.
   * Used by {@code VaadinAdministratorAccountStore} when the first
   * administrator is created via the bootstrap flow.
   */
  void registerWithHashedPassword(String username, String passwordHash, MyUser user);

  /** Removes the user with the given id. No-op if unknown. */
  void deleteUser(Long id);

  /**
   * Removes any pre-populated administrator entries. Called by the
   * bootstrap wiring before the first-run setup so the demo cannot fall
   * back to a pre-installed admin account.
   */
  void enableBootstrapMode();

  /**
   * The hasher this directory uses for passwords. Exposed so the bootstrap
   * service can produce hashes in the same format the directory expects.
   */
  PasswordHasher passwordHasher();
}
