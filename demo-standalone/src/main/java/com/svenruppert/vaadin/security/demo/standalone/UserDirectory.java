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
package com.svenruppert.vaadin.security.demo.standalone;

import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * In-memory user directory shared across the demo's
 * {@code AuthenticationService} and {@code AuthorizationService}
 * SPI implementations. Singleton; the demo populates it from
 * {@link DemoApp}.
 */
public final class UserDirectory {

  private static final UserDirectory INSTANCE = new UserDirectory();

  private final Map<String, Stored> byUsername = new HashMap<>();

  private UserDirectory() {
    addUser("admin", "admin", new User("admin", "Administrator",
        EnumSet.of(Role.ADMIN, Role.LIBRARIAN, Role.MEMBER)));
    addUser("librarian", "librarian", new User("librarian", "Librarian",
        EnumSet.of(Role.LIBRARIAN, Role.MEMBER)));
    addUser("alice", "alice", new User("alice", "Alice",
        EnumSet.of(Role.MEMBER)));
  }

  public static UserDirectory instance() {
    return INSTANCE;
  }

  public void addUser(String username, String password, User user) {
    byUsername.put(username, new Stored(user, password));
  }

  public Optional<User> findByCredentials(Credentials credentials) {
    Stored stored = byUsername.get(credentials.username());
    if (stored == null || !stored.password.equals(credentials.password())) {
      return Optional.empty();
    }
    return Optional.of(stored.user);
  }

  private record Stored(User user, String password) { }
}
