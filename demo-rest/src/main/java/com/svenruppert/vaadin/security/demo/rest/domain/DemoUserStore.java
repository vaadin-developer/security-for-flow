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

import com.svenruppert.vaadin.security.bootstrap.PasswordHasher;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * In-memory demo user store. Demo-only — not for production.
 * <p>
 * When {@code bootstrapMode} is {@code true}, the administrator user is
 * not pre-populated; the first administrator must be created via the
 * bootstrap mechanism.
 */
public final class DemoUserStore {

  private final Map<String, DemoUser> users = new LinkedHashMap<>();
  private final PasswordHasher hasher;

  public DemoUserStore(PasswordHasher hasher) {
    this(hasher, false);
  }

  public DemoUserStore(PasswordHasher hasher, boolean bootstrapMode) {
    this.hasher = hasher;
    if (!bootstrapMode) {
      register("admin", "admin", "Admin User", DemoRole.ROLE_ADMIN);
    }
    register("editor", "editor", "Editor User", DemoRole.ROLE_EDITOR);
    register("viewer", "viewer", "Viewer User", DemoRole.ROLE_VIEWER);
  }

  private void register(String username, String plaintextPassword, String displayName, DemoRole role) {
    String hash = hasher.hash(plaintextPassword.toCharArray());
    users.put(username, new DemoUser(username, displayName, hash, role));
  }

  public synchronized Optional<DemoUser> authenticate(String username, String password) {
    DemoUser user = users.get(username);
    if (user == null) {
      return Optional.empty();
    }
    char[] raw = password.toCharArray();
    if (!hasher.verify(raw, user.passwordHash())) {
      return Optional.empty();
    }
    DemoUser current = user;
    if (hasher.needsRehash(current.passwordHash())) {
      try {
        String freshHash = hasher.hash(raw);
        DemoUser upgraded = new DemoUser(
            current.username(), current.displayName(), freshHash, current.role());
        users.put(upgraded.username(), upgraded);
        current = upgraded;
      } catch (RuntimeException rehashFailure) {
        // Login already succeeded against the existing hash; failing to
        // upgrade the hash on this login attempt is not a security
        // failure. Fall through with the original user.
      }
    }
    return Optional.of(current);
  }

  /** Test seam: returns the stored hash for the given username, or empty. */
  public synchronized Optional<String> storedPasswordHash(String username) {
    DemoUser user = users.get(username);
    return user == null ? Optional.empty() : Optional.of(user.passwordHash());
  }

  public synchronized void register(DemoUser user) {
    if (users.containsKey(user.username())) {
      throw new IllegalStateException("user already exists: " + user.username());
    }
    users.put(user.username(), user);
  }

  public synchronized boolean hasAnyAdministrator() {
    return users.values().stream().anyMatch(u -> u.role() == DemoRole.ROLE_ADMIN);
  }
}
