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

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * In-memory demo user store. Demo-only — not for production.
 */
public final class DemoUserStore {

  private final Map<String, DemoUser> users = new LinkedHashMap<>();

  public DemoUserStore() {
    register(new DemoUser("admin", "Admin User", "admin", DemoRole.ROLE_ADMIN));
    register(new DemoUser("editor", "Editor User", "editor", DemoRole.ROLE_EDITOR));
    register(new DemoUser("viewer", "Viewer User", "viewer", DemoRole.ROLE_VIEWER));
  }

  private void register(DemoUser user) {
    users.put(user.username(), user);
  }

  public Optional<DemoUser> authenticate(String username, String password) {
    DemoUser user = users.get(username);
    if (user == null || !user.password().equals(password)) {
      return Optional.empty();
    }
    return Optional.of(user);
  }
}
