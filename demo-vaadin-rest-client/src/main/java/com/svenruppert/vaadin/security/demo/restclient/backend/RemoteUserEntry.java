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
package com.svenruppert.vaadin.security.demo.restclient.backend;

import java.util.Objects;

/**
 * Backend-shaped snapshot returned by {@code GET /api/admin/users} and
 * {@code PUT /api/admin/users/{username}}. Mirrors the {@code DemoUser}
 * shape on the server side without leaking the password hash.
 *
 * @param username    unique identifier, never blank
 * @param displayName human-readable name, never {@code null}
 * @param role        current backend role name (e.g. {@code "ROLE_ADMIN"}),
 *                    never {@code null}
 */
public record RemoteUserEntry(String username, String displayName, String role) {

  public RemoteUserEntry {
    Objects.requireNonNull(username, "username");
    Objects.requireNonNull(role, "role");
    if (username.isBlank()) {
      throw new IllegalArgumentException("username must not be blank");
    }
    if (displayName == null) displayName = username;
  }
}
