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
package com.svenruppert.vaadin.security.bootstrap;

import java.util.Objects;

/**
 * Carrier record handed to {@link AdministratorAccountStore#createAdministrator(NewAdministrator)}.
 * The password is already hashed.
 */
public record NewAdministrator(
    String username,
    String displayName,
    String email,
    String passwordHash
) {

  public NewAdministrator {
    Objects.requireNonNull(username, "username");
    if (username.isBlank()) throw new IllegalArgumentException("username must not be blank");
    Objects.requireNonNull(passwordHash, "passwordHash");
    if (passwordHash.isBlank()) throw new IllegalArgumentException("passwordHash must not be blank");
  }
}
