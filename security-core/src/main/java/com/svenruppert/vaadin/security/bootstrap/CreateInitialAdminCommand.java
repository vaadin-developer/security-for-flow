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
 * Command consumed by {@link InitialAdminBootstrapService#createInitialAdmin}.
 * <p>
 * The {@code password} field uses {@code char[]} so the caller can clear it
 * after use. The bootstrap service hashes it and clears the array before
 * returning.
 */
public record CreateInitialAdminCommand(
    String bootstrapToken,
    String username,
    char[] password,
    String displayName,
    String email
) {

  public CreateInitialAdminCommand {
    Objects.requireNonNull(bootstrapToken, "bootstrapToken");
    Objects.requireNonNull(username, "username");
    Objects.requireNonNull(password, "password");
  }
}
