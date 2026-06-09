/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * http://ec.europa.eu/idabc/eupl5
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */
package com.svenruppert.jsentinel.credential.change;

import com.svenruppert.jsentinel.credential.secret.SecretValue;

import java.util.Objects;

/**
 * Input to {@link PasswordChangeService#change}.
 *
 * <p>The two {@link SecretValue}s are owned by the caller and are
 * <em>not</em> destroyed by the service. Wrap the call in a
 * try-with-resources block when possible.</p>
 *
 * @param username        the user whose credential is being changed
 * @param currentPassword the present-day password — required for the
 *                        explicit re-authentication step (CWE-620)
 * @param newPassword     the proposed new password
 */
public record PasswordChangeCommand(
    String username,
    SecretValue currentPassword,
    SecretValue newPassword
) {

  public PasswordChangeCommand {
    Objects.requireNonNull(username, "username");
    if (username.isBlank()) {
      throw new IllegalArgumentException("username must not be blank");
    }
    Objects.requireNonNull(currentPassword, "currentPassword");
    Objects.requireNonNull(newPassword, "newPassword");
  }
}
