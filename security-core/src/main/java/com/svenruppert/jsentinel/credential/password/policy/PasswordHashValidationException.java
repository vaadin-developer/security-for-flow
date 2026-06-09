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
package com.svenruppert.jsentinel.credential.password.policy;

/**
 * Thrown by {@link PasswordHashValidator} when a structurally well-formed
 * envelope is rejected by the active {@link PasswordHashPolicy}.
 *
 * <p>Validation happens before any KDF is executed; this exception is
 * therefore the gate that prevents
 * {@linkplain java.util.Map parameter}-driven resource exhaustion.</p>
 *
 * <p>Messages remain structural and must not embed envelope payloads,
 * salts, inner-hash material or pepper key identifiers.</p>
 */
public final class PasswordHashValidationException extends RuntimeException {

  public PasswordHashValidationException(String message) {
    super(message);
  }

  public PasswordHashValidationException(String message, Throwable cause) {
    super(message, cause);
  }
}
