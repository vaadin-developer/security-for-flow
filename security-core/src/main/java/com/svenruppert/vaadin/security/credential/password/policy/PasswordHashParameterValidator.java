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
package com.svenruppert.vaadin.security.credential.password.policy;

import java.util.Map;

/**
 * Algorithm-specific validator for a {@code parameters} map carried by a
 * password-hash envelope.
 *
 * <p>Phase 1a ships only the PBKDF2 implementation. Modern profile
 * algorithms (Argon2id, bcrypt, scrypt) plug their validators in through
 * the same SPI from the optional {@code security-crypto-bc} module.</p>
 *
 * <p>Validators must complete in O(parameters) time and must not run any
 * KDF, decode arbitrary user input or call out to providers. They are
 * the cheap gate that runs <em>before</em> the expensive hashing step.</p>
 */
public interface PasswordHashParameterValidator {

  /**
   * Algorithm identifier this validator handles, matched verbatim against
   * the {@code alg} field of the envelope.
   */
  String algorithm();

  /**
   * Validates the supplied parameter map against the active policy
   * bounds.
   *
   * @param parameters parameters as parsed from the envelope
   * @param minimum    lower bound from the active policy
   * @param maximum    upper bound from the active policy
   * @throws PasswordHashValidationException on the first violation
   */
  void validate(
      Map<String, String> parameters,
      Map<String, String> minimum,
      Map<String, String> maximum);
}
