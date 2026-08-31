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
package eu.jsentinel.jcustos.credential.password.policy;

import eu.jsentinel.jcustos.credential.password.envelope.PasswordHashEnvelope;

/**
 * Validates a parsed envelope against the active policy <em>before</em>
 * a KDF is executed. The validator is the budget gate: it rejects
 * malformed or out-of-bound parameters cheaply so that no expensive
 * provider runs against unbounded input.
 */
public interface PasswordHashValidator {

  /**
   * @throws PasswordHashValidationException on the first policy
   *                                          violation
   */
  ValidatedPasswordHash validate(
      PasswordHashEnvelope envelope,
      PasswordHashPolicy policy);
}
