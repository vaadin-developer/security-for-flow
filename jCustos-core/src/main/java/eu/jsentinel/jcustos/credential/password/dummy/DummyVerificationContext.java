/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */
package eu.jsentinel.jcustos.credential.password.dummy;

/**
 * Why the verification pipeline took the dummy KDF path.
 *
 * <p>Carried internally so audit sinks can differentiate the
 * enumeration-resistant failures, but never surfaced through the public
 * response (CWE-203).</p>
 */
public enum DummyVerificationContext {
  UNKNOWN_USER,
  ENVELOPE_DECODE_ERROR,
  ENVELOPE_VALIDATION_ERROR,
  PROVIDER_MISSING,
  PEPPER_KEY_UNKNOWN,

  /**
   * The stored hash used an algorithm other than the preferred one, so the
   * verification ran a KDF of a different cost. The dummy run brings the total
   * back up to the preferred cost, keeping a lazy migration from leaking which
   * accounts are still on the old algorithm (CWE-208).
   *
   * @since 00.82.00
   */
  NON_PREFERRED_ALGORITHM_COST_FLOOR
}
