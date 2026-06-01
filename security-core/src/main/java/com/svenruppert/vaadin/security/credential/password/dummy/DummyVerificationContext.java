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
package com.svenruppert.vaadin.security.credential.password.dummy;

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
  PEPPER_KEY_UNKNOWN
}
