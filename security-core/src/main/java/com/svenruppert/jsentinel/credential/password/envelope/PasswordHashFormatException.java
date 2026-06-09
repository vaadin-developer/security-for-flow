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
package com.svenruppert.jsentinel.credential.password.envelope;

/**
 * Thrown by {@link PasswordHashCodec} when the supplied input cannot be
 * parsed as a valid Phase-1a envelope.
 *
 * <p>Message strings of this exception type must remain structural; they
 * describe what is wrong with the envelope itself (missing field name,
 * unknown format version, malformed key/value pair) and must never embed
 * raw input fragments, salt material, inner hash material or pepper key
 * identifiers.</p>
 */
public final class PasswordHashFormatException extends RuntimeException {

  public PasswordHashFormatException(String message) {
    super(message);
  }

  public PasswordHashFormatException(String message, Throwable cause) {
    super(message, cause);
  }
}
