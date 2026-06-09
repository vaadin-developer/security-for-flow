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
package com.svenruppert.jsentinel.credential.password.pbkdf2;

/**
 * Stable parameter-key constants used by the PBKDF2 envelope.
 *
 * <p>The keys are intentionally short to keep the encoded envelope
 * compact. They are part of the Phase-1a wire contract; renaming them
 * would break stored hashes.</p>
 */
public final class Pbkdf2ParameterNames {

  /** Canonical algorithm identifier. */
  public static final String ALGORITHM = "PBKDF2WithHmacSHA256";

  /** Canonical Phase-1a JDK provider id. */
  public static final String PROVIDER_ID = "pbkdf2-jdk";

  /** Iteration count, decimal integer. */
  public static final String ITERATIONS = "i";

  /** Base64-encoded random salt. */
  public static final String SALT = "s";

  /** Derived-key length in bytes, decimal integer. */
  public static final String KEY_LENGTH = "l";

  /** Salt length in bytes, decimal integer; used by min/max bounds. */
  public static final String SALT_LENGTH = "sl";

  private Pbkdf2ParameterNames() { }
}
