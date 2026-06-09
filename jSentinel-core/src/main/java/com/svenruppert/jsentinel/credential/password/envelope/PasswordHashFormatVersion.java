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

import java.util.Arrays;

/**
 * Known envelope wire-format versions.
 *
 * <p>The wire value is the integer printed on the wire; the enum names
 * are stable Java identifiers. Decoders must reject any wire value that
 * does not map to a known constant (via
 * {@link #fromWireValue(int)}) so unknown newer formats fail loudly
 * instead of being silently downgraded.</p>
 */
public enum PasswordHashFormatVersion {

  /**
   * First productive Phase-1a envelope.
   */
  V1(1);

  /**
   * Maximum wire value currently understood. Used by the codec to bound
   * the legal range when parsing.
   */
  public static final int MAX_KNOWN_WIRE_VALUE = Arrays.stream(values())
      .mapToInt(PasswordHashFormatVersion::wireValue)
      .max()
      .orElseThrow();

  /**
   * Format that newly produced envelopes should declare.
   */
  public static final PasswordHashFormatVersion CURRENT = V1;

  private final int wireValue;

  PasswordHashFormatVersion(int wireValue) {
    this.wireValue = wireValue;
  }

  public int wireValue() {
    return wireValue;
  }

  /**
   * Resolves the enum constant that matches the supplied wire value.
   *
   * @throws PasswordHashFormatException if the value is not recognised.
   */
  public static PasswordHashFormatVersion fromWireValue(int wireValue) {
    for (PasswordHashFormatVersion v : values()) {
      if (v.wireValue == wireValue) {
        return v;
      }
    }
    throw new PasswordHashFormatException(
        "Unknown envelope format version: " + wireValue);
  }
}
