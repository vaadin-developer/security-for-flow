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
package com.svenruppert.jsentinel.credential.password.pepper;

import java.util.Arrays;
import java.util.Objects;

/**
 * Resolved pepper material handed to a {@code PasswordHashProvider}.
 *
 * <p>Carries the stable {@code keyId} (recorded in the envelope so the
 * verifier can resolve the same key) plus a defensive copy of the
 * pepper bytes themselves. The byte array is owned by this record; do
 * not mutate it.</p>
 *
 * <p>{@link #toString()} never exposes the key material (CWE-209 /
 * CWE-522).</p>
 *
 * @param keyId stable identifier; written into the envelope
 * @param key   pepper material; minimum 32 bytes for HMAC-SHA-256
 */
public record PepperReference(String keyId, byte[] key) {

  /** Minimum key length expected for HMAC-SHA-256 (256-bit). */
  public static final int MIN_KEY_BYTES = 32;

  public PepperReference {
    Objects.requireNonNull(keyId, "keyId");
    if (keyId.isBlank()) {
      throw new IllegalArgumentException("keyId must not be blank");
    }
    Objects.requireNonNull(key, "key");
    if (key.length < MIN_KEY_BYTES) {
      throw new IllegalArgumentException(
          "pepper key must be at least " + MIN_KEY_BYTES + " bytes");
    }
    // Defensive copy so the caller cannot mutate the stored key.
    key = key.clone();
  }

  /**
   * Returns a fresh copy of the key bytes. The internal array stays
   * untouched.
   */
  public byte[] copyKey() {
    return key.clone();
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof PepperReference that)) {
      return false;
    }
    return keyId.equals(that.keyId) && Arrays.equals(key, that.key);
  }

  @Override
  public int hashCode() {
    return keyId.hashCode() * 31 + Arrays.hashCode(key);
  }

  @Override
  public String toString() {
    return "PepperReference[keyId=" + keyId
        + ", keyLength=" + key.length + ", key=<redacted>]";
  }
}
