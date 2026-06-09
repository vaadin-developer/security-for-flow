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
package com.svenruppert.jsentinel.credential.history;

import java.time.Instant;
import java.util.Objects;

/**
 * Single archived password verifier — the full envelope as it was
 * stored at the time. The envelope itself already redacts secrets in
 * {@link #toString()} via the credential package.
 */
public record PasswordHistoryEntry(String encodedHash, Instant recordedAt) {

  public PasswordHistoryEntry {
    Objects.requireNonNull(encodedHash, "encodedHash");
    if (encodedHash.isBlank()) {
      throw new IllegalArgumentException("encodedHash must not be blank");
    }
    Objects.requireNonNull(recordedAt, "recordedAt");
  }

  @Override
  public String toString() {
    return "PasswordHistoryEntry[recordedAt=" + recordedAt
        + ", encodedHash=<redacted>]";
  }
}
