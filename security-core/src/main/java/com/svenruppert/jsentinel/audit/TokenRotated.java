/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package com.svenruppert.jsentinel.audit;

import java.time.Instant;

import static java.util.Objects.requireNonNull;

/**
 * Emitted when a refresh-token rotation succeeded — the old token
 * was consumed and a fresh access + refresh pair was issued.
 *
 * @param timestamp UTC rotation time; non-null
 * @param subjectId subject the new pair authenticates; non-blank
 * @param oldHash   hash of the consumed refresh token; non-blank
 * @param newHash   hash of the freshly issued refresh token; non-blank
 */
public record TokenRotated(
    Instant timestamp,
    String subjectId,
    String oldHash,
    String newHash
) implements AuditEvent {

  /** Validates the record components. */
  public TokenRotated {
    requireNonNull(timestamp, "timestamp must not be null");
    if (subjectId == null || subjectId.isBlank()) {
      throw new IllegalArgumentException("subjectId must not be blank");
    }
    if (oldHash == null || oldHash.isBlank()) {
      throw new IllegalArgumentException("oldHash must not be blank");
    }
    if (newHash == null || newHash.isBlank()) {
      throw new IllegalArgumentException("newHash must not be blank");
    }
  }
}
