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
package com.svenruppert.vaadin.security.audit;

import java.time.Instant;

import static java.util.Objects.requireNonNull;

/**
 * Emitted when an API-key was successfully used to authenticate a
 * request — i.e. {@code ApiKeyAuthenticationService.authenticate}
 * returned an active record.
 *
 * @param timestamp UTC use time; non-null
 * @param subjectId subject the key authenticates; non-blank
 * @param keyName   human-readable label of the key; non-blank
 * @param keyHash   hash of the used key; non-blank
 */
public record ApiKeyUsed(
    Instant timestamp,
    String subjectId,
    String keyName,
    String keyHash
) implements AuditEvent {

  /** Validates the record components. */
  public ApiKeyUsed {
    requireNonNull(timestamp, "timestamp must not be null");
    if (subjectId == null || subjectId.isBlank()) {
      throw new IllegalArgumentException("subjectId must not be blank");
    }
    if (keyName == null || keyName.isBlank()) {
      throw new IllegalArgumentException("keyName must not be blank");
    }
    if (keyHash == null || keyHash.isBlank()) {
      throw new IllegalArgumentException("keyHash must not be blank");
    }
  }
}
