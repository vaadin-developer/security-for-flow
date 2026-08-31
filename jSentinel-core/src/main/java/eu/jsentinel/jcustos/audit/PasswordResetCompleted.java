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
package eu.jsentinel.jcustos.audit;

import java.time.Instant;

import static java.util.Objects.requireNonNull;

/**
 * Emitted when a password-reset token is consumed and the password
 * has been replaced.
 *
 * @param timestamp UTC consumption time; non-null
 * @param subjectId subject whose password was changed; non-blank
 * @param tokenHash hash of the consumed token; non-blank
 */
public record PasswordResetCompleted(
    Instant timestamp,
    String subjectId,
    String tokenHash
) implements AuditEvent {

  /** Validates the record components. */
  public PasswordResetCompleted {
    requireNonNull(timestamp, "timestamp must not be null");
    if (subjectId == null || subjectId.isBlank()) {
      throw new IllegalArgumentException("subjectId must not be blank");
    }
    if (tokenHash == null || tokenHash.isBlank()) {
      throw new IllegalArgumentException("tokenHash must not be blank");
    }
  }
}
