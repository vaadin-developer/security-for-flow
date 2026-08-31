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
 * Emitted when an API-key authentication was refused — unknown
 * key, expired, revoked, or in a foreign tenant.
 * <p>
 * {@code subjectId} can be empty when the key was unknown: there
 * is no subject to attribute the rejection to. Audit consumers
 * should pivot on {@link #reason()} rather than {@code subjectId}.
 *
 * @param timestamp UTC denial time; non-null
 * @param subjectId subject the key would have authenticated, or
 *                  empty when the key was unknown; may be empty
 * @param keyHash   hash of the rejected key; non-blank
 * @param reason    short denial reason ({@code "Unknown"},
 *                  {@code "Expired"}, {@code "Revoked"},
 *                  {@code "ForeignTenant"}); non-blank
 */
public record ApiKeyDenied(
    Instant timestamp,
    String subjectId,
    String keyHash,
    String reason
) implements AuditEvent {

  /** Validates the record components. */
  public ApiKeyDenied {
    requireNonNull(timestamp, "timestamp must not be null");
    subjectId = subjectId == null ? "" : subjectId;
    if (keyHash == null || keyHash.isBlank()) {
      throw new IllegalArgumentException("keyHash must not be blank");
    }
    if (reason == null || reason.isBlank()) {
      throw new IllegalArgumentException("reason must not be blank");
    }
  }
}
