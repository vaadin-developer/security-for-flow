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
package eu.jsentinel.jcustos.session;

import java.time.Instant;
import java.util.Objects;

/**
 * Adapter-neutral query input for
 * {@link SessionPolicy#evaluate(SessionMetadata)}.
 * <p>
 * Compared to {@link SessionContext}, this record carries only the
 * three fields needed for the lifetime check: {@code subjectId},
 * {@code createdAt}, and {@code lastActivityAt}. The Vaadin and REST
 * adapters build it from their respective runtime types.
 *
 * @param subjectId      stable identifier of the authenticated subject;
 *                       non-{@code null}, non-blank
 * @param createdAt      when the session was first established
 * @param lastActivityAt most recent observed activity in the session
 */
public record SessionMetadata(
    String subjectId,
    Instant createdAt,
    Instant lastActivityAt
) {

  public SessionMetadata {
    Objects.requireNonNull(subjectId, "subjectId");
    if (subjectId.isBlank()) {
      throw new IllegalArgumentException("subjectId must not be blank");
    }
    Objects.requireNonNull(createdAt, "createdAt");
    Objects.requireNonNull(lastActivityAt, "lastActivityAt");
    if (lastActivityAt.isBefore(createdAt)) {
      throw new IllegalArgumentException(
          "lastActivityAt must be >= createdAt");
    }
  }
}
