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
import java.util.Objects;

/**
 * A role was assigned to a subject by an administrator action.
 *
 * @param timestamp  UTC creation time, never {@code null}
 * @param subjectId  subject receiving the role, never {@code null}
 * @param role       role name, never {@code null}
 * @param assignedBy subject id of the actor performing the assignment,
 *                   or {@code null} if anonymous / system
 */
public record RoleAssigned(
    Instant timestamp,
    String subjectId,
    String role,
    String assignedBy
) implements AuditEvent {

  public RoleAssigned {
    Objects.requireNonNull(timestamp, "timestamp");
    Objects.requireNonNull(subjectId, "subjectId");
    Objects.requireNonNull(role, "role");
  }
}
