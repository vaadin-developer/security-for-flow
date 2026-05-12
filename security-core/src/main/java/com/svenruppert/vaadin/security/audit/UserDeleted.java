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
 * A user account was removed from the directory.
 *
 * @param timestamp UTC creation time, never {@code null}
 * @param username  username of the removed account, never {@code null}
 * @param deletedBy subject id of the actor that triggered deletion, or
 *                  {@code null} if anonymous / system
 */
public record UserDeleted(
    Instant timestamp,
    String username,
    String deletedBy
) implements AuditEvent {

  public UserDeleted {
    Objects.requireNonNull(timestamp, "timestamp");
    Objects.requireNonNull(username, "username");
  }
}
