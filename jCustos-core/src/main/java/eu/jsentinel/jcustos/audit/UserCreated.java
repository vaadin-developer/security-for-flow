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
import java.util.Objects;

/**
 * A new user account was added to the directory.
 *
 * @param timestamp UTC creation time, never {@code null}
 * @param username  username of the new account, never {@code null}
 * @param role      initial role label (e.g. {@code "ROLE_ADMIN"} or
 *                  {@code "USER"}). May be {@code null} if the directory
 *                  models users without an initial role.
 * @param createdBy subject id of the actor that triggered creation, or
 *                  {@code null} if anonymous / system
 */
public record UserCreated(
    Instant timestamp,
    String username,
    String role,
    String createdBy
) implements AuditEvent {

  public UserCreated {
    Objects.requireNonNull(timestamp, "timestamp");
    Objects.requireNonNull(username, "username");
  }
}
