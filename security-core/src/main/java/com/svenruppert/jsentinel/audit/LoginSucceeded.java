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
import java.util.Objects;

/**
 * Credentials were accepted and the subject is now authenticated.
 *
 * @param timestamp     UTC creation time, never {@code null}
 * @param username      authenticated username, never {@code null}
 * @param clientAddress remote client address, or {@code null} if unknown
 * @param sessionId     session identifier opened for the subject, or
 *                      {@code null} if no session abstraction applies
 */
public record LoginSucceeded(
    Instant timestamp,
    String username,
    String clientAddress,
    String sessionId
) implements AuditEvent {

  public LoginSucceeded {
    Objects.requireNonNull(timestamp, "timestamp");
    Objects.requireNonNull(username, "username");
  }
}
