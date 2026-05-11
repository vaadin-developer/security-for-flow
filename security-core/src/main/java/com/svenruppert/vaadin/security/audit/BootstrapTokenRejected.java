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
 * A bootstrap-token submission was rejected. Causes include unknown
 * tokens, expired tokens, already-used tokens, and malformed tokens.
 *
 * @param timestamp     UTC creation time, never {@code null}
 * @param reason        short reason key (e.g. {@code "Unknown"},
 *                      {@code "Expired"}, {@code "AlreadyUsed"},
 *                      {@code "Malformed"}), never {@code null}
 * @param clientAddress remote client address that submitted the token,
 *                      or {@code null}
 */
public record BootstrapTokenRejected(
    Instant timestamp,
    String reason,
    String clientAddress
) implements AuditEvent {

  public BootstrapTokenRejected {
    Objects.requireNonNull(timestamp, "timestamp");
    Objects.requireNonNull(reason, "reason");
  }
}
