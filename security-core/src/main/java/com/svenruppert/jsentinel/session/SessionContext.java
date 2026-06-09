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
package com.svenruppert.jsentinel.session;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;

/**
 * Adapter-neutral session view for the {@link SessionPolicy}.
 * <p>
 * The Vaadin and REST adapters build this record from their respective
 * runtime types ({@code VaadinSession}, HTTP session) so the policy stays
 * Vaadin-free and unit-testable.
 *
 * @param subject       the authenticated subject; may be {@code null} for
 *                      navigation events that occur before login
 * @param sessionId     stable session identifier; may be {@code null}
 * @param createdAt     when the session was first established
 * @param lastActivity  most recent activity within the session;
 *                      {@code null} when no activity has been recorded yet
 * @param clientAddress remote client address as observed by the adapter,
 *                      or {@code null}
 * @param attributes    free-form non-{@code null} attribute map
 *                      (defensive copy)
 * @param <U>           subject type
 */
public record SessionContext<U>(
    U subject,
    String sessionId,
    Instant createdAt,
    Instant lastActivity,
    String clientAddress,
    Map<String, Object> attributes
) {

  public SessionContext {
    Objects.requireNonNull(createdAt, "createdAt");
    attributes = attributes == null ? Map.of() : Map.copyOf(attributes);
  }
}
