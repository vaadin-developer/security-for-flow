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

import java.time.Clock;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable structured security event.
 * <p>
 * Every field except {@code timestamp} and {@code type} is optional. A
 * {@link SecurityAuditService} implementation may persist or filter
 * events, but must not mutate the record.
 *
 * @param timestamp     when the event happened (UTC)
 * @param type          event category
 * @param subjectId     stable subject id, or {@code null} if unknown
 * @param username      human-readable subject name, or {@code null}
 * @param route         route / endpoint involved, or {@code null}
 * @param decision      one of {@code GRANTED / DENIED / ACCEPTED / REJECTED / ...},
 *                      or {@code null}
 * @param clientAddress remote client address, or {@code null}
 * @param sessionId     session identifier, or {@code null}
 * @param attributes    free-form non-{@code null} attribute map (defensive copy)
 */
public record SecurityAuditEvent(
    Instant timestamp,
    SecurityAuditEventType type,
    String subjectId,
    String username,
    String route,
    String decision,
    String clientAddress,
    String sessionId,
    Map<String, String> attributes
) {

  /** Defensive-copy constructor with null-coalescing for {@code attributes}. */
  public SecurityAuditEvent {
    Objects.requireNonNull(timestamp, "timestamp");
    Objects.requireNonNull(type, "type");
    attributes = attributes == null ? Map.of() : Map.copyOf(attributes);
  }

  /** Builder-style entry point. */
  public static Builder builder(SecurityAuditEventType type) {
    return new Builder(type);
  }

  /** Convenience: a minimal event of {@code type} with {@link Clock#systemUTC()} as the time source. */
  public static SecurityAuditEvent of(SecurityAuditEventType type) {
    return new SecurityAuditEvent(
        Instant.now(Clock.systemUTC()), type,
        null, null, null, null, null, null, Map.of());
  }

  /** Mutable builder — produces a single immutable {@link SecurityAuditEvent}. */
  public static final class Builder {

    private Clock clock = Clock.systemUTC();
    private final SecurityAuditEventType type;
    private String subjectId;
    private String username;
    private String route;
    private String decision;
    private String clientAddress;
    private String sessionId;
    private final Map<String, String> attributes = new LinkedHashMap<>();

    private Builder(SecurityAuditEventType type) {
      this.type = Objects.requireNonNull(type, "type");
    }

    public Builder clock(Clock clock) {
      this.clock = Objects.requireNonNull(clock);
      return this;
    }

    public Builder subjectId(String value) {
      this.subjectId = value;
      return this;
    }

    public Builder username(String value) {
      this.username = value;
      return this;
    }

    public Builder route(String value) {
      this.route = value;
      return this;
    }

    public Builder decision(String value) {
      this.decision = value;
      return this;
    }

    public Builder clientAddress(String value) {
      this.clientAddress = value;
      return this;
    }

    public Builder sessionId(String value) {
      this.sessionId = value;
      return this;
    }

    public Builder attribute(String key, String value) {
      Objects.requireNonNull(key, "key");
      if (value != null) {
        attributes.put(key, value);
      }
      return this;
    }

    public Builder attributes(Map<String, String> attrs) {
      if (attrs != null) {
        attrs.forEach(this::attribute);
      }
      return this;
    }

    public SecurityAuditEvent build() {
      return new SecurityAuditEvent(
          Instant.now(clock), type,
          subjectId, username, route, decision, clientAddress, sessionId,
          attributes);
    }
  }
}
