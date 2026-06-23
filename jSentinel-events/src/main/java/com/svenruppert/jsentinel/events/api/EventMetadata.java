package com.svenruppert.jsentinel.events.api;

/*-
 * #%L
 * jSentinel Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jSentinel by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * http://ec.europa.eu/idabc/eupl5
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import com.svenruppert.jsentinel.logout.SubjectId;

import java.time.Instant;
import java.util.Objects;

/**
 * The variable per-instance metadata shared by every {@link JSentinelEvent}.
 *
 * <p>The constant parts of an event — its {@link EventType} and
 * {@link JSentinelEventCategory} — are <em>not</em> part of the metadata;
 * they are declared by each concrete event type. The metadata holds only the
 * fields that differ between instances of the same type.
 *
 * @param eventId stable business identity
 * @param tenantId mandatory tenant context (never {@code null})
 * @param subjectId business or technical subject
 * @param occurredAt business timestamp
 * @param severity security-relevance level
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public record EventMetadata(
    EventId eventId,
    TenantId tenantId,
    SubjectId subjectId,
    Instant occurredAt,
    JSentinelEventSeverity severity
) {

  public EventMetadata {
    Objects.requireNonNull(eventId, "eventId");
    Objects.requireNonNull(tenantId, "tenantId");
    Objects.requireNonNull(subjectId, "subjectId");
    Objects.requireNonNull(occurredAt, "occurredAt");
    Objects.requireNonNull(severity, "severity");
  }

  /**
   * Convenience factory that assigns a fresh random {@link EventId}.
   *
   * @param tenantId mandatory tenant
   * @param subjectId subject (use {@link JSentinelEvent#SYSTEM_SUBJECT} for
   *     system events)
   * @param occurredAt business timestamp
   * @param severity security-relevance level
   * @return metadata with a generated event id
   */
  public static EventMetadata create(TenantId tenantId, SubjectId subjectId,
      Instant occurredAt, JSentinelEventSeverity severity) {
    return new EventMetadata(EventId.random(), tenantId, subjectId, occurredAt, severity);
  }
}
