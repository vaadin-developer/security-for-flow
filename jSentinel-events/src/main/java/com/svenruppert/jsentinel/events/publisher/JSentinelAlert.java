package com.svenruppert.jsentinel.events.publisher;

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
import com.svenruppert.jsentinel.events.api.EventId;
import com.svenruppert.jsentinel.events.api.EventType;
import com.svenruppert.jsentinel.events.api.JSentinelEventSeverity;
import com.svenruppert.jsentinel.logout.SubjectId;

import java.time.Instant;
import java.util.Objects;

/**
 * A compact, secret-free alert derived from a security event that crossed the
 * {@link JSentinelAlertPublisher}'s severity threshold. Carries only the
 * identifying event metadata plus a short reason — never the event payload.
 *
 * @param eventType the typed kind of the triggering event
 * @param severity the event's security-relevance level
 * @param tenantId the tenant context
 * @param subjectId the business or technical subject
 * @param eventId the triggering event's stable identity
 * @param occurredAt the business timestamp
 * @param detail short scrubbed reason (e.g. the event's simple class name),
 *     never payload content
 * @since 00.80.00
 */
@ExperimentalJSentinelApi
public record JSentinelAlert(
    EventType eventType,
    JSentinelEventSeverity severity,
    TenantId tenantId,
    SubjectId subjectId,
    EventId eventId,
    Instant occurredAt,
    String detail
) {

  public JSentinelAlert {
    Objects.requireNonNull(eventType, "eventType");
    Objects.requireNonNull(severity, "severity");
    Objects.requireNonNull(tenantId, "tenantId");
    Objects.requireNonNull(subjectId, "subjectId");
    Objects.requireNonNull(eventId, "eventId");
    Objects.requireNonNull(occurredAt, "occurredAt");
    Objects.requireNonNull(detail, "detail");
  }
}
