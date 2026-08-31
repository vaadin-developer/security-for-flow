package eu.jsentinel.jcustos.events.publisher;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.events.api.EventId;
import eu.jsentinel.jcustos.events.api.EventType;
import eu.jsentinel.jcustos.events.api.JCustosEventSeverity;
import eu.jsentinel.jcustos.logout.SubjectId;

import java.time.Instant;
import java.util.Objects;

/**
 * A compact, secret-free alert derived from a security event that crossed the
 * {@link JCustosAlertPublisher}'s severity threshold. Carries only the
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
@ExperimentalJCustosApi
public record JCustosAlert(
    EventType eventType,
    JCustosEventSeverity severity,
    TenantId tenantId,
    SubjectId subjectId,
    EventId eventId,
    Instant occurredAt,
    String detail
) {

  public JCustosAlert {
    Objects.requireNonNull(eventType, "eventType");
    Objects.requireNonNull(severity, "severity");
    Objects.requireNonNull(tenantId, "tenantId");
    Objects.requireNonNull(subjectId, "subjectId");
    Objects.requireNonNull(eventId, "eventId");
    Objects.requireNonNull(occurredAt, "occurredAt");
    Objects.requireNonNull(detail, "detail");
  }
}
