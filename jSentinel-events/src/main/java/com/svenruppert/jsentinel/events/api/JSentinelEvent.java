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

/**
 * A typed, security-relevant event in the jSentinel Security Event Bus.
 *
 * <p>Security events are first-class Java objects, not free-form maps or
 * unstructured log text (Konzept §156). The interface is deliberately
 * <em>not</em> sealed: applications may define their own event types in
 * addition to the ~30 framework events shipped in V00.75.
 *
 * <p>Every event carries a mandatory {@link #tenantId()} — system-wide
 * events use a defined tenant value such as {@link TenantId#DEFAULT}, never
 * {@code null} (Konzept §176). Events without an authenticated user use a
 * technical subject such as {@link #SYSTEM_SUBJECT}.
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public interface JSentinelEvent {

  /**
   * Technical subject for events that occur without an authenticated user
   * (e.g. bus lifecycle, scheduled jobs).
   */
  SubjectId SYSTEM_SUBJECT = SubjectId.of("system");

  /**
   * The variable per-instance metadata (event id, tenant, subject, timestamp,
   * severity). Concrete events compose an {@link EventMetadata} and let the
   * default accessors below delegate to it, so each event only has to declare
   * its constant {@link #eventType()} and {@link #category()}.
   *
   * @return the non-null metadata
   */
  EventMetadata metadata();

  /**
   * Typed kind of this event, used by the producer policy and for wire
   * routing. Constant per concrete event type.
   *
   * @return the non-null event type
   */
  EventType eventType();

  /**
   * Coarse security-domain classification. Constant per concrete event type.
   *
   * @return the non-null category
   */
  JSentinelEventCategory category();

  /**
   * Business identity of this event, stable across re-encoding and
   * re-delivery.
   *
   * @return the non-null event id
   */
  default EventId eventId() {
    return metadata().eventId();
  }

  /**
   * Mandatory tenant context. Never {@code null}.
   *
   * @return the non-null tenant id
   */
  default TenantId tenantId() {
    return metadata().tenantId();
  }

  /**
   * Business or technical subject this event is about.
   *
   * @return the non-null subject id
   */
  default SubjectId subjectId() {
    return metadata().subjectId();
  }

  /**
   * Business timestamp at which the underlying occurrence happened.
   *
   * @return the non-null instant
   */
  default Instant occurredAt() {
    return metadata().occurredAt();
  }

  /**
   * Security-relevance level for monitoring and alerting.
   *
   * @return the non-null severity
   */
  default JSentinelEventSeverity severity() {
    return metadata().severity();
  }
}
