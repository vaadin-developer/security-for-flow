package com.svenruppert.jsentinel.events.integration;

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

import com.svenruppert.jsentinel.audit.AuditEvent;
import com.svenruppert.jsentinel.audit.LoginFailed;
import com.svenruppert.jsentinel.audit.LoginSucceeded;
import com.svenruppert.jsentinel.audit.AccessDenied;
import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.events.api.JSentinelEvent;
import com.svenruppert.jsentinel.events.types.LoginFailedEvent;
import com.svenruppert.jsentinel.events.types.LoginSucceededEvent;
import com.svenruppert.jsentinel.events.types.PermissionDeniedEvent;

import java.util.Optional;

/**
 * Maps a bus {@link JSentinelEvent} to the core {@link AuditEvent} model where a
 * direct counterpart exists (Konzept §1033). Audit is a separate <em>consumer</em>
 * of the bus — the bus does not hard-wire it (Konzept §30, §143).
 *
 * <p>Events without an audit counterpart map to {@link Optional#empty()} and are
 * skipped by the listener; the audit model can grow counterparts over time.
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public final class AuditEventMapper {

  private static final String UNKNOWN = "unknown";

  /**
   * @param event the bus event
   * @return the mapped audit event, if a counterpart exists
   */
  public Optional<AuditEvent> toAuditEvent(JSentinelEvent event) {
    return switch (event) {
      case LoginSucceededEvent e -> Optional.of(new LoginSucceeded(
          e.occurredAt(), e.subjectId().value(), UNKNOWN, UNKNOWN));
      case LoginFailedEvent e -> Optional.of(new LoginFailed(
          e.occurredAt(), e.subjectId().value(), UNKNOWN, e.failureCode()));
      case PermissionDeniedEvent e -> Optional.of(new AccessDenied(
          e.occurredAt(), e.subjectId().value(), e.permission(), "permission-denied"));
      default -> Optional.empty();
    };
  }
}
