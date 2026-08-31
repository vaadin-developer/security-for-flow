package eu.jsentinel.jcustos.events.integration;

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

import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.LoginFailed;
import eu.jsentinel.jcustos.audit.LoginSucceeded;
import eu.jsentinel.jcustos.audit.AccessDenied;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.events.api.JCustosEvent;
import eu.jsentinel.jcustos.events.types.LoginFailedEvent;
import eu.jsentinel.jcustos.events.types.LoginSucceededEvent;
import eu.jsentinel.jcustos.events.types.PermissionDeniedEvent;

import java.util.Optional;

/**
 * Maps a bus {@link JCustosEvent} to the core {@link AuditEvent} model where a
 * direct counterpart exists (Konzept §1033). Audit is a separate <em>consumer</em>
 * of the bus — the bus does not hard-wire it (Konzept §30, §143).
 *
 * <p>Events without an audit counterpart map to {@link Optional#empty()} and are
 * skipped by the listener; the audit model can grow counterparts over time.
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public final class AuditEventMapper {

  private static final String UNKNOWN = "unknown";

  /**
   * @param event the bus event
   * @return the mapped audit event, if a counterpart exists
   */
  public Optional<AuditEvent> toAuditEvent(JCustosEvent event) {
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
