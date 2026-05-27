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
import java.util.Set;

/**
 * Filter passed to {@code SecurityAuditService.query(...)}. All fields are
 * optional — a {@link #all()} query returns every retained event.
 * <p>
 * Filters compose with AND semantics: an event must match every non-empty
 * predicate to be included.
 *
 * @param types     restrict to these {@link AuditEvent} subtypes, or empty
 *                  to allow every type
 * @param subjectId restrict to events whose {@code subjectId} equals this
 *                  value, or {@code null} to ignore the subject
 * @param from      restrict to events with {@code timestamp} ≥ {@code from},
 *                  or {@code null} for no lower bound
 * @param to        restrict to events with {@code timestamp} ≤ {@code to},
 *                  or {@code null} for no upper bound
 * @param limit     maximum number of results, or {@code 0} for unlimited
 */
public record AuditQuery(
    Set<Class<? extends AuditEvent>> types,
    String subjectId,
    Instant from,
    Instant to,
    int limit
) {

  public AuditQuery {
    types = types == null ? Set.of() : Set.copyOf(types);
    if (limit < 0) {
      throw new IllegalArgumentException("limit must be >= 0");
    }
  }

  /** A query that returns every retained event. */
  public static AuditQuery all() {
    return new AuditQuery(Set.of(), null, null, null, 0);
  }

  /**
   * A query restricted to a single event type.
   *
   * @param type the {@link AuditEvent} subtype to filter on
   * @return query matching only events of {@code type}
   */
  public static AuditQuery ofType(Class<? extends AuditEvent> type) {
    return new AuditQuery(Set.of(type), null, null, null, 0);
  }

  /**
   * A query restricted to a single subject.
   *
   * @param subjectId the subject id to filter on
   * @return query matching only events carrying {@code subjectId}
   */
  public static AuditQuery forSubject(String subjectId) {
    return new AuditQuery(Set.of(), subjectId, null, null, 0);
  }

  /**
   * @param event the event to test against this query's predicates
   * @return {@code true} if the event matches every active predicate
   */
  public boolean matches(AuditEvent event) {
    if (!types.isEmpty() && !types.contains(event.getClass())) {
      return false;
    }
    if (subjectId != null) {
      String eventSubject = subjectIdOf(event);
      if (eventSubject == null || !eventSubject.equals(subjectId)) {
        return false;
      }
    }
    Instant ts = event.timestamp();
    if (from != null && ts.isBefore(from)) {
      return false;
    }
    if (to != null && ts.isAfter(to)) {
      return false;
    }
    return true;
  }

  private static String subjectIdOf(AuditEvent event) {
    return switch (event) {
      case AccessGranted e -> e.subjectId();
      case AccessDenied e -> e.subjectId();
      case ActionDenied e -> e.subjectId();
      case LogoutPerformed e -> e.subjectId();
      case SessionCreated e -> e.subjectId();
      case SessionExpired e -> e.subjectId();
      case SessionInvalidated e -> e.subjectId();
      case RoleAssigned e -> e.subjectId();
      case RoleRevoked e -> e.subjectId();
      case LoginSucceeded e -> e.username();
      case LoginFailed e -> e.username();
      case BruteForceLimitReached e -> e.username();
      case BootstrapAdminCreated e -> e.username();
      case UserCreated e -> e.username();
      case UserDeleted e -> e.username();
      case BootstrapTokenRejected ignored -> null;
      case PolicyEvaluated e -> e.subjectId();
      case StepUpChallenged e -> e.subjectId();
    };
  }
}
