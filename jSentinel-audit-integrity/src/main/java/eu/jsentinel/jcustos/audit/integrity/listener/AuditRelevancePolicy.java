package eu.jsentinel.jcustos.audit.integrity.listener;

/*-
 * #%L
 * jSentinel Audit Integrity — tamper-evident audit
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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;
import eu.jsentinel.jcustos.events.api.JSentinelEvent;
import eu.jsentinel.jcustos.events.api.JSentinelEventCategory;
import eu.jsentinel.jcustos.events.api.JSentinelEventSeverity;

import java.util.Objects;
import java.util.Set;

/**
 * Decides which bus events are worth a link in the forensic hash chain.
 * Configurable with a sensible default: {@link #auditRelevantDefaults()}
 * chains every warning-or-worse event plus all authentication,
 * authorization, admin and integrity events regardless of severity —
 * DEBUG/INFO system noise (bus lifecycle, telemetry) stays out of the
 * chain by default.
 *
 * @since 00.80.00
 */
@ExperimentalJSentinelApi
@FunctionalInterface
public interface AuditRelevancePolicy {

  /**
   * @param event the published event
   * @return {@code true} when the event should be chained
   */
  boolean isAuditRelevant(JSentinelEvent event);

  /** @return a policy chaining every event */
  static AuditRelevancePolicy all() {
    return event -> true;
  }

  /**
   * @param minimum the inclusive severity floor
   * @return a policy chaining events at or above {@code minimum}
   */
  static AuditRelevancePolicy severityAtLeast(JSentinelEventSeverity minimum) {
    Objects.requireNonNull(minimum, "minimum");
    return event -> event.severity().compareTo(minimum) >= 0;
  }

  /**
   * @param categories the chained categories
   * @return a policy chaining events of any of the given categories
   */
  static AuditRelevancePolicy categories(JSentinelEventCategory... categories) {
    Set<JSentinelEventCategory> chained = Set.of(categories);
    return event -> chained.contains(event.category());
  }

  /**
   * @return the documented default: severity at least
   *     {@link JSentinelEventSeverity#NOTICE}, or any authentication /
   *     authorization / admin / integrity event
   */
  static AuditRelevancePolicy auditRelevantDefaults() {
    return severityAtLeast(JSentinelEventSeverity.NOTICE)
        .or(categories(JSentinelEventCategory.AUTHENTICATION,
            JSentinelEventCategory.AUTHORIZATION,
            JSentinelEventCategory.ADMIN,
            JSentinelEventCategory.INTEGRITY));
  }

  /**
   * @param other the alternative policy
   * @return a policy chaining events either policy accepts
   */
  default AuditRelevancePolicy or(AuditRelevancePolicy other) {
    Objects.requireNonNull(other, "other");
    return event -> isAuditRelevant(event) || other.isAuditRelevant(event);
  }
}
