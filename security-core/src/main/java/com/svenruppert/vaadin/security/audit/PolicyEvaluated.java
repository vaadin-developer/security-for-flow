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
import java.util.Objects;

/**
 * A named {@code Policy} was evaluated against a {@code PolicyContext}.
 * <p>
 * Emitted by {@code RequiresPolicyEvaluator} (or any code that runs the
 * registry directly) <em>in addition to</em> the access-level
 * {@link AccessGranted} / {@link AccessDenied} events from the adapter
 * pipelines. {@code PolicyEvaluated} carries the policy name plus a
 * coarse decision label so consumers can build per-policy dashboards
 * without re-implementing the decision mapping.
 *
 * @param timestamp UTC creation time, never {@code null}
 * @param subjectId subject identifier, or {@code null} for anonymous
 * @param policyName non-null policy name
 * @param decision   coarse label: {@code "Allowed"}, {@code "Denied"},
 *                   or {@code "StepUpRequired"}
 * @param reason     adapter-neutral diagnostic reason, possibly empty
 */
public record PolicyEvaluated(
    Instant timestamp,
    String subjectId,
    String policyName,
    String decision,
    String reason
) implements AuditEvent {

  public PolicyEvaluated {
    Objects.requireNonNull(timestamp, "timestamp");
    Objects.requireNonNull(policyName, "policyName");
    Objects.requireNonNull(decision, "decision");
    reason = reason == null ? "" : reason;
  }
}
