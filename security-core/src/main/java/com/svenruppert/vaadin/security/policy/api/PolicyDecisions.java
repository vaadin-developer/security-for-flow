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
package com.svenruppert.vaadin.security.policy.api;

import com.svenruppert.vaadin.security.authorization.api.AuthorizationDecision;
import com.svenruppert.vaadin.security.authorization.api.ExperimentalSecurityApi;

import static java.util.Objects.requireNonNull;

/**
 * Bridge from the policy-specific {@link PolicyDecision} sealed hierarchy
 * down to the adapter-neutral {@link AuthorizationDecision} contract used
 * by the existing {@code AuthorizationEvaluator} pipeline.
 *
 * <p>Mapping:
 * <ul>
 *   <li>{@code Allowed}        → {@code Granted}</li>
 *   <li>{@code Denied}         → {@code Forbidden(reason)}</li>
 *   <li>{@code StepUpRequired} → {@code Forbidden("StepUpRequired:<method>" + extra)}</li>
 * </ul>
 *
 * <p>Until adapters learn to route a step-up challenge, the
 * {@code StepUpRequired} branch is collapsed to {@code Forbidden} with a
 * structured reason prefix. The prefix lets adapter-side mappers (or
 * later step-up adapters) recognise the case without breaking the sealed
 * API.
 */
@ExperimentalSecurityApi
public final class PolicyDecisions {

  /** Reason prefix used when a {@code StepUpRequired} is collapsed to {@code Forbidden}. */
  public static final String STEP_UP_REASON_PREFIX = "StepUpRequired:";

  private PolicyDecisions() {
  }

  /**
   * Bridges a {@link PolicyDecision} to an {@link AuthorizationDecision}.
   *
   * @param decision policy decision; must not be {@code null}
   * @return adapter-neutral authorization decision
   */
  public static AuthorizationDecision toAuthorizationDecision(PolicyDecision decision) {
    requireNonNull(decision, "decision must not be null");
    return switch (decision) {
      case PolicyDecision.Allowed ignored -> AuthorizationDecision.granted();
      case PolicyDecision.Denied denied -> AuthorizationDecision.forbidden(denied.reason());
      case PolicyDecision.StepUpRequired stepUp -> AuthorizationDecision.forbidden(
          STEP_UP_REASON_PREFIX + stepUp.method().name()
              + (stepUp.reason().isEmpty() ? "" : ":" + stepUp.reason()));
    };
  }
}
