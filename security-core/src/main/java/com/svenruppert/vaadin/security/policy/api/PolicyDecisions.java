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
 *   <li>{@code PolicyDecision.Allowed}        → {@code AuthorizationDecision.Granted}</li>
 *   <li>{@code PolicyDecision.Denied}         → {@code AuthorizationDecision.Forbidden(reason)}</li>
 *   <li>{@code PolicyDecision.StepUpRequired} → {@code AuthorizationDecision.StepUpRequired(reason, method)}</li>
 * </ul>
 *
 * <p>Before PR-9a the bridge collapsed {@code StepUpRequired} to
 * {@code Forbidden} with a {@link #STEP_UP_REASON_PREFIX}-prefixed
 * reason. Adapters that still rely on parsing that prefix can use the
 * constant; new adapter code should switch on the typed
 * {@link AuthorizationDecision.StepUpRequired} variant directly.
 */
@ExperimentalSecurityApi
public final class PolicyDecisions {

  /**
   * Legacy reason prefix used when a {@code StepUpRequired} was
   * collapsed to {@code Forbidden}. No longer produced by the bridge
   * since PR-9 (the bridge now returns
   * {@link AuthorizationDecision.StepUpRequired} directly). Retained
   * for downstream code that still parses the reason string.
   *
   * @deprecated since PR-9 — switch on
   *             {@link AuthorizationDecision.StepUpRequired} instead
   *             of parsing the {@code Forbidden} reason string.
   */
  @Deprecated(since = "00.70.00")
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
      case PolicyDecision.StepUpRequired stepUp ->
          AuthorizationDecision.stepUpRequired(stepUp.reason(), stepUp.method().name());
    };
  }
}
