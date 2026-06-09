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

import com.svenruppert.vaadin.security.authorization.api.ExperimentalJSentinelApi;

import static java.util.Objects.requireNonNull;

/**
 * Outcome of a {@code Policy} evaluation.
 * <p>
 * {@code PolicyDecision} is more expressive than
 * {@link com.svenruppert.vaadin.security.authorization.api.AuthorizationDecision}:
 * it distinguishes a hard deny from a step-up challenge (e.g. MFA / re-auth).
 * Adapters bridge it down to {@code AuthorizationDecision} via
 * {@link PolicyDecisions#toAuthorizationDecision(PolicyDecision)}.
 *
 * <p>Until adapter-side step-up routing ships, {@link StepUpRequired} is
 * mapped to {@code Forbidden} by the bridge. The variant is part of the
 * sealed hierarchy from day one so later step-up support is additive,
 * not a breaking change.
 */
@ExperimentalJSentinelApi
public sealed interface PolicyDecision
    permits PolicyDecision.Allowed,
            PolicyDecision.Denied,
            PolicyDecision.StepUpRequired {

  /**
   * Access is permitted.
   *
   * @param reason short, adapter-neutral diagnostic
   */
  record Allowed(String reason) implements PolicyDecision {
    public Allowed {
      reason = reason == null ? "" : reason;
    }
  }

  /**
   * Access is denied.
   *
   * @param reason short, adapter-neutral diagnostic
   */
  record Denied(String reason) implements PolicyDecision {
    public Denied {
      reason = reason == null ? "" : reason;
    }
  }

  /**
   * Subject is authenticated but a step-up challenge is required before
   * access can be granted.
   *
   * @param reason short, adapter-neutral diagnostic
   * @param method requested step-up mechanism
   */
  record StepUpRequired(String reason, StepUpMethod method) implements PolicyDecision {
    public StepUpRequired {
      reason = reason == null ? "" : reason;
      method = requireNonNull(method, "method must not be null");
    }
  }

  /**
   * Step-up mechanism a policy may ask for.
   */
  enum StepUpMethod {
    /** Multi-factor authentication (e.g. TOTP, WebAuthn). */
    MFA,
    /** Re-authentication with the primary credentials. */
    REAUTH
  }

  /**
   * Creates an {@link Allowed} decision.
   *
   * @param reason diagnostic
   * @return decision
   */
  static PolicyDecision allowed(String reason) {
    return new Allowed(reason);
  }

  /**
   * Creates a {@link Denied} decision.
   *
   * @param reason diagnostic
   * @return decision
   */
  static PolicyDecision denied(String reason) {
    return new Denied(reason);
  }

  /**
   * Creates a {@link StepUpRequired} decision.
   *
   * @param reason diagnostic
   * @param method requested step-up mechanism
   * @return decision
   */
  static PolicyDecision stepUpRequired(String reason, StepUpMethod method) {
    return new StepUpRequired(reason, method);
  }
}
