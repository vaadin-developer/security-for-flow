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

import com.svenruppert.vaadin.security.authorization.api.ExperimentalSecurityApi;
import com.svenruppert.vaadin.security.authorization.api.SecuritySubject;
import com.svenruppert.vaadin.security.authorization.navigation.AccessContext;

import java.util.Map;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Input to a {@code Policy} evaluation.
 * <p>
 * Wraps the adapter-neutral {@link AccessContext} and adds the resolved
 * {@code policyName} plus any policy-specific {@code resourceAttributes}
 * a caller wants to expose to predicates without polluting the shared
 * {@code AccessContext.attributes} map.
 *
 * <p>Wrapping (rather than extending) keeps the existing
 * {@code AuthorizationEvaluator} contract and all adapter pipelines
 * unchanged: a {@code RequiresPolicyEvaluator} builds a
 * {@code PolicyContext} from the inbound {@code AccessContext} just
 * before calling into the {@code PolicyRegistry}.
 *
 * @param accessContext      underlying adapter-neutral access context
 * @param policyName         name of the policy being evaluated
 * @param resourceAttributes policy-specific resource attributes
 */
@ExperimentalSecurityApi
public record PolicyContext(
    AccessContext accessContext,
    String policyName,
    Map<String, Object> resourceAttributes
) {

  /**
   * Creates a policy context with defensive copies.
   *
   * @param accessContext      underlying adapter-neutral access context
   * @param policyName         name of the policy being evaluated
   * @param resourceAttributes policy-specific resource attributes
   */
  public PolicyContext {
    accessContext = requireNonNull(accessContext, "accessContext must not be null");
    if (policyName == null || policyName.isBlank()) {
      throw new IllegalArgumentException("policyName must not be blank");
    }
    resourceAttributes = Map.copyOf(
        requireNonNull(resourceAttributes, "resourceAttributes must not be null"));
  }

  /**
   * Convenience constructor using an empty {@code resourceAttributes} map.
   *
   * @param accessContext underlying adapter-neutral access context
   * @param policyName    name of the policy being evaluated
   */
  public PolicyContext(AccessContext accessContext, String policyName) {
    this(accessContext, policyName, Map.of());
  }

  /**
   * Shortcut to the authenticated subject of the wrapped access context.
   *
   * @return authenticated subject, if any
   */
  public Optional<SecuritySubject> subject() {
    return accessContext.subject();
  }
}
