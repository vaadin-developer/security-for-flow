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
package eu.jsentinel.jcustos.policy.api;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;
import eu.jsentinel.jcustos.authorization.api.JSentinelSubject;
import eu.jsentinel.jcustos.authorization.navigation.AccessContext;

import java.util.Map;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Input to a {@code Policy} evaluation.
 * <p>
 * Wraps the adapter-neutral {@link AccessContext} and adds:
 * <ul>
 *   <li>the resolved {@code policyName} (the value of the
 *       {@code @RequiresPolicy} annotation that caused this
 *       evaluation),</li>
 *   <li>an optional {@link ResourceRef} pointing at the concrete
 *       domain resource the request is about — used by
 *       {@link ResourcePredicates},</li>
 *   <li>a policy-specific {@code resourceAttributes} map that callers
 *       can populate with pre-resolved fields without polluting the
 *       shared {@code AccessContext.attributes} map.</li>
 * </ul>
 *
 * <p>Wrapping (rather than extending) keeps the existing
 * {@code AuthorizationEvaluator} contract and all adapter pipelines
 * unchanged: a {@code RequiresPolicyEvaluator} builds a
 * {@code PolicyContext} from the inbound {@code AccessContext} just
 * before calling into the {@code PolicyRegistry}.
 *
 * @param accessContext      underlying adapter-neutral access context
 * @param policyName         name of the policy being evaluated
 * @param resourceRef        reference to the concrete domain resource, if any
 * @param resourceAttributes policy-specific resource attributes
 */
@ExperimentalJSentinelApi
public record PolicyContext(
    AccessContext accessContext,
    String policyName,
    Optional<ResourceRef> resourceRef,
    Map<String, Object> resourceAttributes
) {

  /**
   * Creates a policy context with defensive copies.
   *
   * @param accessContext      underlying adapter-neutral access context
   * @param policyName         name of the policy being evaluated
   * @param resourceRef        reference to the concrete domain resource, if any
   * @param resourceAttributes policy-specific resource attributes
   */
  public PolicyContext {
    accessContext = requireNonNull(accessContext, "accessContext must not be null");
    if (policyName == null || policyName.isBlank()) {
      throw new IllegalArgumentException("policyName must not be blank");
    }
    resourceRef = resourceRef == null ? Optional.empty() : resourceRef;
    resourceAttributes = Map.copyOf(
        requireNonNull(resourceAttributes, "resourceAttributes must not be null"));
  }

  /**
   * Convenience constructor without a {@link ResourceRef}.
   *
   * @param accessContext      underlying adapter-neutral access context
   * @param policyName         name of the policy being evaluated
   * @param resourceAttributes policy-specific resource attributes
   */
  public PolicyContext(
      AccessContext accessContext,
      String policyName,
      Map<String, Object> resourceAttributes) {
    this(accessContext, policyName, Optional.empty(), resourceAttributes);
  }

  /**
   * Convenience constructor using an empty {@code resourceAttributes}
   * map and no {@link ResourceRef}.
   *
   * @param accessContext underlying adapter-neutral access context
   * @param policyName    name of the policy being evaluated
   */
  public PolicyContext(AccessContext accessContext, String policyName) {
    this(accessContext, policyName, Optional.empty(), Map.of());
  }

  /**
   * Convenience constructor with a {@link ResourceRef} and an empty
   * {@code resourceAttributes} map. Pass {@code null} for an absent
   * reference.
   *
   * @param accessContext underlying adapter-neutral access context
   * @param policyName    name of the policy being evaluated
   * @param resourceRef   reference to the concrete domain resource, or {@code null}
   */
  public PolicyContext(
      AccessContext accessContext,
      String policyName,
      ResourceRef resourceRef) {
    this(accessContext, policyName, Optional.ofNullable(resourceRef), Map.of());
  }

  /**
   * Shortcut to the authenticated subject of the wrapped access context.
   *
   * @return authenticated subject, if any
   */
  public Optional<JSentinelSubject> subject() {
    return accessContext.subject();
  }
}
