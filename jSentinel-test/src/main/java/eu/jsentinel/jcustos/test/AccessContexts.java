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
package eu.jsentinel.jcustos.test;

import eu.jsentinel.jcustos.authorization.api.JSentinelSubject;
import eu.jsentinel.jcustos.authorization.navigation.AccessContext;
import eu.jsentinel.jcustos.policy.api.ResourceRef;

import java.util.Map;
import java.util.Optional;

/**
 * Static factories for typical {@link AccessContext} test fixtures.
 * Each factory pre-sets a reasonable adapter surface
 * ({@code resourceType="rest-endpoint"}, {@code resourceName="/x"},
 * {@code operation="read"}) so tests focus on the variant under test
 * (subject presence, resource reference, etc.) rather than ceremony.
 */
public final class AccessContexts {

  private AccessContexts() {
  }

  /** Default resourceType used by all factories. */
  public static final String DEFAULT_RESOURCE_TYPE = "rest-endpoint";

  /** Default resourceName used by all factories. */
  public static final String DEFAULT_RESOURCE_NAME = "/x";

  /** Default operation used by all factories. */
  public static final String DEFAULT_OPERATION = "read";

  /**
   * Anonymous context: no subject, default adapter fields, empty
   * attributes.
   *
   * @return access context
   */
  public static AccessContext anonymous() {
    return new AccessContext(
        Optional.empty(),
        DEFAULT_RESOURCE_TYPE, DEFAULT_RESOURCE_NAME, DEFAULT_OPERATION,
        Map.of());
  }

  /**
   * Context with the given subject; default adapter fields and empty
   * attributes.
   *
   * @param subject subject to bind
   * @return access context
   */
  public static AccessContext withSubject(JSentinelSubject subject) {
    return new AccessContext(
        Optional.of(subject),
        DEFAULT_RESOURCE_TYPE, DEFAULT_RESOURCE_NAME, DEFAULT_OPERATION,
        Map.of());
  }

  /**
   * Context with the given subject and a {@link ResourceRef} stashed
   * under {@link ResourceRef#ATTRIBUTE_KEY} so the
   * {@code RequiresPolicyEvaluator} promotes it into the
   * {@code PolicyContext}.
   *
   * @param subject subject to bind
   * @param ref     resource reference
   * @return access context
   */
  public static AccessContext withSubjectAndResource(
      JSentinelSubject subject, ResourceRef ref) {
    return new AccessContext(
        Optional.of(subject),
        DEFAULT_RESOURCE_TYPE, DEFAULT_RESOURCE_NAME, DEFAULT_OPERATION,
        Map.of(ResourceRef.ATTRIBUTE_KEY, ref));
  }

  /**
   * Anonymous context with a {@link ResourceRef} stashed under
   * {@link ResourceRef#ATTRIBUTE_KEY}.
   *
   * @param ref resource reference
   * @return access context
   */
  public static AccessContext anonymousWithResource(ResourceRef ref) {
    return new AccessContext(
        Optional.empty(),
        DEFAULT_RESOURCE_TYPE, DEFAULT_RESOURCE_NAME, DEFAULT_OPERATION,
        Map.of(ResourceRef.ATTRIBUTE_KEY, ref));
  }
}
