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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import java.util.Objects;
import java.util.function.Predicate;

import static java.util.Objects.requireNonNull;

/**
 * Predicate factories that branch on fields of the wrapped
 * {@link eu.jsentinel.jcustos.authorization.navigation.AccessContext}
 * — the operation name, the resource type, and the adapter-provided
 * attribute map.
 *
 * <p>For predicates over the policy-specific resource attributes (see
 * {@link PolicyContext#resourceAttributes()}), use
 * {@link #resourceAttributeEquals(String, Object)}.
 */
@ExperimentalJCustosApi
public final class ContextPredicates {

  private ContextPredicates() {
  }

  /**
   * Matches when the wrapped access context's operation equals the
   * given value.
   *
   * @param operation non-blank operation identifier
   * @return predicate
   */
  public static Predicate<PolicyContext> operationEquals(String operation) {
    if (operation == null || operation.isBlank()) {
      throw new IllegalArgumentException("operation must not be blank");
    }
    return ctx -> operation.equals(ctx.accessContext().operation());
  }

  /**
   * Matches when the wrapped access context's resource type equals the
   * given value.
   *
   * @param resourceType non-blank resource type identifier
   * @return predicate
   */
  public static Predicate<PolicyContext> resourceTypeEquals(String resourceType) {
    if (resourceType == null || resourceType.isBlank()) {
      throw new IllegalArgumentException("resourceType must not be blank");
    }
    return ctx -> resourceType.equals(ctx.accessContext().resourceType());
  }

  /**
   * Matches when the wrapped access context's
   * {@code attributes} map contains {@code key} with the given value.
   *
   * @param key   non-blank attribute key
   * @param value expected value; may be {@code null}
   * @return predicate
   */
  public static Predicate<PolicyContext> attributeEquals(String key, Object value) {
    String k = requireNonBlank(key, "key");
    return ctx -> Objects.equals(value, ctx.accessContext().attributes().get(k));
  }

  /**
   * Matches when the {@link PolicyContext#resourceAttributes()} map
   * contains {@code key} with the given value.
   *
   * @param key   non-blank attribute key
   * @param value expected value; may be {@code null}
   * @return predicate
   */
  public static Predicate<PolicyContext> resourceAttributeEquals(String key, Object value) {
    String k = requireNonBlank(key, "key");
    return ctx -> Objects.equals(value, ctx.resourceAttributes().get(k));
  }

  private static String requireNonBlank(String value, String name) {
    requireNonNull(value, name + " must not be null");
    if (value.isBlank()) {
      throw new IllegalArgumentException(name + " must not be blank");
    }
    return value;
  }
}
