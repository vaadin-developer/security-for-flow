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
package com.svenruppert.jsentinel.policy.api;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver;
import com.svenruppert.jsentinel.policy.spi.ResourceResolverRegistry;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Predicate;

import static java.util.Objects.requireNonNull;

/**
 * Predicate factories that branch on the {@link ResourceRef} carried
 * by a {@link PolicyContext}.
 *
 * <p>The predicates consult the
 * {@link ResourceResolverRegistry} resolved via
 * {@link JSentinelServiceResolver#resourceResolverRegistry()} to turn
 * the reference into a resolved attribute map. None of them throw on
 * missing references, missing resolvers, or unresolvable ids — they
 * return {@code false} so a policy denies gracefully.
 *
 * <p>For a predicate to match, the {@link PolicyContext#resourceRef()}
 * must
 * <ul>
 *   <li>be present,</li>
 *   <li>have a {@link ResourceRef#resourceType()} equal to the
 *       expected type, and</li>
 *   <li>resolve to attributes via the registry.</li>
 * </ul>
 */
@ExperimentalJSentinelApi
public final class ResourcePredicates {

  private ResourcePredicates() {
  }

  /**
   * Matches when the resolved resource has an {@code ownerAttribute}
   * value that equals the authenticated subject's
   * {@code subjectId}. Returns {@code false} when no subject is
   * present, when the {@link ResourceRef} is absent or of the wrong
   * type, when no resolver is registered, or when the resource cannot
   * be resolved.
   *
   * @param resourceType   non-blank resource type identifier
   * @param ownerAttribute non-blank attribute name carrying the owner id
   * @return predicate
   */
  public static Predicate<PolicyContext> ownerMatchesSubject(
      String resourceType, String ownerAttribute) {
    String type = requireNonBlank(resourceType, "resourceType");
    String attr = requireNonBlank(ownerAttribute, "ownerAttribute");
    return ctx -> ctx.subject()
        .flatMap(subject -> resolvedAttributes(ctx, type)
            .map(attrs -> Objects.equals(attrs.get(attr), subject.subjectId())))
        .orElse(false);
  }

  /**
   * Matches when the resolved resource's {@code attribute} value
   * equals {@code expected}. {@code expected == null} matches an
   * absent or null attribute.
   *
   * @param resourceType non-blank resource type identifier
   * @param attribute    non-blank attribute name
   * @param expected     expected value, may be {@code null}
   * @return predicate
   */
  public static Predicate<PolicyContext> resourceAttributeEquals(
      String resourceType, String attribute, Object expected) {
    String type = requireNonBlank(resourceType, "resourceType");
    String attr = requireNonBlank(attribute, "attribute");
    return ctx -> resolvedAttributes(ctx, type)
        .map(attrs -> Objects.equals(attrs.get(attr), expected))
        .orElse(false);
  }

  /**
   * Matches when the {@link PolicyContext} carries a
   * {@link ResourceRef} of the given resource type. Does not consult
   * the registry — useful for guarding rules that require the
   * presence of a resource without inspecting its fields.
   *
   * @param resourceType non-blank resource type identifier
   * @return predicate
   */
  public static Predicate<PolicyContext> hasResource(String resourceType) {
    String type = requireNonBlank(resourceType, "resourceType");
    return ctx -> ctx.resourceRef()
        .map(ref -> type.equals(ref.resourceType()))
        .orElse(false);
  }

  private static Optional<Map<String, Object>> resolvedAttributes(
      PolicyContext ctx, String expectedType) {
    Optional<ResourceRef> refOpt = ctx.resourceRef();
    if (refOpt.isEmpty()) {
      return Optional.empty();
    }
    ResourceRef ref = refOpt.get();
    if (!expectedType.equals(ref.resourceType())) {
      return Optional.empty();
    }
    return JSentinelServiceResolver.resourceResolverRegistry()
        .resolveAttributes(ref);
  }

  private static String requireNonBlank(String value, String name) {
    requireNonNull(value, name + " must not be null");
    if (value.isBlank()) {
      throw new IllegalArgumentException(name + " must not be blank");
    }
    return value;
  }
}
