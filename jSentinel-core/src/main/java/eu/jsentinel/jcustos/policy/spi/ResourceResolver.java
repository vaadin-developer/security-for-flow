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
package eu.jsentinel.jcustos.policy.spi;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.policy.api.ResourceRef;

import java.util.Map;
import java.util.Optional;

/**
 * Application-provided adapter that materialises a
 * {@link ResourceRef} into a domain object and exposes the attributes
 * a policy might want to reason about (owner id, status, …).
 * <p>
 * Each resolver covers a single {@link #resourceType() resource type}.
 * The application registers all its resolvers with a
 * {@link ResourceResolverRegistry} at startup — typically inside a
 * {@code VaadinServiceInitListener} or equivalent bootstrap hook —
 * after which {@code ResourcePredicates} can consult the registry
 * from inside a policy evaluation.
 *
 * @param <T> the domain type for this resolver
 */
@ExperimentalJCustosApi
public interface ResourceResolver<T> {

  /**
   * Stable, non-blank resource type identifier (e.g. {@code "document"}).
   * Must match the {@link ResourceRef#resourceType()} of every reference
   * this resolver should handle.
   *
   * @return resource type
   */
  String resourceType();

  /**
   * Loads the domain object for the given resource id, or returns empty
   * if no such resource exists. Resolvers <strong>should not throw</strong>
   * for unknown ids — return {@code Optional.empty()} so policies can
   * deny gracefully.
   *
   * @param id resource id; never {@code null} or blank
   * @return domain object, or empty
   */
  Optional<T> resolve(String id);

  /**
   * Extracts the predicate-relevant attributes of a resolved resource
   * (e.g. {@code ownerId}, {@code status}). The returned map is
   * read-only — callers must not mutate it. Implementations should
   * include only fields that are safe to expose to policy code.
   *
   * @param resource non-{@code null} resolved domain object
   * @return read-only attribute map
   */
  Map<String, Object> attributes(T resource);
}
