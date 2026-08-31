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
 * Lookup of {@link ResourceResolver}s by resource type and one-shot
 * {@link #resolveAttributes(ResourceRef)} pipeline for policy
 * predicates.
 * <p>
 * Discovered via {@code java.util.ServiceLoader}; consuming
 * applications register a default implementation in
 * {@code META-INF/services/eu.jsentinel.jcustos.policy.spi.ResourceResolverRegistry}.
 * If no implementation is registered, the {@code JCustosServiceResolver}
 * supplies an in-memory default into which individual
 * {@link ResourceResolver}s are registered programmatically at
 * startup.
 *
 * <p>Implementations should be thread-safe: resolver registration
 * typically happens at startup, resolution runs on every protected
 * access.
 */
@ExperimentalJCustosApi
public interface ResourceResolverRegistry {

  /**
   * Registers a resolver. Duplicate {@link ResourceResolver#resourceType()}
   * registrations replace the previous entry.
   *
   * @param resolver non-{@code null} resolver
   */
  void register(ResourceResolver<?> resolver);

  /**
   * Looks up a resolver by resource type.
   *
   * @param resourceType non-blank resource type
   * @return resolver, or empty if none is registered
   */
  Optional<ResourceResolver<?>> find(String resourceType);

  /**
   * Resolves the given reference and returns the resolver's attribute
   * map. Returns empty when no resolver is registered for the
   * resource type, or when the resolver itself returns empty for the
   * id. Never throws on unknown types or ids — policies treat the
   * absence of attributes as a graceful deny.
   *
   * @param ref non-{@code null} reference
   * @return attribute map, or empty
   */
  Optional<Map<String, Object>> resolveAttributes(ResourceRef ref);
}
