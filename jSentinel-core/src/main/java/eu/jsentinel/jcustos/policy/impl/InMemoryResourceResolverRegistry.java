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
package eu.jsentinel.jcustos.policy.impl;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;
import eu.jsentinel.jcustos.policy.api.ResourceRef;
import eu.jsentinel.jcustos.policy.spi.ResourceResolver;
import eu.jsentinel.jcustos.policy.spi.ResourceResolverRegistry;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import static java.util.Objects.requireNonNull;

/**
 * Thread-safe in-memory {@link ResourceResolverRegistry} backed by a
 * {@link ConcurrentHashMap}. Resolvers are keyed by their
 * {@link ResourceResolver#resourceType()}; re-registering replaces
 * the previous entry.
 *
 * <p>This is the default implementation returned by
 * {@code JSentinelServiceResolver.resourceResolverRegistry()} when no
 * SPI override is registered. Applications register their domain
 * resolvers into the cached instance at startup.
 */
@ExperimentalJSentinelApi
public final class InMemoryResourceResolverRegistry implements ResourceResolverRegistry {

  private final ConcurrentMap<String, ResourceResolver<?>> resolvers = new ConcurrentHashMap<>();

  /** Creates an empty registry. */
  public InMemoryResourceResolverRegistry() {
  }

  @Override
  public void register(ResourceResolver<?> resolver) {
    requireNonNull(resolver, "resolver must not be null");
    String type = resolver.resourceType();
    if (type == null || type.isBlank()) {
      throw new IllegalArgumentException(
          "resolver.resourceType() must not be blank: " + resolver.getClass().getName());
    }
    resolvers.put(type, resolver);
  }

  @Override
  public Optional<ResourceResolver<?>> find(String resourceType) {
    if (resourceType == null) {
      return Optional.empty();
    }
    return Optional.ofNullable(resolvers.get(resourceType));
  }

  @Override
  public Optional<Map<String, Object>> resolveAttributes(ResourceRef ref) {
    requireNonNull(ref, "ref must not be null");
    ResourceResolver<?> resolver = resolvers.get(ref.resourceType());
    if (resolver == null) {
      return Optional.empty();
    }
    return resolveAttributesOf(resolver, ref.resourceId());
  }

  @SuppressWarnings({"rawtypes", "unchecked"})
  private static Optional<Map<String, Object>> resolveAttributesOf(
      ResourceResolver resolver, String id) {
    Optional<Object> resource = resolver.resolve(id);
    if (resource.isEmpty()) {
      return Optional.empty();
    }
    Map<String, Object> attributes = resolver.attributes(resource.get());
    if (attributes == null) {
      return Optional.of(Map.of());
    }
    return Optional.of(Map.copyOf(attributes));
  }
}
