/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * http://ec.europa.eu/idabc/eupl5
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */
package com.svenruppert.jsentinel.credential.password.provider;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.ServiceLoader;
import java.util.Set;

/**
 * Lookup of {@link PasswordHashProvider}s by stored envelope metadata.
 *
 * <p>The registry resolves providers by the {@code providerId} that is
 * embedded in the envelope &mdash; <em>not</em> by the active policy.
 * That way a stored hash always finds the implementation that produced
 * it, regardless of policy churn (CWE-693).</p>
 *
 * <p>Construction takes a defensive copy. Duplicate {@code providerId}
 * values are rejected at construction time so that misconfiguration
 * surfaces fast (CWE-755).</p>
 */
public final class PasswordHashProviderRegistry {

  private final Map<String, PasswordHashProvider> byProviderId;

  public PasswordHashProviderRegistry(
      Collection<? extends PasswordHashProvider> providers) {
    Objects.requireNonNull(providers, "providers");
    Map<String, PasswordHashProvider> map = new LinkedHashMap<>();
    for (PasswordHashProvider p : providers) {
      Objects.requireNonNull(p, "provider");
      String id = Objects.requireNonNull(p.providerId(), "provider.providerId()");
      if (id.isBlank()) {
        throw new IllegalArgumentException("provider id must not be blank");
      }
      if (map.put(id, p) != null) {
        throw new IllegalArgumentException(
            "duplicate password hash provider id");
      }
    }
    this.byProviderId = Collections.unmodifiableMap(map);
  }

  /**
   * Resolves the provider associated with the given envelope metadata.
   *
   * @return the matching provider, or {@link Optional#empty()} when no
   *         provider with that {@code providerId} is registered, or
   *         the registered provider declines to {@code supports(...)}
   *         the requested algorithm
   */
  public Optional<PasswordHashProvider> resolve(
      String providerId, String algorithm) {
    Objects.requireNonNull(providerId, "providerId");
    Objects.requireNonNull(algorithm, "algorithm");
    PasswordHashProvider p = byProviderId.get(providerId);
    if (p == null) {
      return Optional.empty();
    }
    return p.supports(providerId, algorithm) ? Optional.of(p) : Optional.empty();
  }

  /**
   * Returns the provider identifiers known to this registry, in
   * registration order.
   */
  public Set<String> knownProviderIds() {
    return byProviderId.keySet();
  }

  /**
   * Returns the providers registered with this instance.
   */
  public Collection<PasswordHashProvider> providers() {
    return byProviderId.values();
  }

  /**
   * Builds a registry from every {@link PasswordHashProvider}
   * discovered through {@link ServiceLoader} on the current thread's
   * context class loader.
   *
   * <p>The global JCA provider order is not modified by this call.
   * Providers are only registered with this registry instance; the
   * caller decides where to hand the registry next.</p>
   */
  public static PasswordHashProviderRegistry fromServiceLoader() {
    List<PasswordHashProvider> discovered = new ArrayList<>();
    for (PasswordHashProvider p : ServiceLoader.load(PasswordHashProvider.class)) {
      discovered.add(p);
    }
    return new PasswordHashProviderRegistry(discovered);
  }
}
