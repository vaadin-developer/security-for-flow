/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.dx.internal;

import eu.jsentinel.jcustos.policy.api.Policy;
import eu.jsentinel.jcustos.policy.spi.PolicyRegistry;
import eu.jsentinel.jcustos.policy.spi.ResourceResolver;
import eu.jsentinel.jcustos.policy.spi.ResourceResolverRegistry;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Sub-aggregate of {@link BootstrapState} for policy configuration
 * (Konzept §8). Holds the in-order list of policies / resolvers and
 * the optional registry overrides.
 *
 * <p>{@link #knownPolicyNames()} is exposed for the
 * {@code SecureRouteDiscovery} cross-validation introduced in
 * Konzept §8.5 (Prompt 012).
 *
 * @since 00.73.00
 */
public final class PolicyState {

  private final List<Policy> policies = new ArrayList<>();
  private final List<ResourceResolver<?>> resolvers = new ArrayList<>();
  private PolicyRegistry registry;
  private ResourceResolverRegistry resourceRegistry;

  public List<Policy> policies() {
    return List.copyOf(policies);
  }

  public void addPolicy(Policy policy) {
    policies.add(policy);
  }

  public List<ResourceResolver<?>> resolvers() {
    return List.copyOf(resolvers);
  }

  public void addResolver(ResourceResolver<?> resolver) {
    resolvers.add(resolver);
  }

  public PolicyRegistry registry() {
    return registry;
  }

  public void registry(PolicyRegistry external) {
    this.registry = external;
  }

  public ResourceResolverRegistry resourceRegistry() {
    return resourceRegistry;
  }

  public void resourceRegistry(ResourceResolverRegistry external) {
    this.resourceRegistry = external;
  }

  /**
   * @return the set of registered policy names, for cross-validation
   *         with {@code @SecureRoute(policy="x")} annotations
   *         (Konzept §8.5, Prompt 012)
   */
  public Set<String> knownPolicyNames() {
    Set<String> names = new LinkedHashSet<>();
    for (Policy p : policies) {
      names.add(p.name());
    }
    return names;
  }

  public boolean hasAnySelection() {
    return !policies.isEmpty() || !resolvers.isEmpty()
        || registry != null || resourceRegistry != null;
  }
}
