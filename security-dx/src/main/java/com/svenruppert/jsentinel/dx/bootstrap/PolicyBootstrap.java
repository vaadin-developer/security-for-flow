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
package com.svenruppert.jsentinel.dx.bootstrap;

import com.svenruppert.jsentinel.policy.api.Policy;
import com.svenruppert.jsentinel.policy.spi.PolicyRegistry;
import com.svenruppert.jsentinel.policy.spi.ResourceResolver;
import com.svenruppert.jsentinel.policy.spi.ResourceResolverRegistry;

/**
 * Policy sub-builder of the fluent bootstrap.
 *
 * <p><strong>V00.73 status:</strong> typed surface (Konzept §8).
 * Replaces the V00.72 untyped {@code register(Object)} placeholder.
 *
 * <ul>
 *   <li>{@link #register(Policy)} — adds a policy to whatever
 *       registry is active (custom via {@link #registry(PolicyRegistry)}
 *       or the default {@code JSentinelServiceResolver.policyRegistry()}).</li>
 *   <li>{@link #resourceResolver(ResourceResolver)} — adds a resource
 *       resolver to whatever registry is active.</li>
 *   <li>{@link #registry(PolicyRegistry)} — replaces the active
 *       policy registry via
 *       {@code JSentinelServiceResolver.setPolicyRegistry(...)}.</li>
 *   <li>{@link #resourceRegistry(ResourceResolverRegistry)} — same
 *       for resource resolvers.</li>
 * </ul>
 *
 * @since 00.72.00
 */
public interface PolicyBootstrap {

  PolicyBootstrap register(Policy policy);

  PolicyBootstrap resourceResolver(ResourceResolver<?> resolver);

  PolicyBootstrap registry(PolicyRegistry external);

  PolicyBootstrap resourceRegistry(ResourceResolverRegistry external);
}
