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
package com.svenruppert.vaadin.security.policy.impl;

import com.svenruppert.vaadin.security.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.vaadin.security.policy.api.Policy;
import com.svenruppert.vaadin.security.policy.api.PolicyContext;
import com.svenruppert.vaadin.security.policy.api.PolicyDecision;
import com.svenruppert.vaadin.security.policy.spi.PolicyRegistry;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import static java.util.Objects.requireNonNull;

/**
 * Thread-safe in-memory {@link PolicyRegistry}.
 * <p>
 * Re-registering a policy with the same name replaces the previous
 * entry. Concurrent reads and registrations are safe because the
 * backing map is a {@link ConcurrentHashMap}.
 *
 * <p>This is the default implementation returned by
 * {@code JSentinelServiceResolver.policyRegistry()} when no SPI override
 * is registered.
 */
@ExperimentalJSentinelApi
public final class InMemoryPolicyRegistry implements PolicyRegistry {

  private final ConcurrentMap<String, Policy> policies = new ConcurrentHashMap<>();

  /** Creates an empty registry. */
  public InMemoryPolicyRegistry() {
  }

  @Override
  public void register(Policy policy) {
    requireNonNull(policy, "policy must not be null");
    policies.put(policy.name(), policy);
  }

  @Override
  public Optional<Policy> find(String name) {
    if (name == null) {
      return Optional.empty();
    }
    return Optional.ofNullable(policies.get(name));
  }

  @Override
  public PolicyDecision evaluate(String name, PolicyContext context) {
    requireNonNull(context, "context must not be null");
    if (name == null || name.isBlank()) {
      return PolicyDecision.denied("unknown policy: <blank>");
    }
    Policy policy = policies.get(name);
    if (policy == null) {
      return PolicyDecision.denied("unknown policy: " + name);
    }
    return policy.evaluate(context);
  }
}
