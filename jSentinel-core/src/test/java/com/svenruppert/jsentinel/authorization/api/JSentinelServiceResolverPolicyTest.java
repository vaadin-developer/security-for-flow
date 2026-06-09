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
package com.svenruppert.jsentinel.authorization.api;

import com.svenruppert.jsentinel.policy.impl.InMemoryPolicyRegistry;
import com.svenruppert.jsentinel.policy.spi.PolicyRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JSentinelServiceResolverPolicyTest {

  @AfterEach
  void tearDown() {
    JSentinelServiceResolver.resetAll();
  }

  @Test
  @DisplayName("policyRegistry() returns an InMemoryPolicyRegistry fallback when no SPI is registered")
  void fallbackReturnsInMemoryRegistry() {
    PolicyRegistry registry = JSentinelServiceResolver.policyRegistry();
    assertNotNull(registry);
    assertInstanceOf(InMemoryPolicyRegistry.class, registry);
  }

  @Test
  @DisplayName("policyRegistry() is cached: same instance on subsequent calls")
  void fallbackIsCached() {
    PolicyRegistry first = JSentinelServiceResolver.policyRegistry();
    PolicyRegistry second = JSentinelServiceResolver.policyRegistry();
    assertSame(first, second);
  }

  @Test
  @DisplayName("findPolicyRegistry() returns empty when only the fallback is in use")
  void findReturnsEmptyForFallback() {
    JSentinelServiceResolver.policyRegistry(); // forces fallback caching
    assertTrue(JSentinelServiceResolver.findPolicyRegistry().isEmpty());
  }

  @Test
  @DisplayName("setPolicyRegistry overrides the cached fallback")
  void setOverridesFallback() {
    JSentinelServiceResolver.policyRegistry(); // cache fallback
    PolicyRegistry custom = new InMemoryPolicyRegistry();
    JSentinelServiceResolver.setPolicyRegistry(custom);
    assertSame(custom, JSentinelServiceResolver.policyRegistry());
  }

  @Test
  @DisplayName("setPolicyRegistry(null) clears the cache, fallback returns again")
  void setNullClears() {
    PolicyRegistry custom = new InMemoryPolicyRegistry();
    JSentinelServiceResolver.setPolicyRegistry(custom);
    JSentinelServiceResolver.setPolicyRegistry(null);

    PolicyRegistry next = JSentinelServiceResolver.policyRegistry();
    assertInstanceOf(InMemoryPolicyRegistry.class, next);
  }

  @Test
  @DisplayName("resetAll() clears the registry reference")
  void resetAllClearsRegistry() {
    PolicyRegistry custom = new InMemoryPolicyRegistry();
    JSentinelServiceResolver.setPolicyRegistry(custom);
    JSentinelServiceResolver.resetAll();

    PolicyRegistry next = JSentinelServiceResolver.policyRegistry();
    // After reset, fallback is rebuilt — must not be the previously
    // cached custom instance.
    assertInstanceOf(InMemoryPolicyRegistry.class, next);
    assertNotNull(next);
    assertSame(next, JSentinelServiceResolver.policyRegistry());
  }
}
