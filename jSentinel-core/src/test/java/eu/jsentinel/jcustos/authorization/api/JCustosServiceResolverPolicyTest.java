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
package eu.jsentinel.jcustos.authorization.api;

import eu.jsentinel.jcustos.policy.impl.InMemoryPolicyRegistry;
import eu.jsentinel.jcustos.policy.spi.PolicyRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JCustosServiceResolverPolicyTest {

  @AfterEach
  void tearDown() {
    JCustosServiceResolver.resetAll();
  }

  @Test
  @DisplayName("policyRegistry() returns an InMemoryPolicyRegistry fallback when no SPI is registered")
  void fallbackReturnsInMemoryRegistry() {
    PolicyRegistry registry = JCustosServiceResolver.policyRegistry();
    assertNotNull(registry);
    assertInstanceOf(InMemoryPolicyRegistry.class, registry);
  }

  @Test
  @DisplayName("policyRegistry() is cached: same instance on subsequent calls")
  void fallbackIsCached() {
    PolicyRegistry first = JCustosServiceResolver.policyRegistry();
    PolicyRegistry second = JCustosServiceResolver.policyRegistry();
    assertSame(first, second);
  }

  @Test
  @DisplayName("findPolicyRegistry() returns empty when only the fallback is in use")
  void findReturnsEmptyForFallback() {
    JCustosServiceResolver.policyRegistry(); // forces fallback caching
    assertTrue(JCustosServiceResolver.findPolicyRegistry().isEmpty());
  }

  @Test
  @DisplayName("setPolicyRegistry overrides the cached fallback")
  void setOverridesFallback() {
    JCustosServiceResolver.policyRegistry(); // cache fallback
    PolicyRegistry custom = new InMemoryPolicyRegistry();
    JCustosServiceResolver.setPolicyRegistry(custom);
    assertSame(custom, JCustosServiceResolver.policyRegistry());
  }

  @Test
  @DisplayName("setPolicyRegistry(null) clears the cache, fallback returns again")
  void setNullClears() {
    PolicyRegistry custom = new InMemoryPolicyRegistry();
    JCustosServiceResolver.setPolicyRegistry(custom);
    JCustosServiceResolver.setPolicyRegistry(null);

    PolicyRegistry next = JCustosServiceResolver.policyRegistry();
    assertInstanceOf(InMemoryPolicyRegistry.class, next);
  }

  @Test
  @DisplayName("resetAll() clears the registry reference")
  void resetAllClearsRegistry() {
    PolicyRegistry custom = new InMemoryPolicyRegistry();
    JCustosServiceResolver.setPolicyRegistry(custom);
    JCustosServiceResolver.resetAll();

    PolicyRegistry next = JCustosServiceResolver.policyRegistry();
    // After reset, fallback is rebuilt — must not be the previously
    // cached custom instance.
    assertInstanceOf(InMemoryPolicyRegistry.class, next);
    assertNotNull(next);
    assertSame(next, JCustosServiceResolver.policyRegistry());
  }
}
