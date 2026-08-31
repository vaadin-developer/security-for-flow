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

import eu.jsentinel.jcustos.policy.impl.InMemoryResourceResolverRegistry;
import eu.jsentinel.jcustos.policy.spi.ResourceResolverRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JCustosServiceResolverResourceTest {

  @AfterEach
  void tearDown() {
    JCustosServiceResolver.resetAll();
  }

  @Test
  @DisplayName("resourceResolverRegistry() returns an InMemoryResourceResolverRegistry fallback when no SPI is registered")
  void fallbackReturnsInMemoryRegistry() {
    ResourceResolverRegistry registry = JCustosServiceResolver.resourceResolverRegistry();
    assertNotNull(registry);
    assertInstanceOf(InMemoryResourceResolverRegistry.class, registry);
  }

  @Test
  @DisplayName("resourceResolverRegistry() is cached: same instance on subsequent calls")
  void fallbackIsCached() {
    ResourceResolverRegistry first = JCustosServiceResolver.resourceResolverRegistry();
    ResourceResolverRegistry second = JCustosServiceResolver.resourceResolverRegistry();
    assertSame(first, second);
  }

  @Test
  @DisplayName("findResourceResolverRegistry() returns empty when only the fallback is in use")
  void findReturnsEmptyForFallback() {
    JCustosServiceResolver.resourceResolverRegistry(); // forces fallback caching
    assertTrue(JCustosServiceResolver.findResourceResolverRegistry().isEmpty());
  }

  @Test
  @DisplayName("setResourceResolverRegistry overrides the cached fallback")
  void setOverridesFallback() {
    JCustosServiceResolver.resourceResolverRegistry(); // cache fallback
    ResourceResolverRegistry custom = new InMemoryResourceResolverRegistry();
    JCustosServiceResolver.setResourceResolverRegistry(custom);
    assertSame(custom, JCustosServiceResolver.resourceResolverRegistry());
  }

  @Test
  @DisplayName("setResourceResolverRegistry(null) clears the cache, fallback returns again")
  void setNullClears() {
    ResourceResolverRegistry custom = new InMemoryResourceResolverRegistry();
    JCustosServiceResolver.setResourceResolverRegistry(custom);
    JCustosServiceResolver.setResourceResolverRegistry(null);

    ResourceResolverRegistry next = JCustosServiceResolver.resourceResolverRegistry();
    assertInstanceOf(InMemoryResourceResolverRegistry.class, next);
  }

  @Test
  @DisplayName("resetAll() clears the registry reference")
  void resetAllClearsRegistry() {
    ResourceResolverRegistry custom = new InMemoryResourceResolverRegistry();
    JCustosServiceResolver.setResourceResolverRegistry(custom);
    JCustosServiceResolver.resetAll();

    ResourceResolverRegistry next = JCustosServiceResolver.resourceResolverRegistry();
    assertInstanceOf(InMemoryResourceResolverRegistry.class, next);
    assertNotNull(next);
    assertSame(next, JCustosServiceResolver.resourceResolverRegistry());
  }
}
