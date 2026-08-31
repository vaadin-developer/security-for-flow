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

import eu.jsentinel.jcustos.authorization.api.roles.NoopRoleHierarchy;
import eu.jsentinel.jcustos.authorization.api.roles.RoleHierarchy;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.authorization.api.roles.StaticRoleHierarchy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JCustosServiceResolverRoleHierarchyTest {

  @AfterEach
  void tearDown() {
    JCustosServiceResolver.resetAll();
  }

  @Test
  @DisplayName("roleHierarchy() returns NoopRoleHierarchy.INSTANCE as the fallback")
  void fallbackIsNoopInstance() {
    RoleHierarchy hierarchy = JCustosServiceResolver.roleHierarchy();
    assertNotNull(hierarchy);
    assertSame(NoopRoleHierarchy.INSTANCE, hierarchy);
  }

  @Test
  @DisplayName("findRoleHierarchy() returns empty when only the fallback is in use")
  void findReturnsEmptyForFallback() {
    JCustosServiceResolver.roleHierarchy(); // forces fallback caching
    assertTrue(JCustosServiceResolver.findRoleHierarchy().isEmpty());
  }

  @Test
  @DisplayName("setRoleHierarchy overrides the cached fallback")
  void setOverridesFallback() {
    JCustosServiceResolver.roleHierarchy(); // cache fallback
    RoleHierarchy custom = StaticRoleHierarchy.builder()
        .role(new RoleName("ROLE_ADMIN")).inheritsFrom(new RoleName("ROLE_EDITOR"))
        .build();
    JCustosServiceResolver.setRoleHierarchy(custom);
    assertSame(custom, JCustosServiceResolver.roleHierarchy());
    assertTrue(JCustosServiceResolver.findRoleHierarchy().isPresent());
  }

  @Test
  @DisplayName("setRoleHierarchy(null) clears the cache, Noop returns again")
  void setNullClears() {
    JCustosServiceResolver.setRoleHierarchy(
        StaticRoleHierarchy.builder()
            .role(new RoleName("ROLE_ADMIN")).inheritsFrom(new RoleName("ROLE_EDITOR"))
            .build());
    JCustosServiceResolver.setRoleHierarchy(null);
    assertSame(NoopRoleHierarchy.INSTANCE, JCustosServiceResolver.roleHierarchy());
  }

  @Test
  @DisplayName("resetAll() clears the hierarchy reference")
  void resetAllClearsHierarchy() {
    RoleHierarchy custom = StaticRoleHierarchy.builder()
        .role(new RoleName("ROLE_ADMIN")).inheritsFrom(new RoleName("ROLE_EDITOR"))
        .build();
    JCustosServiceResolver.setRoleHierarchy(custom);
    JCustosServiceResolver.resetAll();
    assertSame(NoopRoleHierarchy.INSTANCE, JCustosServiceResolver.roleHierarchy());
  }
}
