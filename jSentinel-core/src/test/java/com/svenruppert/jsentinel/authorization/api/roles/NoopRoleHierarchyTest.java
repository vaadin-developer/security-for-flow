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
package com.svenruppert.jsentinel.authorization.api.roles;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NoopRoleHierarchyTest {

  @Test
  @DisplayName("impliedRoles returns the held role itself")
  void impliedRolesSelf() {
    Set<RoleName> implied = NoopRoleHierarchy.INSTANCE
        .impliedRoles(new RoleName("ROLE_ADMIN"));
    assertEquals(Set.of(new RoleName("ROLE_ADMIN")), implied);
  }

  @Test
  @DisplayName("impliesRole returns true for identical role")
  void impliesIdentical() {
    assertTrue(NoopRoleHierarchy.INSTANCE
        .impliesRole(new RoleName("ROLE_ADMIN"), new RoleName("ROLE_ADMIN")));
  }

  @Test
  @DisplayName("impliesRole returns false for distinct roles")
  void doesNotImplyDistinct() {
    assertFalse(NoopRoleHierarchy.INSTANCE
        .impliesRole(new RoleName("ROLE_ADMIN"), new RoleName("ROLE_EDITOR")));
  }

  @Test
  @DisplayName("impliedRoles rejects null")
  void rejectsNull() {
    assertThrows(NullPointerException.class,
        () -> NoopRoleHierarchy.INSTANCE.impliedRoles(null));
  }

  @Test
  @DisplayName("INSTANCE is the shared singleton")
  void singletonIdentity() {
    assertEquals(NoopRoleHierarchy.INSTANCE, NoopRoleHierarchy.INSTANCE);
  }
}
