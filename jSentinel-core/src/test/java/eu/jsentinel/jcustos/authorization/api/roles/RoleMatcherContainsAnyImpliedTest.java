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
package eu.jsentinel.jcustos.authorization.api.roles;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RoleMatcherContainsAnyImpliedTest {

  private static final RoleName ADMIN = new RoleName("ROLE_ADMIN");
  private static final RoleName EDITOR = new RoleName("ROLE_EDITOR");
  private static final RoleName VIEWER = new RoleName("ROLE_VIEWER");

  @Test
  @DisplayName("noop hierarchy: behaves like containsAny")
  void noopBehavesLikeContainsAny() {
    assertTrue(RoleMatcher.containsAnyImplied(
        Set.of(ADMIN), Set.of(ADMIN), NoopRoleHierarchy.INSTANCE));
    assertFalse(RoleMatcher.containsAnyImplied(
        Set.of(EDITOR), Set.of(ADMIN), NoopRoleHierarchy.INSTANCE));
  }

  @Test
  @DisplayName("hierarchy: held ADMIN matches required VIEWER via ADMIN -> EDITOR -> VIEWER")
  void hierarchyMatchesTransitive() {
    RoleHierarchy hierarchy = StaticRoleHierarchy.builder()
        .role(ADMIN).inheritsFrom(EDITOR)
        .role(EDITOR).inheritsFrom(VIEWER)
        .build();
    assertTrue(RoleMatcher.containsAnyImplied(
        Set.of(ADMIN), Set.of(VIEWER), hierarchy));
  }

  @Test
  @DisplayName("hierarchy: held VIEWER does not match required ADMIN")
  void hierarchyDirectionIsTopDown() {
    RoleHierarchy hierarchy = StaticRoleHierarchy.builder()
        .role(ADMIN).inheritsFrom(EDITOR)
        .build();
    assertFalse(RoleMatcher.containsAnyImplied(
        Set.of(EDITOR), Set.of(ADMIN), hierarchy));
  }

  @Test
  @DisplayName("empty granted set returns false")
  void emptyGrantedFalse() {
    assertFalse(RoleMatcher.containsAnyImplied(
        Set.of(), Set.of(ADMIN), NoopRoleHierarchy.INSTANCE));
  }

  @Test
  @DisplayName("empty required set returns false")
  void emptyRequiredFalse() {
    assertFalse(RoleMatcher.containsAnyImplied(
        Set.of(ADMIN), Set.of(), NoopRoleHierarchy.INSTANCE));
  }

  @Test
  @DisplayName("null hierarchy throws NullPointerException")
  void nullHierarchyThrows() {
    assertThrows(NullPointerException.class,
        () -> RoleMatcher.containsAnyImplied(
            Set.of(ADMIN), Set.of(ADMIN), null));
  }
}
