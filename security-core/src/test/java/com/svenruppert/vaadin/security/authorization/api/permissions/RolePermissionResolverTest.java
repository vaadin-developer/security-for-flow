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
package com.svenruppert.vaadin.security.authorization.api.permissions;

import com.svenruppert.vaadin.security.authorization.api.roles.NoopRoleHierarchy;
import com.svenruppert.vaadin.security.authorization.api.roles.RoleHierarchy;
import com.svenruppert.vaadin.security.authorization.api.roles.RoleName;
import com.svenruppert.vaadin.security.authorization.api.roles.StaticRoleHierarchy;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("RolePermissionResolver")
class RolePermissionResolverTest {

  private static final RoleName ADMIN = new RoleName("ADMIN");
  private static final RoleName EDITOR = new RoleName("EDITOR");
  private static final RoleName VIEWER = new RoleName("VIEWER");
  private static final RoleName UNMAPPED = new RoleName("UNMAPPED");

  private static final PermissionName ADMIN_WRITE = new PermissionName("admin:write");
  private static final PermissionName EDITOR_EDIT = new PermissionName("editor:edit");
  private static final PermissionName VIEWER_READ = new PermissionName("viewer:read");

  private static final StaticRolePermissionMapping FLAT_MAPPING =
      StaticRolePermissionMapping.builder()
          .put(ADMIN, Set.of(ADMIN_WRITE))
          .put(EDITOR, Set.of(EDITOR_EDIT))
          .put(VIEWER, Set.of(VIEWER_READ))
          .build();

  // Each role gets only its OWN permission; inheritance comes from the hierarchy.
  private static final RoleHierarchy HIERARCHY =
      StaticRoleHierarchy.builder()
          .role(ADMIN).inheritsFrom(EDITOR)
          .role(EDITOR).inheritsFrom(VIEWER)
          .build();

  // ── flat resolver (no hierarchy) ────────────────────────────────

  @Nested
  @DisplayName("permissionsForRoles(roles, mapping)")
  class Flat {

    @Test
    @DisplayName("single role maps to its own permissions only — no transitive expansion")
    void singleRoleNoExpansion() {
      Set<PermissionName> result = RolePermissionResolver.permissionsForRoles(
          Set.of(ADMIN), FLAT_MAPPING);
      assertEquals(Set.of(ADMIN_WRITE), result,
          "without a hierarchy ADMIN gives only its directly-mapped permission");
    }

    @Test
    @DisplayName("multiple roles union their permission sets")
    void multipleRolesUnioned() {
      Set<PermissionName> result = RolePermissionResolver.permissionsForRoles(
          Set.of(EDITOR, VIEWER), FLAT_MAPPING);
      assertEquals(Set.of(EDITOR_EDIT, VIEWER_READ), result);
    }

    @Test
    @DisplayName("empty role set yields empty permission set")
    void emptyRoles() {
      Set<PermissionName> result = RolePermissionResolver.permissionsForRoles(
          Set.of(), FLAT_MAPPING);
      assertTrue(result.isEmpty());
    }

    @Test
    @DisplayName("role without mapping contributes nothing")
    void unmappedRoleContributesNothing() {
      Set<PermissionName> result = RolePermissionResolver.permissionsForRoles(
          Set.of(UNMAPPED, VIEWER), FLAT_MAPPING);
      assertEquals(Set.of(VIEWER_READ), result,
          "UNMAPPED has no permissions in the mapping, so only VIEWER_READ remains");
    }

    @Test
    @DisplayName("null roles throw NullPointerException")
    void nullRolesRejected() {
      assertThrows(NullPointerException.class,
          () -> RolePermissionResolver.permissionsForRoles(null, FLAT_MAPPING));
    }

    @Test
    @DisplayName("null mapping throws NullPointerException")
    void nullMappingRejected() {
      assertThrows(NullPointerException.class,
          () -> RolePermissionResolver.permissionsForRoles(Set.of(ADMIN), null));
    }

    @Test
    @DisplayName("returned set is immutable")
    void resultIsImmutable() {
      Set<PermissionName> result = RolePermissionResolver.permissionsForRoles(
          Set.of(ADMIN), FLAT_MAPPING);
      assertThrows(UnsupportedOperationException.class,
          () -> result.add(new PermissionName("intruder")));
    }
  }

  // ── hierarchy-aware resolver ────────────────────────────────────

  @Nested
  @DisplayName("permissionsForRoles(roles, mapping, hierarchy)")
  class WithHierarchy {

    @Test
    @DisplayName("ADMIN transitively inherits EDITOR + VIEWER permissions via the hierarchy")
    void transitiveInheritance() {
      Set<PermissionName> result = RolePermissionResolver.permissionsForRoles(
          Set.of(ADMIN), FLAT_MAPPING, HIERARCHY);
      assertEquals(Set.of(ADMIN_WRITE, EDITOR_EDIT, VIEWER_READ), result,
          "ADMIN → EDITOR → VIEWER must expand into all three permissions");
    }

    @Test
    @DisplayName("intermediate role gets its own + descendant permissions, not the parent's")
    void intermediateRoleDoesNotInheritParentPermissions() {
      Set<PermissionName> result = RolePermissionResolver.permissionsForRoles(
          Set.of(EDITOR), FLAT_MAPPING, HIERARCHY);
      assertEquals(Set.of(EDITOR_EDIT, VIEWER_READ), result,
          "EDITOR implies VIEWER but NOT ADMIN — admin:write must not leak down");
    }

    @Test
    @DisplayName("leaf role contributes only itself")
    void leafRoleSelfOnly() {
      Set<PermissionName> result = RolePermissionResolver.permissionsForRoles(
          Set.of(VIEWER), FLAT_MAPPING, HIERARCHY);
      assertEquals(Set.of(VIEWER_READ), result);
    }

    @Test
    @DisplayName("NoopRoleHierarchy makes the result identical to the flat variant")
    void noopHierarchyEqualsFlatVariant() {
      Set<PermissionName> hierarchical = RolePermissionResolver.permissionsForRoles(
          Set.of(ADMIN, VIEWER), FLAT_MAPPING, NoopRoleHierarchy.INSTANCE);
      Set<PermissionName> flat = RolePermissionResolver.permissionsForRoles(
          Set.of(ADMIN, VIEWER), FLAT_MAPPING);
      assertEquals(flat, hierarchical,
          "Noop hierarchy implies only the role itself — must equal the flat union");
    }

    @Test
    @DisplayName("role with no mapping but implied roles with mappings yields the implied permissions")
    void unmappedParentWithMappedChildren() {
      RoleHierarchy hierarchy = StaticRoleHierarchy.builder()
          .role(UNMAPPED).inheritsFrom(VIEWER)
          .build();
      Set<PermissionName> result = RolePermissionResolver.permissionsForRoles(
          Set.of(UNMAPPED), FLAT_MAPPING, hierarchy);
      assertEquals(Set.of(VIEWER_READ), result,
          "UNMAPPED carries no direct permissions but inherits from VIEWER, "
              + "so VIEWER_READ must surface");
    }

    @Test
    @DisplayName("overlapping role sets de-duplicate")
    void overlappingExpansionsDeduplicate() {
      Set<PermissionName> result = RolePermissionResolver.permissionsForRoles(
          Set.of(ADMIN, EDITOR), FLAT_MAPPING, HIERARCHY);
      // ADMIN expands to {ADMIN, EDITOR, VIEWER}; EDITOR expands to {EDITOR, VIEWER}.
      // Union is identical to ADMIN's expansion.
      assertEquals(Set.of(ADMIN_WRITE, EDITOR_EDIT, VIEWER_READ), result);
    }

    @Test
    @DisplayName("empty role set yields empty permission set")
    void emptyRoles() {
      Set<PermissionName> result = RolePermissionResolver.permissionsForRoles(
          Set.of(), FLAT_MAPPING, HIERARCHY);
      assertTrue(result.isEmpty());
    }

    @Test
    @DisplayName("null hierarchy throws NullPointerException")
    void nullHierarchyRejected() {
      assertThrows(NullPointerException.class,
          () -> RolePermissionResolver.permissionsForRoles(
              Set.of(ADMIN), FLAT_MAPPING, null));
    }

    @Test
    @DisplayName("null roles throws NullPointerException")
    void nullRolesRejected() {
      assertThrows(NullPointerException.class,
          () -> RolePermissionResolver.permissionsForRoles(
              null, FLAT_MAPPING, HIERARCHY));
    }

    @Test
    @DisplayName("null mapping throws NullPointerException")
    void nullMappingRejected() {
      assertThrows(NullPointerException.class,
          () -> RolePermissionResolver.permissionsForRoles(
              Set.of(ADMIN), null, HIERARCHY));
    }

    @Test
    @DisplayName("returned set is immutable")
    void resultIsImmutable() {
      Set<PermissionName> result = RolePermissionResolver.permissionsForRoles(
          Set.of(ADMIN), FLAT_MAPPING, HIERARCHY);
      assertThrows(UnsupportedOperationException.class,
          () -> result.add(new PermissionName("intruder")));
    }
  }
}
