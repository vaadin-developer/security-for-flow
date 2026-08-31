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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StaticRoleHierarchyTest {

  private static final RoleName ADMIN = new RoleName("ROLE_ADMIN");
  private static final RoleName EDITOR = new RoleName("ROLE_EDITOR");
  private static final RoleName VIEWER = new RoleName("ROLE_VIEWER");
  private static final RoleName GUEST = new RoleName("ROLE_GUEST");

  @Test
  @DisplayName("simple two-level hierarchy: ADMIN -> EDITOR")
  void twoLevel() {
    RoleHierarchy hierarchy = StaticRoleHierarchy.builder()
        .role(ADMIN).inheritsFrom(EDITOR)
        .build();
    assertTrue(hierarchy.impliesRole(ADMIN, EDITOR));
    assertTrue(hierarchy.impliesRole(ADMIN, ADMIN));
    assertFalse(hierarchy.impliesRole(EDITOR, ADMIN));
  }

  @Test
  @DisplayName("transitive three-level hierarchy: ADMIN -> EDITOR -> VIEWER")
  void transitive() {
    RoleHierarchy hierarchy = StaticRoleHierarchy.builder()
        .role(ADMIN).inheritsFrom(EDITOR)
        .role(EDITOR).inheritsFrom(VIEWER)
        .build();
    assertTrue(hierarchy.impliesRole(ADMIN, VIEWER));
    assertTrue(hierarchy.impliesRole(ADMIN, EDITOR));
    assertTrue(hierarchy.impliesRole(EDITOR, VIEWER));
    assertFalse(hierarchy.impliesRole(VIEWER, EDITOR));
    assertFalse(hierarchy.impliesRole(VIEWER, ADMIN));
  }

  @Test
  @DisplayName("multiple children in one inheritsFrom call")
  void multipleChildrenOneCall() {
    RoleHierarchy hierarchy = StaticRoleHierarchy.builder()
        .role(ADMIN).inheritsFrom(EDITOR, VIEWER)
        .build();
    assertTrue(hierarchy.impliesRole(ADMIN, EDITOR));
    assertTrue(hierarchy.impliesRole(ADMIN, VIEWER));
  }

  @Test
  @DisplayName("repeated role(...) calls accumulate children")
  void roleCallAccumulates() {
    RoleHierarchy hierarchy = StaticRoleHierarchy.builder()
        .role(ADMIN).inheritsFrom(EDITOR)
        .role(ADMIN).inheritsFrom(VIEWER)
        .build();
    assertTrue(hierarchy.impliesRole(ADMIN, EDITOR));
    assertTrue(hierarchy.impliesRole(ADMIN, VIEWER));
  }

  @Test
  @DisplayName("roles never declared as parents still imply themselves")
  void undeclaredRoleImpliesSelf() {
    RoleHierarchy hierarchy = StaticRoleHierarchy.builder()
        .role(ADMIN).inheritsFrom(EDITOR)
        .build();
    assertTrue(hierarchy.impliesRole(GUEST, GUEST));
    assertFalse(hierarchy.impliesRole(GUEST, ADMIN));
  }

  @Test
  @DisplayName("impliedRoles for an undeclared role returns only the role itself")
  void impliedRolesUndeclared() {
    RoleHierarchy hierarchy = StaticRoleHierarchy.builder()
        .role(ADMIN).inheritsFrom(EDITOR)
        .build();
    assertEquals(java.util.Set.of(GUEST), hierarchy.impliedRoles(GUEST));
  }

  @Test
  @DisplayName("impliedRoles includes the held role itself")
  void impliedIncludesSelf() {
    RoleHierarchy hierarchy = StaticRoleHierarchy.builder()
        .role(ADMIN).inheritsFrom(EDITOR, VIEWER)
        .build();
    var implied = hierarchy.impliedRoles(ADMIN);
    assertTrue(implied.contains(ADMIN));
    assertTrue(implied.contains(EDITOR));
    assertTrue(implied.contains(VIEWER));
  }

  @Test
  @DisplayName("direct self-cycle is rejected at build time")
  void rejectsDirectSelfCycle() {
    StaticRoleHierarchy.Builder builder = StaticRoleHierarchy.builder()
        .role(ADMIN).inheritsFrom(ADMIN);
    assertThrows(IllegalStateException.class, builder::build);
  }

  @Test
  @DisplayName("indirect cycle (ADMIN -> EDITOR -> ADMIN) is rejected at build time")
  void rejectsIndirectCycle() {
    StaticRoleHierarchy.Builder builder = StaticRoleHierarchy.builder()
        .role(ADMIN).inheritsFrom(EDITOR)
        .role(EDITOR).inheritsFrom(ADMIN);
    assertThrows(IllegalStateException.class, builder::build);
  }

  @Test
  @DisplayName("three-node transitive cycle (ADMIN -> EDITOR -> VIEWER -> ADMIN) is rejected (R034)")
  void rejectsThreeNodeCycle() {
    StaticRoleHierarchy.Builder builder = StaticRoleHierarchy.builder()
        .role(ADMIN).inheritsFrom(EDITOR)
        .role(EDITOR).inheritsFrom(VIEWER)
        .role(VIEWER).inheritsFrom(ADMIN);
    assertThrows(IllegalStateException.class, builder::build,
        "a transitive 3-node cycle must be rejected at build time");
  }

  @Test
  @DisplayName("a cycle not involving the entry node is still rejected (R034)")
  void rejectsCycleReachedFromANonCycleNode() {
    // GUEST is not part of the cycle; it points into the EDITOR <-> VIEWER cycle.
    // Detection must not depend on which parent build() happens to walk first:
    // walking from EDITOR or VIEWER reaches a back-edge to its own start.
    StaticRoleHierarchy.Builder builder = StaticRoleHierarchy.builder()
        .role(GUEST).inheritsFrom(EDITOR)
        .role(EDITOR).inheritsFrom(VIEWER)
        .role(VIEWER).inheritsFrom(EDITOR);
    assertThrows(IllegalStateException.class, builder::build,
        "a cycle reachable from a non-cycle node must still be rejected");
  }

  @Test
  @DisplayName("inheritsFrom without preceding role(...) throws")
  void inheritsFromWithoutRoleThrows() {
    StaticRoleHierarchy.Builder builder = StaticRoleHierarchy.builder();
    assertThrows(IllegalStateException.class, () -> builder.inheritsFrom(EDITOR));
  }

  @Test
  @DisplayName("builder rejects null parent/child")
  void rejectsNullParticipants() {
    assertThrows(NullPointerException.class,
        () -> StaticRoleHierarchy.builder().role(null));
    assertThrows(NullPointerException.class,
        () -> StaticRoleHierarchy.builder().role(ADMIN).inheritsFrom(null));
  }

  @Test
  @DisplayName("impliedRoles rejects null")
  void impliedRolesRejectsNull() {
    RoleHierarchy hierarchy = StaticRoleHierarchy.builder()
        .role(ADMIN).inheritsFrom(EDITOR)
        .build();
    assertThrows(NullPointerException.class, () -> hierarchy.impliedRoles(null));
  }
}
