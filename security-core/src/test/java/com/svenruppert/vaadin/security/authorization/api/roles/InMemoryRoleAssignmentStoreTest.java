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
package com.svenruppert.vaadin.security.authorization.api.roles;

import com.svenruppert.vaadin.security.authorization.api.tenant.TenantId;
import com.svenruppert.vaadin.security.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("InMemoryRoleAssignmentStore")
class InMemoryRoleAssignmentStoreTest {

  private static final RoleName ADMIN = new RoleName("ADMIN");
  private static final RoleName EDITOR = new RoleName("EDITOR");
  private static final RoleName VIEWER = new RoleName("VIEWER");

  private final InMemoryRoleAssignmentStore store = new InMemoryRoleAssignmentStore();

  private static RoleAssignmentKey key(String subject) {
    return new RoleAssignmentKey(TenantId.DEFAULT, new SubjectId(subject));
  }

  // ── findRoles ───────────────────────────────────────────────────

  @Test
  @DisplayName("findRoles returns an empty set for an unknown key")
  void unknownKeyReturnsEmpty() {
    assertTrue(store.findRoles(key("ghost")).isEmpty());
  }

  @Test
  @DisplayName("findRoles returns an immutable defensive copy")
  void findRolesReturnsImmutable() {
    store.assignRole(key("alice"), ADMIN);
    Set<RoleName> roles = store.findRoles(key("alice"));
    assertThrows(UnsupportedOperationException.class, () -> roles.add(EDITOR));
  }

  // ── setRoles ────────────────────────────────────────────────────

  @Test
  @DisplayName("setRoles replaces the role set wholesale")
  void setRolesReplaces() {
    store.setRoles(key("alice"), Set.of(ADMIN, EDITOR));
    store.setRoles(key("alice"), Set.of(VIEWER));
    assertEquals(Set.of(VIEWER), store.findRoles(key("alice")));
  }

  @Test
  @DisplayName("setRoles with an empty set clears the entry")
  void setRolesEmptyClears() {
    store.setRoles(key("alice"), Set.of(ADMIN));
    store.setRoles(key("alice"), Set.of());
    assertTrue(store.findRoles(key("alice")).isEmpty());
  }

  @Test
  @DisplayName("setRoles with null is treated as empty (clears the entry)")
  void setRolesNullClears() {
    store.setRoles(key("alice"), Set.of(ADMIN));
    store.setRoles(key("alice"), null);
    assertTrue(store.findRoles(key("alice")).isEmpty());
  }

  // ── assignRole / revokeRole ─────────────────────────────────────

  @Test
  @DisplayName("assignRole adds a role and returns true the first time")
  void assignRoleFirstTimeReturnsTrue() {
    assertTrue(store.assignRole(key("alice"), ADMIN));
    assertEquals(Set.of(ADMIN), store.findRoles(key("alice")));
  }

  @Test
  @DisplayName("assignRole returns false on a duplicate add")
  void assignRoleDuplicateReturnsFalse() {
    store.assignRole(key("alice"), ADMIN);
    assertFalse(store.assignRole(key("alice"), ADMIN));
  }

  @Test
  @DisplayName("assignRole keeps existing roles")
  void assignRolePreservesExisting() {
    store.assignRole(key("alice"), ADMIN);
    store.assignRole(key("alice"), EDITOR);
    assertEquals(Set.of(ADMIN, EDITOR), store.findRoles(key("alice")));
  }

  @Test
  @DisplayName("revokeRole removes a present role and returns true")
  void revokePresentReturnsTrue() {
    store.assignRole(key("alice"), ADMIN);
    store.assignRole(key("alice"), EDITOR);
    assertTrue(store.revokeRole(key("alice"), ADMIN));
    assertEquals(Set.of(EDITOR), store.findRoles(key("alice")));
  }

  @Test
  @DisplayName("revokeRole returns false for a role that was not held")
  void revokeAbsentReturnsFalse() {
    store.assignRole(key("alice"), ADMIN);
    assertFalse(store.revokeRole(key("alice"), EDITOR));
  }

  @Test
  @DisplayName("revoking the last remaining role drops the whole entry")
  void revokingLastRoleDropsEntry() {
    store.assignRole(key("alice"), ADMIN);
    store.revokeRole(key("alice"), ADMIN);
    assertTrue(store.findRoles(key("alice")).isEmpty());
  }

  // ── clearRoles ──────────────────────────────────────────────────

  @Test
  @DisplayName("clearRoles drops every role for the key")
  void clearRolesDropsEverything() {
    store.assignRole(key("alice"), ADMIN);
    store.assignRole(key("alice"), EDITOR);
    store.clearRoles(key("alice"));
    assertTrue(store.findRoles(key("alice")).isEmpty());
  }

  @Test
  @DisplayName("clearRoles on an unknown key is a no-op")
  void clearRolesUnknownKey() {
    store.clearRoles(key("ghost"));
    assertTrue(store.findRoles(key("ghost")).isEmpty());
  }

  // ── tenant scope ────────────────────────────────────────────────

  @Test
  @DisplayName("assignments are tenant-scoped — same SubjectId carries different roles per tenant")
  void tenantScopedAssignments() {
    SubjectId alice = new SubjectId("alice");
    RoleAssignmentKey defaultScope = new RoleAssignmentKey(TenantId.DEFAULT, alice);
    RoleAssignmentKey acmeScope = new RoleAssignmentKey(new TenantId("acme"), alice);

    store.assignRole(defaultScope, ADMIN);
    store.assignRole(acmeScope, VIEWER);

    assertEquals(Set.of(ADMIN), store.findRoles(defaultScope));
    assertEquals(Set.of(VIEWER), store.findRoles(acmeScope));
  }

  // ── null arguments ──────────────────────────────────────────────

  @Test
  @DisplayName("findRoles / assignRole / revokeRole / clearRoles / setRoles reject null key")
  void nullKeyRejected() {
    assertThrows(NullPointerException.class, () -> store.findRoles(null));
    assertThrows(NullPointerException.class, () -> store.assignRole(null, ADMIN));
    assertThrows(NullPointerException.class, () -> store.revokeRole(null, ADMIN));
    assertThrows(NullPointerException.class, () -> store.clearRoles(null));
    assertThrows(NullPointerException.class, () -> store.setRoles(null, Set.of()));
  }

  @Test
  @DisplayName("assignRole / revokeRole reject null role")
  void nullRoleRejected() {
    assertThrows(NullPointerException.class, () -> store.assignRole(key("a"), null));
    assertThrows(NullPointerException.class, () -> store.revokeRole(key("a"), null));
  }
}
