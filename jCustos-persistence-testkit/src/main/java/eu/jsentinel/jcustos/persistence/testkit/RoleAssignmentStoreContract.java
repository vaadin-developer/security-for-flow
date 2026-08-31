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
package eu.jsentinel.jcustos.persistence.testkit;

import eu.jsentinel.jcustos.authorization.api.roles.RoleAssignmentKey;
import eu.jsentinel.jcustos.authorization.api.roles.RoleAssignmentStore;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Contract every {@link RoleAssignmentStore} implementation must
 * satisfy.
 */
@DisplayName("RoleAssignmentStore — contract")
public interface RoleAssignmentStoreContract {

  /**
   * @return a fresh, empty {@code RoleAssignmentStore}
   */
  RoleAssignmentStore newStore();

  RoleName ADMIN = new RoleName("ADMIN");
  RoleName EDITOR = new RoleName("EDITOR");
  RoleName VIEWER = new RoleName("VIEWER");

  /**
   * Builds an assignment key in the default tenant.
   *
   * @param subject username
   * @return new key
   */
  default RoleAssignmentKey key(String subject) {
    return new RoleAssignmentKey(TenantId.DEFAULT, new SubjectId(subject));
  }

  @Test
  @DisplayName("findRoles returns an empty set for an unknown key")
  default void unknownKeyReturnsEmpty() {
    RoleAssignmentStore store = newStore();
    assertTrue(store.findRoles(key("ghost")).isEmpty());
  }

  @Test
  @DisplayName("findRoles returns an immutable defensive copy")
  default void findRolesImmutable() {
    RoleAssignmentStore store = newStore();
    store.assignRole(key("alice"), ADMIN);
    Set<RoleName> roles = store.findRoles(key("alice"));
    assertThrows(UnsupportedOperationException.class, () -> roles.add(EDITOR));
  }

  @Test
  @DisplayName("setRoles replaces the role set wholesale")
  default void setRolesReplaces() {
    RoleAssignmentStore store = newStore();
    store.setRoles(key("alice"), Set.of(ADMIN, EDITOR));
    store.setRoles(key("alice"), Set.of(VIEWER));
    assertEquals(Set.of(VIEWER), store.findRoles(key("alice")));
  }

  @Test
  @DisplayName("setRoles with an empty set clears the entry")
  default void setRolesEmptyClears() {
    RoleAssignmentStore store = newStore();
    store.setRoles(key("alice"), Set.of(ADMIN));
    store.setRoles(key("alice"), Set.of());
    assertTrue(store.findRoles(key("alice")).isEmpty());
  }

  @Test
  @DisplayName("setRoles with null is treated as empty")
  default void setRolesNullClears() {
    RoleAssignmentStore store = newStore();
    store.setRoles(key("alice"), Set.of(ADMIN));
    store.setRoles(key("alice"), null);
    assertTrue(store.findRoles(key("alice")).isEmpty());
  }

  @Test
  @DisplayName("assignRole adds a role and returns true the first time")
  default void assignRoleFirstTime() {
    RoleAssignmentStore store = newStore();
    assertTrue(store.assignRole(key("alice"), ADMIN));
    assertEquals(Set.of(ADMIN), store.findRoles(key("alice")));
  }

  @Test
  @DisplayName("assignRole returns false on a duplicate add")
  default void assignRoleDuplicate() {
    RoleAssignmentStore store = newStore();
    store.assignRole(key("alice"), ADMIN);
    assertFalse(store.assignRole(key("alice"), ADMIN));
  }

  @Test
  @DisplayName("assignRole preserves existing roles")
  default void assignRolePreservesExisting() {
    RoleAssignmentStore store = newStore();
    store.assignRole(key("alice"), ADMIN);
    store.assignRole(key("alice"), EDITOR);
    assertEquals(Set.of(ADMIN, EDITOR), store.findRoles(key("alice")));
  }

  @Test
  @DisplayName("revokeRole removes a present role and returns true")
  default void revokePresent() {
    RoleAssignmentStore store = newStore();
    store.assignRole(key("alice"), ADMIN);
    store.assignRole(key("alice"), EDITOR);
    assertTrue(store.revokeRole(key("alice"), ADMIN));
    assertEquals(Set.of(EDITOR), store.findRoles(key("alice")));
  }

  @Test
  @DisplayName("revokeRole returns false for a role not held")
  default void revokeAbsent() {
    RoleAssignmentStore store = newStore();
    store.assignRole(key("alice"), ADMIN);
    assertFalse(store.revokeRole(key("alice"), EDITOR));
  }

  @Test
  @DisplayName("revoking the last role drops the whole entry")
  default void revokingLastRoleDropsEntry() {
    RoleAssignmentStore store = newStore();
    store.assignRole(key("alice"), ADMIN);
    store.revokeRole(key("alice"), ADMIN);
    assertTrue(store.findRoles(key("alice")).isEmpty());
  }

  @Test
  @DisplayName("clearRoles drops every role for the key")
  default void clearRolesDrops() {
    RoleAssignmentStore store = newStore();
    store.assignRole(key("alice"), ADMIN);
    store.assignRole(key("alice"), EDITOR);
    store.clearRoles(key("alice"));
    assertTrue(store.findRoles(key("alice")).isEmpty());
  }

  @Test
  @DisplayName("assignments are tenant-scoped")
  default void tenantScopedAssignments() {
    RoleAssignmentStore store = newStore();
    SubjectId alice = new SubjectId("alice");
    RoleAssignmentKey defaultScope = new RoleAssignmentKey(TenantId.DEFAULT, alice);
    RoleAssignmentKey acmeScope = new RoleAssignmentKey(new TenantId("acme"), alice);

    store.assignRole(defaultScope, ADMIN);
    store.assignRole(acmeScope, VIEWER);

    assertEquals(Set.of(ADMIN), store.findRoles(defaultScope));
    assertEquals(Set.of(VIEWER), store.findRoles(acmeScope));
  }

  @Test
  @DisplayName("all methods reject null key / role")
  default void rejectNulls() {
    RoleAssignmentStore store = newStore();
    assertThrows(NullPointerException.class, () -> store.findRoles(null));
    assertThrows(NullPointerException.class, () -> store.assignRole(null, ADMIN));
    assertThrows(NullPointerException.class, () -> store.assignRole(key("a"), null));
    assertThrows(NullPointerException.class, () -> store.revokeRole(null, ADMIN));
    assertThrows(NullPointerException.class, () -> store.revokeRole(key("a"), null));
    assertThrows(NullPointerException.class, () -> store.clearRoles(null));
    assertThrows(NullPointerException.class, () -> store.setRoles(null, Set.of()));
  }
}
