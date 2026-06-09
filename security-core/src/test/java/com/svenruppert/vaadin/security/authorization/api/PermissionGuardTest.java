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
package com.svenruppert.vaadin.security.authorization.api;

import com.svenruppert.vaadin.security.authorization.api.permissions.PermissionName;
import com.svenruppert.vaadin.security.authorization.api.roles.RoleName;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("PermissionGuard")
class PermissionGuardTest {

  private final PermissionName perm = new PermissionName("document:delete");
  private final RoleName role = new RoleName("ROLE_ADMIN");

  private final JSentinelSubject withPermAndRole = new JSentinelSubject(
      "u1", "User", Set.of(role), Set.of(perm));
  private final JSentinelSubject withoutPerm = new JSentinelSubject(
      "u2", "Other", Set.of(), Set.of());

  @Test
  @DisplayName("hasPermission true when subject contains permission")
  void hasPerm() {
    assertTrue(PermissionGuard.hasPermission(withPermAndRole, perm));
    assertFalse(PermissionGuard.hasPermission(withoutPerm, perm));
    assertFalse(PermissionGuard.hasPermission(null, perm));
    assertFalse(PermissionGuard.hasPermission(withPermAndRole, null));
  }

  @Test
  @DisplayName("requirePermission throws AccessDeniedException when missing")
  void requirePerm() {
    assertDoesNotThrow(() -> PermissionGuard.requirePermission(withPermAndRole, perm));
    AccessDeniedException ex = assertThrows(AccessDeniedException.class,
        () -> PermissionGuard.requirePermission(withoutPerm, perm));
    assertTrue(ex.getMessage().contains(perm.value()));
  }

  @Test
  @DisplayName("hasRole / requireRole behave consistently")
  void roles() {
    assertTrue(PermissionGuard.hasRole(withPermAndRole, role));
    assertFalse(PermissionGuard.hasRole(withoutPerm, role));
    assertThrows(AccessDeniedException.class,
        () -> PermissionGuard.requireRole(withoutPerm, role));
    assertDoesNotThrow(() -> PermissionGuard.requireRole(withPermAndRole, role));
  }

  @Test
  @DisplayName("hasRole returns false for null subject or null role")
  void hasRoleNullArguments() {
    assertFalse(PermissionGuard.hasRole(null, role));
    assertFalse(PermissionGuard.hasRole(withPermAndRole, null));
    assertFalse(PermissionGuard.hasRole(null, null));
  }

  @Test
  @DisplayName("requireRole rejects null role argument up-front")
  void requireRoleRejectsNullRole() {
    assertThrows(NullPointerException.class,
        () -> PermissionGuard.requireRole(withPermAndRole, null));
  }

  @Test
  @DisplayName("requireRole error message carries the role name")
  void requireRoleErrorMessage() {
    AccessDeniedException ex = assertThrows(AccessDeniedException.class,
        () -> PermissionGuard.requireRole(withoutPerm, role));
    assertTrue(ex.getMessage().contains(role.value()));
  }

  @Test
  @DisplayName("requirePermission rejects null permission argument up-front")
  void requirePermissionRejectsNullPermission() {
    assertThrows(NullPointerException.class,
        () -> PermissionGuard.requirePermission(withPermAndRole, null));
  }
}
