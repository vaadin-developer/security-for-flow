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

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("JSentinelSubject")
class JSentinelSubjectTest {

  @Test
  @DisplayName("stores defensive copies of roles and permissions")
  void defensiveCopies() {
    Set<RoleName> roles = new HashSet<>(Set.of(new RoleName("ROLE_ADMIN")));
    Set<PermissionName> permissions = new HashSet<>(Set.of(new PermissionName("demo:read")));

    JSentinelSubject subject = new JSentinelSubject("u1", "Admin", roles, permissions);

    roles.clear();
    permissions.clear();

    assertEquals(Set.of(new RoleName("ROLE_ADMIN")), subject.roleNames());
    assertEquals(Set.of(new PermissionName("demo:read")), subject.permissionNames());
  }

  @Test
  @DisplayName("empty roles and permissions are valid")
  void emptyRolesAndPermissionsAreValid() {
    JSentinelSubject subject = new JSentinelSubject("u1", "User", Set.of(), Set.of());

    assertTrue(subject.roleNames().isEmpty());
    assertTrue(subject.permissionNames().isEmpty());
  }

  @Test
  @DisplayName("blank subject id is rejected")
  void blankSubjectIdRejected() {
    assertThrows(IllegalArgumentException.class,
        () -> new JSentinelSubject(" ", "User", Set.of(), Set.of()));
  }
}
