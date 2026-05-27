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
package com.svenruppert.vaadin.security.test;

import com.svenruppert.vaadin.security.authorization.api.permissions.PermissionName;
import com.svenruppert.vaadin.security.authorization.api.roles.RoleName;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FakeAuthorizationServiceTest {

  @Test
  @DisplayName("unknown subject returns empty roles and permissions, never throws")
  void unknownSubjectReturnsEmpty() {
    FakeAuthorizationService<String> auth = new FakeAuthorizationService<>();
    assertTrue(auth.rolesFor("ghost").roleNames().isEmpty());
    assertTrue(auth.permissionsFor("ghost").permissionNames().isEmpty());
  }

  @Test
  @DisplayName("put binds roles and permissions for a subject")
  void putBindsRolesAndPermissions() {
    FakeAuthorizationService<String> auth = new FakeAuthorizationService<>();
    auth.put("alice",
        Set.of(new RoleName("ROLE_ADMIN")),
        Set.of(new PermissionName("doc:write")));

    assertEquals(1, auth.rolesFor("alice").roleNames().size());
    assertEquals(1, auth.permissionsFor("alice").permissionNames().size());
  }

  @Test
  @DisplayName("putRoles replaces only roles, permissions stay intact")
  void putRolesIsolated() {
    FakeAuthorizationService<String> auth = new FakeAuthorizationService<>();
    auth.put("alice",
        Set.of(new RoleName("ROLE_VIEWER")),
        Set.of(new PermissionName("doc:read")));
    auth.putRoles("alice", Set.of(new RoleName("ROLE_EDITOR")));

    assertEquals(Set.of(new RoleName("ROLE_EDITOR")),
        Set.copyOf(auth.rolesFor("alice").roleNames()));
    assertEquals(Set.of(new PermissionName("doc:read")),
        Set.copyOf(auth.permissionsFor("alice").permissionNames()));
  }

  @Test
  @DisplayName("putPermissions replaces only permissions, roles stay intact")
  void putPermissionsIsolated() {
    FakeAuthorizationService<String> auth = new FakeAuthorizationService<>();
    auth.put("alice",
        Set.of(new RoleName("ROLE_VIEWER")),
        Set.of(new PermissionName("doc:read")));
    auth.putPermissions("alice", Set.of(new PermissionName("doc:write")));

    assertEquals(Set.of(new RoleName("ROLE_VIEWER")),
        Set.copyOf(auth.rolesFor("alice").roleNames()));
    assertEquals(Set.of(new PermissionName("doc:write")),
        Set.copyOf(auth.permissionsFor("alice").permissionNames()));
  }

  @Test
  @DisplayName("put rejects null subject / role set / permission set")
  void putRejectsNulls() {
    FakeAuthorizationService<String> auth = new FakeAuthorizationService<>();
    assertThrows(NullPointerException.class,
        () -> auth.put(null, Set.of(), Set.of()));
    assertThrows(NullPointerException.class,
        () -> auth.put("a", null, Set.of()));
    assertThrows(NullPointerException.class,
        () -> auth.put("a", Set.of(), null));
  }

  @Test
  @DisplayName("clear removes all entries")
  void clearWipesEntries() {
    FakeAuthorizationService<String> auth = new FakeAuthorizationService<>();
    auth.put("alice",
        Set.of(new RoleName("ROLE_VIEWER")),
        Set.of(new PermissionName("doc:read")));
    auth.clear();

    assertTrue(auth.rolesFor("alice").roleNames().isEmpty());
    assertTrue(auth.permissionsFor("alice").permissionNames().isEmpty());
  }
}
