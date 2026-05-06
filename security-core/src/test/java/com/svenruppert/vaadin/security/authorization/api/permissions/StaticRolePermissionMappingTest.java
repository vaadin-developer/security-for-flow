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

import com.svenruppert.vaadin.security.authorization.api.roles.RoleName;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("StaticRolePermissionMapping + RolePermissionResolver")
class StaticRolePermissionMappingTest {

  private final StaticRolePermissionMapping mapping = StaticRolePermissionMapping.builder()
      .put("ROLE_ADMIN", "doc:read", "doc:delete")
      .put("ROLE_VIEWER", "doc:read")
      .build();

  @Test
  @DisplayName("known role yields the configured permissions")
  void knownRole() {
    Set<PermissionName> perms = mapping.permissionsFor(new RoleName("ROLE_ADMIN"));
    assertTrue(perms.contains(new PermissionName("doc:read")));
    assertTrue(perms.contains(new PermissionName("doc:delete")));
  }

  @Test
  @DisplayName("unknown role yields an empty permission set")
  void unknownRole() {
    assertTrue(mapping.permissionsFor(new RoleName("ROLE_UNKNOWN")).isEmpty());
  }

  @Test
  @DisplayName("Resolver merges permissions across multiple roles, deduplicated")
  void mergesAcrossRoles() {
    Set<PermissionName> merged = RolePermissionResolver.permissionsForRoles(
        Set.of(new RoleName("ROLE_ADMIN"), new RoleName("ROLE_VIEWER")), mapping);
    assertEquals(2, merged.size());
    assertTrue(merged.contains(new PermissionName("doc:read")));
    assertTrue(merged.contains(new PermissionName("doc:delete")));
  }

  @Test
  @DisplayName("Resolver with empty role set returns empty permissions")
  void emptyRoles() {
    assertTrue(RolePermissionResolver.permissionsForRoles(Set.of(), mapping).isEmpty());
  }
}
