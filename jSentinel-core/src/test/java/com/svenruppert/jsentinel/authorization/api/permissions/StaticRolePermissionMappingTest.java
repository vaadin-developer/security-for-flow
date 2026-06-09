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
package com.svenruppert.jsentinel.authorization.api.permissions;

import com.svenruppert.jsentinel.authorization.api.roles.RoleName;
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

  @Test
  @DisplayName("Builder.put(RoleName, Set) is fluent and registers the role")
  void builderRoleNameOverloadIsFluent() {
    RoleName admin = new RoleName("ROLE_ADMIN");
    PermissionName p = new PermissionName("doc:read");

    StaticRolePermissionMapping.Builder builder = StaticRolePermissionMapping.builder();
    StaticRolePermissionMapping.Builder same = builder.put(admin, Set.of(p));

    assertSame(builder, same, "builder.put must return the same builder for chaining");
    assertEquals(Set.of(p), same.build().permissionsFor(admin));
  }

  @Test
  @DisplayName("Builder.put(String, String...) is fluent and registers the role")
  void builderStringOverloadIsFluent() {
    StaticRolePermissionMapping.Builder builder = StaticRolePermissionMapping.builder();
    StaticRolePermissionMapping.Builder same = builder.put("ROLE_X", "p:1", "p:2");

    assertSame(builder, same);
    Set<PermissionName> perms = same.build().permissionsFor(new RoleName("ROLE_X"));
    assertEquals(2, perms.size());
    assertTrue(perms.contains(new PermissionName("p:1")));
    assertTrue(perms.contains(new PermissionName("p:2")));
  }

  @Test
  @DisplayName("permissionsFor returned set is unmodifiable")
  void returnedPermissionSetIsUnmodifiable() {
    Set<PermissionName> perms = mapping.permissionsFor(new RoleName("ROLE_ADMIN"));
    assertThrows(UnsupportedOperationException.class,
        () -> perms.add(new PermissionName("evil:permission")));
  }

  @Test
  @DisplayName("constructor copies its argument map (mutating the source after build is harmless)")
  void constructorCopiesMap() {
    java.util.Map<RoleName, Set<PermissionName>> source = new java.util.HashMap<>();
    source.put(new RoleName("ROLE_X"), Set.of(new PermissionName("p:1")));
    StaticRolePermissionMapping m = new StaticRolePermissionMapping(source);

    source.put(new RoleName("ROLE_Y"), Set.of(new PermissionName("p:2")));

    assertTrue(m.permissionsFor(new RoleName("ROLE_Y")).isEmpty(),
        "later changes to the source map must not leak into the mapping");
  }
}
