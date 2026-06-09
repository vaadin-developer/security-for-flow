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
package com.svenruppert.jsentinel.authorization.impl;

import com.svenruppert.jsentinel.authorization.api.AuthorizationService;
import com.svenruppert.jsentinel.authorization.api.permissions.HasPermissions;
import com.svenruppert.jsentinel.authorization.api.permissions.PermissionName;
import com.svenruppert.jsentinel.authorization.api.roles.HasRoles;
import com.svenruppert.jsentinel.authorization.api.roles.RoleName;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Test-scope SPI {@link AuthorizationService}. Roles and permissions for a
 * given {@link String} subject are taken from a static map populated via
 * {@link #put(String, Set, Set)} so tests can vary the wiring without
 * registering more services.
 */
public final class StubAuthorizationService implements AuthorizationService<String> {

  private static final Map<String, Set<RoleName>> ROLES = new LinkedHashMap<>();
  private static final Map<String, Set<PermissionName>> PERMISSIONS = new LinkedHashMap<>();

  public static void put(String subject, Set<RoleName> roles, Set<PermissionName> permissions) {
    ROLES.put(subject, roles);
    PERMISSIONS.put(subject, permissions);
  }

  public static void clear() {
    ROLES.clear();
    PERMISSIONS.clear();
  }

  @Override
  public HasRoles rolesFor(String subject) {
    Set<RoleName> roles = ROLES.getOrDefault(subject, Set.of());
    return () -> List.copyOf(roles);
  }

  @Override
  public HasPermissions permissionsFor(String subject) {
    Set<PermissionName> perms = PERMISSIONS.getOrDefault(subject, Set.of());
    return () -> List.copyOf(perms);
  }
}
