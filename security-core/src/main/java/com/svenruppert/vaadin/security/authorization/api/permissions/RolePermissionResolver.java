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

import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

/**
 * Merges role-to-permission lookups for a set of roles.
 */
public final class RolePermissionResolver {

  private RolePermissionResolver() {
  }

  public static Set<PermissionName> permissionsForRoles(
      Set<RoleName> roles,
      RolePermissionMapping mapping) {
    Objects.requireNonNull(roles, "roles");
    Objects.requireNonNull(mapping, "mapping");
    Set<PermissionName> result = new LinkedHashSet<>();
    for (RoleName role : roles) {
      result.addAll(mapping.permissionsFor(role));
    }
    return Set.copyOf(result);
  }
}
