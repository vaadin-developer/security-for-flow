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
package com.svenruppert.jsentinel.authorization.api;

import com.svenruppert.jsentinel.authorization.api.permissions.HasPermissions;
import com.svenruppert.jsentinel.authorization.api.permissions.PermissionName;
import com.svenruppert.jsentinel.authorization.api.roles.HasRoles;
import com.svenruppert.jsentinel.authorization.api.roles.RoleName;

import java.util.Objects;

/**
 * Stateless permission/role checks. Use {@link #hasPermission} for UI
 * affordances (visibility, enablement) and {@link #requirePermission} as
 * the authoritative server-side guard before mutating actions.
 */
public final class PermissionGuard {

  private PermissionGuard() {
  }

  // ── Permissions ────────────────────────────────────────────────

  public static boolean hasPermission(HasPermissions subject, PermissionName permission) {
    if (subject == null || permission == null) return false;
    return subject.permissionNames().contains(permission);
  }

  public static void requirePermission(HasPermissions subject, PermissionName permission) {
    Objects.requireNonNull(permission, "permission");
    if (!hasPermission(subject, permission)) {
      throw new AccessDeniedException("Missing permission: " + permission.value());
    }
  }

  // ── Roles ──────────────────────────────────────────────────────

  public static boolean hasRole(HasRoles subject, RoleName role) {
    if (subject == null || role == null) return false;
    return subject.roleNames().contains(role);
  }

  public static void requireRole(HasRoles subject, RoleName role) {
    Objects.requireNonNull(role, "role");
    if (!hasRole(subject, role)) {
      throw new AccessDeniedException("Missing role: " + role.value());
    }
  }
}
