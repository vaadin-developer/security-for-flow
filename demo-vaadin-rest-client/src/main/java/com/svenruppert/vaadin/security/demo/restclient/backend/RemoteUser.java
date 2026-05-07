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
package com.svenruppert.vaadin.security.demo.restclient.backend;

import com.svenruppert.vaadin.security.authorization.api.permissions.HasPermissions;
import com.svenruppert.vaadin.security.authorization.api.permissions.PermissionName;
import com.svenruppert.vaadin.security.authorization.api.roles.HasRoles;
import com.svenruppert.vaadin.security.authorization.api.roles.RoleName;

import java.util.Collection;
import java.util.Set;

/**
 * Snapshot of the authenticated user as returned by the backend's
 * {@code GET /api/me}.
 * <p>
 * Carries roles + permissions so the Vaadin UI can drive
 * {@code AuthorizationListener} and {@code PermissionGuard} locally
 * without round-tripping for every UI decision. The server remains
 * authoritative for mutating actions — see {@code BackendOperationCard}.
 */
public record RemoteUser(
    String subjectId,
    String displayName,
    Set<RoleName> roles,
    Set<PermissionName> permissions
) implements HasRoles, HasPermissions {

  public RemoteUser {
    if (subjectId == null || subjectId.isBlank()) {
      throw new IllegalArgumentException("subjectId must not be blank");
    }
    displayName = displayName == null ? subjectId : displayName;
    roles = Set.copyOf(roles);
    permissions = Set.copyOf(permissions);
  }

  @Override
  public Collection<RoleName> roleNames() {
    return roles;
  }

  @Override
  public Collection<PermissionName> permissionNames() {
    return permissions;
  }
}
