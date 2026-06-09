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
package com.svenruppert.jsentinel.demo.rest.domain;

import com.svenruppert.jsentinel.authorization.api.permissions.PermissionName;
import com.svenruppert.jsentinel.authorization.api.permissions.RolePermissionMapping;
import com.svenruppert.jsentinel.authorization.api.permissions.StaticRolePermissionMapping;
import com.svenruppert.jsentinel.authorization.api.roles.RoleName;

import java.util.Set;

import static com.svenruppert.jsentinel.demo.rest.domain.DemoPermission.*;

/**
 * Demo role-to-permission mapping. Implemented as a thin wrapper around
 * {@link StaticRolePermissionMapping} so the demo only carries the data,
 * not the merge/lookup logic.
 */
public final class DemoRolePermissionMapping implements RolePermissionMapping {

  private final StaticRolePermissionMapping delegate = StaticRolePermissionMapping.builder()
      .put(DemoRole.ROLE_ADMIN.roleName(), Set.of(
          DOCUMENT_READ.permissionName(),
          DOCUMENT_CREATE.permissionName(),
          DOCUMENT_UPDATE.permissionName(),
          DOCUMENT_DELETE.permissionName(),
          ADMIN_ACCESS.permissionName(),
          AUDIT_READ.permissionName(),
          ADMIN_ROLES.permissionName()))
      .put(DemoRole.ROLE_EDITOR.roleName(), Set.of(
          DOCUMENT_READ.permissionName(),
          DOCUMENT_CREATE.permissionName(),
          DOCUMENT_UPDATE.permissionName()))
      .put(DemoRole.ROLE_VIEWER.roleName(), Set.of(DOCUMENT_READ.permissionName()))
      .build();

  @Override
  public Set<PermissionName> permissionsFor(RoleName role) {
    return delegate.permissionsFor(role);
  }
}
