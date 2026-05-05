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
package com.svenruppert.vaadin.security.demo.rest;

import com.svenruppert.vaadin.security.authorization.api.permissions.PermissionName;
import com.svenruppert.vaadin.security.authorization.api.permissions.RolePermissionMapping;
import com.svenruppert.vaadin.security.authorization.api.roles.RoleName;

import java.util.Set;

import static com.svenruppert.vaadin.security.demo.rest.DemoPermission.*;

/**
 * Demo role-permission mapping.
 */
public final class DemoRolePermissionMapping implements RolePermissionMapping {

  @Override
  public Set<PermissionName> permissionsFor(RoleName role) {
    return switch (DemoRole.valueOf(role.value())) {
      case ROLE_ADMIN -> Set.of(
          DOCUMENT_READ.permissionName(),
          DOCUMENT_CREATE.permissionName(),
          DOCUMENT_UPDATE.permissionName(),
          DOCUMENT_DELETE.permissionName(),
          ADMIN_ACCESS.permissionName());
      case ROLE_EDITOR -> Set.of(
          DOCUMENT_READ.permissionName(),
          DOCUMENT_CREATE.permissionName(),
          DOCUMENT_UPDATE.permissionName());
      case ROLE_VIEWER -> Set.of(DOCUMENT_READ.permissionName());
    };
  }
}
