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
package com.svenruppert.vaadin.security.demo.app.security.services;

import com.svenruppert.vaadin.security.demo.app.security.model.MyUser;
import com.svenruppert.vaadin.security.authorization.api.AuthorizationService;
import com.svenruppert.vaadin.security.authorization.api.permissions.HasPermissions;
import com.svenruppert.vaadin.security.authorization.api.permissions.PermissionName;
import com.svenruppert.vaadin.security.authorization.api.roles.HasRoles;
import com.svenruppert.vaadin.security.authorization.api.roles.RoleName;
import com.svenruppert.vaadin.security.demo.app.security.roles.AuthorizationRole;

import java.util.Set;
import java.util.Objects;

import static com.svenruppert.vaadin.security.demo.app.security.permissions.DemoPermission.*;

/**
 * Demo implementation of {@link AuthorizationService}.
 * <p>
 * Provides role-based authorization and demo-only permissions for UI examples.
 */
public class MyAuthorizationService
    implements AuthorizationService<MyUser> {

  @Override
  public HasRoles rolesFor(MyUser subject) {
    Objects.requireNonNull(subject);
    return () -> subject.roles()
                        .stream()
                        .map(r -> new RoleName(r.name()))
                        .toList();
  }

  @Override
  public HasPermissions permissionsFor(MyUser subject) {
    Objects.requireNonNull(subject);
    return () -> subject.roles()
        .stream()
        .flatMap(role -> permissionsFor(role).stream())
        .toList();
  }

  private Set<PermissionName> permissionsFor(AuthorizationRole role) {
    return switch (role) {
      case ADMIN, Q_ADMIN -> Set.of(
          DEMO_VIEW.permissionName(),
          DEMO_EDIT.permissionName(),
          DEMO_ADMIN.permissionName());
      case NERD -> Set.of(DEMO_VIEW.permissionName(), DEMO_EDIT.permissionName());
      case USER -> Set.of(DEMO_VIEW.permissionName());
      case NOBODY -> Set.of();
    };
  }
}
