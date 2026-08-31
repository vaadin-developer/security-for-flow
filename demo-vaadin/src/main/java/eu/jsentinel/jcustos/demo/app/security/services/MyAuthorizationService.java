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
package eu.jsentinel.jcustos.demo.app.security.services;

import eu.jsentinel.jcustos.authorization.api.AuthorizationService;
import eu.jsentinel.jcustos.autoservice.api.JSentinelAutoService;
import eu.jsentinel.jcustos.authorization.api.permissions.HasPermissions;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.authorization.api.permissions.RolePermissionMapping;
import eu.jsentinel.jcustos.authorization.api.permissions.RolePermissionResolver;
import eu.jsentinel.jcustos.authorization.api.permissions.StaticRolePermissionMapping;
import eu.jsentinel.jcustos.authorization.api.roles.HasRoles;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.demo.app.security.model.MyUser;
import eu.jsentinel.jcustos.demo.app.security.roles.AuthorizationRole;

import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import static eu.jsentinel.jcustos.demo.app.security.permissions.DemoPermission.*;

/**
 * Demo implementation of {@link AuthorizationService}.
 * <p>
 * The role → permission table is expressed as a generic
 * {@link StaticRolePermissionMapping} from {@code security-core}; merging
 * permissions across the user's roles is delegated to
 * {@link RolePermissionResolver}. This keeps the demo free of
 * authorization helper code.
 */
@JSentinelAutoService(AuthorizationService.class)
public class MyAuthorizationService
    implements AuthorizationService<MyUser> {

  private static final RolePermissionMapping ROLE_PERMISSIONS = StaticRolePermissionMapping.builder()
      .put(roleName(AuthorizationRole.ADMIN), Set.of(
          DEMO_VIEW.permissionName(),
          DEMO_EDIT.permissionName(),
          DEMO_ADMIN.permissionName(),
          AUDIT_READ.permissionName(),
          AUDIT_PURGE.permissionName(),
          ADMIN_ROLES.permissionName(),
          ADMIN_SESSIONS.permissionName()))
      .put(roleName(AuthorizationRole.Q_ADMIN), Set.of(
          DEMO_VIEW.permissionName(),
          DEMO_EDIT.permissionName(),
          DEMO_ADMIN.permissionName(),
          AUDIT_READ.permissionName(),
          ADMIN_ROLES.permissionName(),
          ADMIN_SESSIONS.permissionName()))
      .put(roleName(AuthorizationRole.NERD), Set.of(
          DEMO_VIEW.permissionName(),
          DEMO_EDIT.permissionName()))
      .put(roleName(AuthorizationRole.USER), Set.of(DEMO_VIEW.permissionName()))
      .put(roleName(AuthorizationRole.NOBODY), Set.of())
      .build();

  @Override
  public HasRoles rolesFor(MyUser subject) {
    Objects.requireNonNull(subject);
    List<RoleName> roles = subject.roles().stream()
        .map(MyAuthorizationService::roleName)
        .toList();
    return () -> roles;
  }

  @Override
  public HasPermissions permissionsFor(MyUser subject) {
    Objects.requireNonNull(subject);
    Set<RoleName> roles = subject.roles().stream()
        .map(MyAuthorizationService::roleName)
        .collect(Collectors.toSet());
    Set<PermissionName> permissions =
        RolePermissionResolver.permissionsForRoles(roles, ROLE_PERMISSIONS);
    return () -> List.copyOf(permissions);
  }

  private static RoleName roleName(AuthorizationRole role) {
    return new RoleName(role.name());
  }
}
