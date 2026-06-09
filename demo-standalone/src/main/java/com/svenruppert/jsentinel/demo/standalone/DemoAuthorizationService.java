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
package com.svenruppert.jsentinel.demo.standalone;

import com.svenruppert.jsentinel.authorization.api.AuthorizationService;
import com.svenruppert.jsentinel.autoservice.api.JSentinelAutoService;
import com.svenruppert.jsentinel.authorization.api.permissions.HasPermissions;
import com.svenruppert.jsentinel.authorization.api.permissions.PermissionName;
import com.svenruppert.jsentinel.authorization.api.permissions.RolePermissionResolver;
import com.svenruppert.jsentinel.authorization.api.permissions.StaticRolePermissionMapping;
import com.svenruppert.jsentinel.authorization.api.roles.HasRoles;
import com.svenruppert.jsentinel.authorization.api.roles.RoleName;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static com.svenruppert.jsentinel.demo.standalone.Permission.BOOK_ADD;
import static com.svenruppert.jsentinel.demo.standalone.Permission.BOOK_BORROW;
import static com.svenruppert.jsentinel.demo.standalone.Permission.BOOK_LIST;
import static com.svenruppert.jsentinel.demo.standalone.Permission.BOOK_REMOVE;
import static com.svenruppert.jsentinel.demo.standalone.Permission.BOOK_RETURN;
import static com.svenruppert.jsentinel.demo.standalone.Permission.MEMBER_ADD;
import static com.svenruppert.jsentinel.demo.standalone.Permission.MEMBER_AUDIT_LOG;
import static com.svenruppert.jsentinel.demo.standalone.Permission.MEMBER_INVITE;
import static com.svenruppert.jsentinel.demo.standalone.Permission.MEMBER_LIST;
import static com.svenruppert.jsentinel.demo.standalone.Permission.MEMBER_REMOVE;

@JSentinelAutoService(AuthorizationService.class)
public final class DemoAuthorizationService implements AuthorizationService<User> {

  private static final StaticRolePermissionMapping ROLE_PERMISSIONS =
      StaticRolePermissionMapping.builder()
          .put(Role.ADMIN.roleName(), Set.of(
              BOOK_LIST.permissionName(),
              BOOK_BORROW.permissionName(),
              BOOK_RETURN.permissionName(),
              BOOK_ADD.permissionName(),
              BOOK_REMOVE.permissionName(),
              MEMBER_LIST.permissionName(),
              MEMBER_ADD.permissionName(),
              MEMBER_INVITE.permissionName(),
              MEMBER_REMOVE.permissionName(),
              MEMBER_AUDIT_LOG.permissionName()))
          .put(Role.LIBRARIAN.roleName(), Set.of(
              BOOK_LIST.permissionName(),
              BOOK_BORROW.permissionName(),
              BOOK_RETURN.permissionName(),
              BOOK_ADD.permissionName(),
              MEMBER_LIST.permissionName(),
              MEMBER_INVITE.permissionName()))
          .put(Role.MEMBER.roleName(), Set.of(
              BOOK_LIST.permissionName(),
              BOOK_BORROW.permissionName(),
              BOOK_RETURN.permissionName(),
              MEMBER_LIST.permissionName()))
          .build();

  @Override
  public HasRoles rolesFor(User subject) {
    List<RoleName> roles = subject.roles().stream()
        .map(Role::roleName)
        .toList();
    return () -> roles;
  }

  @Override
  public HasPermissions permissionsFor(User subject) {
    Set<RoleName> roles = subject.roles().stream()
        .map(Role::roleName)
        .collect(Collectors.toSet());
    Set<PermissionName> permissions =
        RolePermissionResolver.permissionsForRoles(roles, ROLE_PERMISSIONS);
    return () -> List.copyOf(permissions);
  }
}
