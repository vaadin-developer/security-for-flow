package com.svenruppert.jsentinel.demo.skill.rest.security.services;

import com.svenruppert.jsentinel.authorization.api.AuthorizationService;
import com.svenruppert.jsentinel.authorization.api.permissions.HasPermissions;
import com.svenruppert.jsentinel.authorization.api.permissions.PermissionName;
import com.svenruppert.jsentinel.authorization.api.permissions.RolePermissionMapping;
import com.svenruppert.jsentinel.authorization.api.permissions.RolePermissionResolver;
import com.svenruppert.jsentinel.authorization.api.permissions.StaticRolePermissionMapping;
import com.svenruppert.jsentinel.authorization.api.roles.HasRoles;
import com.svenruppert.jsentinel.authorization.api.roles.RoleName;
import com.svenruppert.jsentinel.autoservice.api.JSentinelAutoService;
import com.svenruppert.jsentinel.demo.skill.rest.security.model.User;
import com.svenruppert.jsentinel.demo.skill.rest.security.roles.AuthorizationRole;

import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import static com.svenruppert.jsentinel.demo.skill.rest.security.permissions.AppPermission.*;

/**
 * Role → permission table. SPI-registered via
 * {@link JSentinelAutoService @JSentinelAutoService}.
 *
 * <ul>
 *   <li>ADMIN: every permission</li>
 *   <li>USER: just app:view</li>
 * </ul>
 *
 * <p>Subject's effective permission set = union of every role's
 * permissions (delegated to {@link RolePermissionResolver}).
 */
@JSentinelAutoService(AuthorizationService.class)
public class MyAuthorizationService
    implements AuthorizationService<User> {

  private static final RolePermissionMapping ROLE_PERMISSIONS = StaticRolePermissionMapping.builder()
      .put(roleName(AuthorizationRole.ADMIN), Set.of(
          API_VIEW.permissionName(),
          AUDIT_READ.permissionName(),
          ADMIN_SESSIONS.permissionName(),
          ADMIN_ROLES.permissionName()))
      .put(roleName(AuthorizationRole.USER), Set.of(
          API_VIEW.permissionName()))
      .build();

  @Override
  public HasRoles rolesFor(User subject) {
    Objects.requireNonNull(subject);
    List<RoleName> roles = subject.roles().stream()
        .map(MyAuthorizationService::roleName)
        .toList();
    return () -> roles;
  }

  @Override
  public HasPermissions permissionsFor(User subject) {
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
