package eu.jsentinel.jcustos.demo.skill.vaadin.security.services;

import eu.jsentinel.jcustos.authorization.api.AuthorizationService;
import eu.jsentinel.jcustos.authorization.api.permissions.HasPermissions;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.authorization.api.permissions.RolePermissionMapping;
import eu.jsentinel.jcustos.authorization.api.permissions.RolePermissionResolver;
import eu.jsentinel.jcustos.authorization.api.permissions.StaticRolePermissionMapping;
import eu.jsentinel.jcustos.authorization.api.roles.HasRoles;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.autoservice.api.JSentinelAutoService;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.User;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.roles.AuthorizationRole;

import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import static eu.jsentinel.jcustos.demo.skill.vaadin.security.permissions.AppPermission.*;

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
          APP_VIEW.permissionName(),
          AUDIT_READ.permissionName(),
          ADMIN_SESSIONS.permissionName(),
          ADMIN_ROLES.permissionName()))
      .put(roleName(AuthorizationRole.USER), Set.of(
          APP_VIEW.permissionName()))
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
