package com.svenruppert.jsentinel.demo.skill.vaadin.security.services;

import com.svenruppert.jsentinel.authorization.api.AuthorizationService;
import com.svenruppert.jsentinel.authorization.api.permissions.HasPermissions;
import com.svenruppert.jsentinel.authorization.api.permissions.PermissionName;
import com.svenruppert.jsentinel.authorization.api.roles.HasRoles;
import com.svenruppert.jsentinel.authorization.api.roles.RoleName;
import com.svenruppert.jsentinel.autoservice.api.JSentinelAutoService;
import com.svenruppert.jsentinel.demo.skill.vaadin.security.RestBackendClient;
import com.svenruppert.jsentinel.demo.skill.vaadin.security.model.User;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * REST-client AuthorizationService. Roles + permissions come from
 * {@code /api/whoami}. The {@link User} argument is ignored — the
 * backend uses the Bearer token to identify the caller.
 *
 * <p>The {@code whoami} payload looks like
 * {@code {"id":"...","displayName":"...","roles":["ADMIN","USER"],"permissions":["app:view",...]}}.
 * The parser only needs the two arrays.
 */
@JSentinelAutoService(AuthorizationService.class)
public class MyAuthorizationService
    implements AuthorizationService<User> {

  private static final Pattern ARRAY = Pattern.compile(
      "\"(roles|permissions)\"\\s*:\\s*\\[([^]]*)]");

  @Override
  public HasRoles rolesFor(User subject) {
    List<RoleName> roles = extract("roles").stream().map(RoleName::new).toList();
    return () -> roles;
  }

  @Override
  public HasPermissions permissionsFor(User subject) {
    List<PermissionName> permissions = extract("permissions").stream()
        .map(PermissionName::new)
        .toList();
    return () -> permissions;
  }

  private static List<String> extract(String key) {
    return RestBackendClient.whoami()
        .map(body -> parseArray(body, key))
        .orElse(List.of());
  }

  private static List<String> parseArray(String body, String key) {
    Matcher m = ARRAY.matcher(body);
    while (m.find()) {
      if (key.equals(m.group(1))) {
        String items = m.group(2);
        if (items.isBlank()) return List.of();
        return java.util.Arrays.stream(items.split(","))
            .map(String::trim)
            .map(s -> s.startsWith("\"") && s.endsWith("\"")
                ? s.substring(1, s.length() - 1)
                : s)
            .toList();
      }
    }
    return List.of();
  }
}
