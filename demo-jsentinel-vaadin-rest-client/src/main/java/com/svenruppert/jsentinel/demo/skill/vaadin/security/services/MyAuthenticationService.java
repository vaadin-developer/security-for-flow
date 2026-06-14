package com.svenruppert.jsentinel.demo.skill.vaadin.security.services;

import com.svenruppert.jsentinel.authentication.AuthenticationService;
import com.svenruppert.jsentinel.autoservice.api.JSentinelAutoService;
import com.svenruppert.jsentinel.demo.skill.vaadin.security.RestBackendClient;
import com.svenruppert.jsentinel.demo.skill.vaadin.security.model.Credentials;
import com.svenruppert.jsentinel.demo.skill.vaadin.security.model.User;
import com.svenruppert.jsentinel.demo.skill.vaadin.security.roles.AuthorizationRole;

import java.util.EnumSet;
import java.util.Optional;

/**
 * REST-client AuthenticationService. {@code checkCredentials} hits
 * the backend's {@code /api/auth/login}; on success the token is
 * stored in {@code VaadinSession} (see {@link RestBackendClient}).
 *
 * <p>{@code loadSubject} returns a {@link User} reconstructed from
 * {@code /api/whoami}'s display name; the typed role set is filled
 * by {@code AuthorizationService} when it's queried.
 */
@JSentinelAutoService(AuthenticationService.class)
public class MyAuthenticationService
    implements AuthenticationService<Credentials, User> {

  @Override
  public boolean checkCredentials(Credentials credentials) {
    if (credentials == null) return false;
    return RestBackendClient.login(credentials.username(), credentials.password()).isPresent();
  }

  @Override
  public User loadSubject(Credentials credentials) {
    Optional<String> whoami = RestBackendClient.whoami();
    if (whoami.isEmpty()) return null;
    var fields = RestBackendClient.parseFlat(whoami.get());
    String displayName = fields.getOrDefault("displayName", credentials.username());
    String id = fields.getOrDefault("id", "0");
    // Roles are filled by AuthorizationService when queried; the
    // subject only needs a stable id + name here.
    return new User(parseId(id), displayName, EnumSet.of(AuthorizationRole.USER));
  }

  @Override
  public Class<User> subjectType() {
    return User.class;
  }

  private static Long parseId(String value) {
    try {
      return Long.parseLong(value);
    } catch (NumberFormatException e) {
      return Math.abs((long) value.hashCode());
    }
  }
}
