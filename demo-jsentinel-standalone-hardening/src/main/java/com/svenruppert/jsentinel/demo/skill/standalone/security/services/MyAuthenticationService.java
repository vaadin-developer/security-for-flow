package com.svenruppert.jsentinel.demo.skill.standalone.security.services;

import com.svenruppert.jsentinel.authentication.AuthenticationService;
import com.svenruppert.jsentinel.autoservice.api.JSentinelAutoService;
import com.svenruppert.jsentinel.demo.skill.standalone.security.model.Credentials;
import com.svenruppert.jsentinel.demo.skill.standalone.security.model.User;
import com.svenruppert.jsentinel.demo.skill.standalone.security.model.UserDirectoryProvider;

/**
 * Standalone AuthenticationService — same shape as the Vaadin /
 * REST skills minus the request-bound client address.
 */
@JSentinelAutoService(AuthenticationService.class)
public class MyAuthenticationService
    implements AuthenticationService<Credentials, User> {

  @Override
  public boolean checkCredentials(Credentials credentials) {
    return credentials != null
        && UserDirectoryProvider.directory().checkCredentials(credentials);
  }

  @Override
  public User loadSubject(Credentials credentials) {
    return UserDirectoryProvider.directory().findByCredentials(credentials).orElse(null);
  }

  @Override
  public Class<User> subjectType() {
    return User.class;
  }
}
