package eu.jsentinel.jcustos.demo.skill.standalone.security.services;

import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.autoservice.api.JSentinelAutoService;
import eu.jsentinel.jcustos.demo.skill.standalone.security.model.Credentials;
import eu.jsentinel.jcustos.demo.skill.standalone.security.model.User;
import eu.jsentinel.jcustos.demo.skill.standalone.security.model.UserDirectoryProvider;

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
