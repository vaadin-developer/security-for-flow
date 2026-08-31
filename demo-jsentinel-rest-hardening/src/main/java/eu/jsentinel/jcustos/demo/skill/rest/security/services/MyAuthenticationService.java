package eu.jsentinel.jcustos.demo.skill.rest.security.services;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.audit.JSentinelAuditService;
import eu.jsentinel.jcustos.audit.LoginSucceeded;
import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.api.JSentinelServiceResolver;
import eu.jsentinel.jcustos.autoservice.api.JSentinelAutoService;
import eu.jsentinel.jcustos.demo.skill.rest.security.model.Credentials;
import eu.jsentinel.jcustos.demo.skill.rest.security.model.User;
import eu.jsentinel.jcustos.demo.skill.rest.security.model.UserDirectoryProvider;

import java.time.Clock;
import java.time.Instant;

/**
 * REST-side AuthenticationService — same shape as the Vaadin skill,
 * minus the {@code VaadinRequest.getCurrent()} client-address lookup
 * (the REST handlers pass the address explicitly via the audit hook).
 */
@JSentinelAutoService(AuthenticationService.class)
public class MyAuthenticationService
    implements AuthenticationService<Credentials, User>, HasLogger {

  @Override
  public boolean checkCredentials(Credentials credentials) {
    if (credentials == null) {
      return false;
    }
    boolean ok = UserDirectoryProvider.directory().checkCredentials(credentials);
    if (ok) {
      auditLoginSucceeded(credentials.username());
    }
    return ok;
  }

  @Override
  public User loadSubject(Credentials credentials) {
    return UserDirectoryProvider.directory().findByCredentials(credentials).orElse(null);
  }

  @Override
  public Class<User> subjectType() {
    return User.class;
  }

  private static void auditLoginSucceeded(String username) {
    JSentinelAuditService sink = JSentinelServiceResolver.securityAuditService();
    try {
      sink.publish(new LoginSucceeded(
          Instant.now(Clock.systemUTC()), username, null, null));
    } catch (RuntimeException ignored) {
      // never block a successful login because the audit sink failed
    }
  }
}
