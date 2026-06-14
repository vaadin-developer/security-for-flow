package com.svenruppert.jsentinel.demo.skill.vaadin.views;

import com.svenruppert.dependencies.core.logger.HasLogger;
import com.svenruppert.jsentinel.authentication.AuthenticationService;
import com.svenruppert.jsentinel.authorization.LoginView;
import com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver;
import com.svenruppert.jsentinel.authorization.api.SubjectStores;
import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import com.svenruppert.jsentinel.logout.SubjectId;
import com.svenruppert.jsentinel.session.JSentinelVersion;
import com.svenruppert.jsentinel.session.SessionId;
import com.svenruppert.jsentinel.session.SessionRecord;
import com.svenruppert.jsentinel.session.SessionStatus;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.server.VaadinSession;
import com.vaadin.flow.server.WrappedSession;
import com.svenruppert.jsentinel.demo.skill.vaadin.security.model.Credentials;
import com.svenruppert.jsentinel.demo.skill.vaadin.security.model.User;
import com.svenruppert.jsentinel.demo.skill.vaadin.security.model.UserDirectoryProvider;
import com.svenruppert.jsentinel.demo.skill.vaadin.security.services.SessionStoreProvider;

import java.time.Clock;
import java.time.Instant;

import static com.svenruppert.jsentinel.demo.skill.vaadin.views.MyLoginView.NAV;

/**
 * Login route. Extends the framework's pre-built form
 * ({@code username / password / remember-me / sign-in}); the four
 * overrides wire credential validation, post-login navigation, and
 * failure handling.
 */
@Route(NAV)
public class MyLoginView
    extends LoginView
    implements HasLogger {

  public static final String NAV = "login";

  private final AuthenticationService<Credentials, User> authenticationService
      = JSentinelServiceResolver.authenticationService();

  @Override
  public boolean checkCredentials() {
    Credentials credentials = new Credentials(username(), password());
    boolean ok = authenticationService.checkCredentials(credentials);
    if (ok) {
      UserDirectoryProvider.directory().findByCredentials(credentials).ifPresent(user -> {
        SubjectStores.subjectStore().setCurrentSubject(user, User.class);
        recordSession(user);
      });
    }
    return ok;
  }

  @Override
  public void reactOnFailedLogin() {
    logger().info("Login rejected — invalid credentials");
    Notification.show("Credentials not accepted.");
  }

  @Override
  public void navigateToApp() {
    UI.getCurrent().navigate(DashboardView.class);
  }

  /**
   * Records a {@link SessionRecord} so the {@code /admin/sessions} view
   * has something to render. Best-effort: missing Vaadin session,
   * missing session id, or any failure is swallowed — session
   * bookkeeping must not block login.
   */
  private static void recordSession(User user) {
    try {
      VaadinSession vaadin = VaadinSession.getCurrent();
      if (vaadin == null) return;
      WrappedSession wrapped = vaadin.getSession();
      String sessionId = wrapped == null ? null : wrapped.getId();
      if (sessionId == null) return;
      Instant now = Instant.now(Clock.systemUTC());
      SessionStoreProvider.sessionStore().save(new SessionRecord(
          SessionId.of(sessionId),
          SubjectId.of(user.id().toString()),
          TenantId.DEFAULT,
          now, now,
          JSentinelVersion.INITIAL,
          SessionStatus.ACTIVE));
    } catch (RuntimeException ignored) {
      // session bookkeeping must not block login
    }
  }
}
