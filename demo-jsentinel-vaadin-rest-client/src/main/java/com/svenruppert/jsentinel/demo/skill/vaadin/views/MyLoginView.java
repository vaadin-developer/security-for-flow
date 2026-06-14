package com.svenruppert.jsentinel.demo.skill.vaadin.views;

import com.svenruppert.dependencies.core.logger.HasLogger;
import com.svenruppert.jsentinel.authentication.AuthenticationService;
import com.svenruppert.jsentinel.authorization.LoginView;
import com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver;
import com.svenruppert.jsentinel.authorization.api.SubjectStores;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.router.Route;
import com.svenruppert.jsentinel.demo.skill.vaadin.security.model.Credentials;
import com.svenruppert.jsentinel.demo.skill.vaadin.security.model.User;

@Route(MyLoginView.NAV)
public class MyLoginView extends LoginView implements HasLogger {
  public static final String NAV = "login";

  @Override
  public boolean checkCredentials() {
    Credentials credentials = new Credentials(username(), password());
    AuthenticationService<Credentials, User> authn =
        JSentinelServiceResolver.authenticationService();
    boolean ok = authn.checkCredentials(credentials);
    if (ok) {
      User user = authn.loadSubject(credentials);
      if (user != null) {
        SubjectStores.subjectStore().setCurrentSubject(user, User.class);
      }
    }
    return ok;
  }

  @Override
  public void reactOnFailedLogin() {
    Notification.show("Credentials not accepted.");
  }

  @Override
  public void navigateToApp() {
    UI.getCurrent().navigate(DashboardView.class);
  }
}
