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
package com.svenruppert.vaadin.security.demo.restclient.views;

import com.svenruppert.dependencies.core.logger.HasLogger;
import com.svenruppert.vaadin.security.authorization.LoginView;
import com.svenruppert.vaadin.security.authentication.AuthenticationService;
import com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver;
import com.svenruppert.vaadin.security.demo.restclient.backend.BackendClientProvider;
import com.svenruppert.vaadin.security.demo.restclient.backend.Credentials;
import com.svenruppert.vaadin.security.demo.restclient.backend.RemoteUser;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.router.BeforeEnterEvent;
import com.vaadin.flow.router.BeforeEnterObserver;
import com.vaadin.flow.router.Route;

@Route(MyLoginView.NAV)
public class MyLoginView extends LoginView implements HasLogger, BeforeEnterObserver {

  public static final String NAV = "login";

  private final AuthenticationService<Credentials, RemoteUser> authenticationService =
      SecurityServiceResolver.authenticationService();

  @Override
  public void beforeEnter(BeforeEnterEvent event) {
    // If the backend has not yet been initialised, redirect to /setup.
    try {
      if (BackendClientProvider.client().bootstrapStatus().bootstrapRequired()) {
        event.forwardTo(SetupView.class);
      }
    } catch (RuntimeException ex) {
      // Backend unreachable — let the user try to log in; the form will
      // surface the transport error on submit.
    }
  }

  @Override
  public boolean checkCredentials() {
    Credentials credentials = new Credentials(username(), password());
    boolean ok = authenticationService.checkCredentials(credentials);
    if (!ok) return false;
    // RestBackedAuthenticationService already cached the RemoteUser via
    // ClientSecurityContext / SubjectStore, so no extra step here.
    return true;
  }

  @Override
  public void reactOnFailedLogin() {
    logger().info("Login failed for user {}", username());
    Notification.show("Credentials not accepted.");
  }

  @Override
  public void navigateToApp() {
    UI.getCurrent().navigate(MainView.class);
  }
}
