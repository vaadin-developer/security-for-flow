package org.rapidpm.vaadin.security.authorization.api;

import org.rapidpm.vaadin.ServiceProvider;

public class AuthenticationServiceProvider
    implements ServiceProvider<AuthenticationService> {
  @Override
  public AuthenticationService load() {
    return ServiceProvider.<AuthenticationService>loadService().apply(AuthenticationService.class);
  }
}
