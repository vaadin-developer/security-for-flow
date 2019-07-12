package org.rapidpm.vaadin.security.authorization.api;

import org.rapidpm.vaadin.ServiceProvider;

public class AuthorizationServiceProvider<U>
    implements ServiceProvider<AuthorizationService<U>> {
  @Override
  public AuthorizationService<U> load() {
    return ServiceProvider.<AuthorizationService>loadService().apply(AuthorizationService.class);
  }
}
