package org.rapidpm.vaadin.security.authorization;

import org.rapidpm.vaadin.ServiceProvider;

public class LoginListenerProvider
    implements ServiceProvider<LoginListener> {
  @Override
  public LoginListener load() {
    return ServiceProvider.<LoginListener>loadService().apply(LoginListener.class);
  }
}
