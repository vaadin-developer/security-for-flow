package org.rapidpm.vaadin.security.authorization.api;

import org.rapidpm.vaadin.ServiceProvider;

public class AccessEvaluatorProvider
    implements ServiceProvider<AccessEvaluator> {
  @Override
  public AccessEvaluator load() {
    return ServiceProvider.<AccessEvaluator>loadService().apply(AccessEvaluator.class);
  }
}

