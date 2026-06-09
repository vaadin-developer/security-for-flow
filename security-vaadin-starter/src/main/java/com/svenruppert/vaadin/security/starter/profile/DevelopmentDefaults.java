/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package com.svenruppert.vaadin.security.starter.profile;

import com.svenruppert.vaadin.security.dx.runtime.SecurityBootstrapMode;

/** Development profile — verbose diagnostics, DEVELOPMENT mode default. */
public final class DevelopmentDefaults implements VaadinSecurityStarter {

  static final DevelopmentDefaults INSTANCE = new DevelopmentDefaults();

  private DevelopmentDefaults() {
  }

  @Override
  public SecurityBootstrapMode preferredMode() {
    return SecurityBootstrapMode.DEVELOPMENT;
  }
}
