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
package eu.jsentinel.jcustos.starter.profile;

import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapMode;

/** Strict profile — mode STRICT; missing critical SPIs raise JCustosBootstrapException. */
public final class StrictDefaults implements VaadinJCustosStarter {

  static final StrictDefaults INSTANCE = new StrictDefaults();

  private StrictDefaults() {
  }

  @Override
  public JCustosBootstrapMode preferredMode() {
    return JCustosBootstrapMode.STRICT;
  }
}
