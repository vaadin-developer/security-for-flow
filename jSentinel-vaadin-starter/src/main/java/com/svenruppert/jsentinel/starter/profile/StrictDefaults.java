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
package com.svenruppert.jsentinel.starter.profile;

import com.svenruppert.jsentinel.dx.runtime.JSentinelBootstrapMode;

/** Strict profile — mode STRICT; missing critical SPIs raise JSentinelBootstrapException. */
public final class StrictDefaults implements VaadinJSentinelStarter {

  static final StrictDefaults INSTANCE = new StrictDefaults();

  private StrictDefaults() {
  }

  @Override
  public JSentinelBootstrapMode preferredMode() {
    return JSentinelBootstrapMode.STRICT;
  }
}
