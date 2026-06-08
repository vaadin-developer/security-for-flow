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
package com.svenruppert.vaadin.security.dx.diagnostics;

import com.svenruppert.vaadin.security.authorization.api.ExperimentalSecurityApi;

import java.util.Objects;

/**
 * A diagnostic warning surfaced through {@link SecurityServiceReport}.
 *
 * @since 00.72.00
 */
@ExperimentalSecurityApi
public record ServiceWarning(String code, String message, String suggestedFix) {

  public ServiceWarning {
    Objects.requireNonNull(code, "code");
    Objects.requireNonNull(message, "message");
    Objects.requireNonNull(suggestedFix, "suggestedFix");
  }
}
