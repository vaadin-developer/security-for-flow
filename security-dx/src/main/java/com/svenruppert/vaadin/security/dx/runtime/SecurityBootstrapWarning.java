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
package com.svenruppert.vaadin.security.dx.runtime;

import com.svenruppert.vaadin.security.authorization.api.ExperimentalSecurityApi;

import java.util.Objects;

/**
 * One diagnostic entry produced by the V00.72 fluent bootstrap or by
 * {@code SecurityDiagnostics.inspect()}.
 *
 * @param severity     informational severity level
 * @param code         stable diagnostic code (e.g. {@code "missing-authentication-service"});
 *                     callers may pattern-match on this for tooling
 * @param message      human-readable description; must not contain secrets
 * @param suggestedFix concrete fix recommendation; must not contain secrets
 *
 * @since 00.72.00
 */
@ExperimentalSecurityApi
public record SecurityBootstrapWarning(
    Severity severity,
    String code,
    String message,
    String suggestedFix) {

  public SecurityBootstrapWarning {
    Objects.requireNonNull(severity, "severity");
    Objects.requireNonNull(code, "code");
    Objects.requireNonNull(message, "message");
    Objects.requireNonNull(suggestedFix, "suggestedFix");
  }
}
