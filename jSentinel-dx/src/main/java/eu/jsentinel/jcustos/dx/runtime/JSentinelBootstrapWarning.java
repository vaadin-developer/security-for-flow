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
package eu.jsentinel.jcustos.dx.runtime;

import java.util.Objects;

/**
 * One diagnostic entry produced by the fluent bootstrap or by
 * {@code JSentinelDiagnostics.inspect()}.
 *
 * @param severity     informational severity level
 * @param code         stable diagnostic code (e.g. {@code "missing-authentication-service"});
 *                     callers may pattern-match on this for tooling
 * @param message      human-readable description; must not contain secrets
 * @param suggestedFix concrete fix recommendation; must not contain secrets
 *
 * @since 00.72.00
 * @apiNote V00.73 — promoted to stable. Diagnostic codes have a stable
 *          namespace (see RELEASE-NOTES-00.73.00.md §13.1 / §13.2).
 */
public record JSentinelBootstrapWarning(
    Severity severity,
    String code,
    String message,
    String suggestedFix) {

  public JSentinelBootstrapWarning {
    Objects.requireNonNull(severity, "severity");
    Objects.requireNonNull(code, "code");
    Objects.requireNonNull(message, "message");
    Objects.requireNonNull(suggestedFix, "suggestedFix");
  }
}
