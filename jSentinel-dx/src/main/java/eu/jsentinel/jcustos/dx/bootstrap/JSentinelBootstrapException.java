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
package eu.jsentinel.jcustos.dx.bootstrap;

import eu.jsentinel.jcustos.dx.runtime.JSentinelBootstrapWarning;

import java.util.List;
import java.util.Objects;

/**
 * Thrown by an adapter facade's {@code install()} in
 * {@code JSentinelBootstrapMode.STRICT} when one or more critical SPIs are
 * missing. The exception carries the same {@link JSentinelBootstrapWarning}
 * entries that would have appeared on a {@code JSentinelRuntime} in
 * {@code PRODUCTION} mode.
 *
 * @since 00.72.00
 * @apiNote V00.73 — promoted to stable. The carried warning list is
 *          unmodifiable and identical in shape to {@code JSentinelRuntime.warnings()}.
 */
public final class JSentinelBootstrapException extends RuntimeException {

  private static final long serialVersionUID = 1L;

  private final List<JSentinelBootstrapWarning> warnings;

  public JSentinelBootstrapException(List<JSentinelBootstrapWarning> warnings) {
    super(buildMessage(warnings));
    this.warnings = List.copyOf(Objects.requireNonNull(warnings, "warnings"));
  }

  public List<JSentinelBootstrapWarning> warnings() {
    return warnings;
  }

  private static String buildMessage(List<JSentinelBootstrapWarning> warnings) {
    if (warnings == null || warnings.isEmpty()) {
      return "Security bootstrap failed (no warnings recorded).";
    }
    StringBuilder sb = new StringBuilder("Security bootstrap failed:");
    for (JSentinelBootstrapWarning w : warnings) {
      sb.append("\n - [").append(w.code()).append("] ").append(w.message());
    }
    return sb.toString();
  }
}
