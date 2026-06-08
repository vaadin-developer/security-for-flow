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
package com.svenruppert.vaadin.security.dx.bootstrap;

import com.svenruppert.vaadin.security.authorization.api.ExperimentalSecurityApi;
import com.svenruppert.vaadin.security.dx.runtime.SecurityBootstrapWarning;

import java.util.List;
import java.util.Objects;

/**
 * Thrown by an adapter facade's {@code install()} in
 * {@code SecurityBootstrapMode.STRICT} when one or more critical SPIs are
 * missing. The exception carries the same {@link SecurityBootstrapWarning}
 * entries that would have appeared on a {@code SecurityRuntime} in
 * {@code PRODUCTION} mode.
 *
 * @since 00.72.00
 */
@ExperimentalSecurityApi
public final class SecurityBootstrapException extends RuntimeException {

  private static final long serialVersionUID = 1L;

  private final List<SecurityBootstrapWarning> warnings;

  public SecurityBootstrapException(List<SecurityBootstrapWarning> warnings) {
    super(buildMessage(warnings));
    this.warnings = List.copyOf(Objects.requireNonNull(warnings, "warnings"));
  }

  public List<SecurityBootstrapWarning> warnings() {
    return warnings;
  }

  private static String buildMessage(List<SecurityBootstrapWarning> warnings) {
    if (warnings == null || warnings.isEmpty()) {
      return "Security bootstrap failed (no warnings recorded).";
    }
    StringBuilder sb = new StringBuilder("Security bootstrap failed:");
    for (SecurityBootstrapWarning w : warnings) {
      sb.append("\n - [").append(w.code()).append("] ").append(w.message());
    }
    return sb.toString();
  }
}
