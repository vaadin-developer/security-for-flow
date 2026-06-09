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

import java.util.List;
import java.util.Objects;

/**
 * Result object returned by every adapter facade's {@code install()} call.
 * Lists every service the bootstrap registered, every diagnostic warning
 * the run accumulated and the operating mode that produced it.
 * <p>
 * Both {@link #services()} and {@link #warnings()} are unmodifiable.
 *
 * @since 00.72.00
 * @apiNote V00.73 — promoted to stable. Record shape and accessor set
 *          are unchanged since V00.72; additions remain non-breaking
 *          (record components cannot be removed without a SemVer bump).
 */
public record JSentinelRuntime(
    List<RegisteredJSentinelService> services,
    List<JSentinelBootstrapWarning> warnings,
    JSentinelBootstrapMode mode) {

  public JSentinelRuntime {
    Objects.requireNonNull(services, "services");
    Objects.requireNonNull(warnings, "warnings");
    Objects.requireNonNull(mode, "mode");
    services = List.copyOf(services);
    warnings = List.copyOf(warnings);
  }

  /**
   * Renders this runtime as a multiline human-readable string suitable
   * for logging at application startup. Contains only metadata
   * (SPI/impl class names, warning codes); never includes credentials,
   * tokens, pepper key material or anything user-supplied beyond the
   * stable {@code source} strings.
   *
   * @return non-null multiline string ending with a final newline
   */
  public String log() {
    StringBuilder sb = new StringBuilder();
    sb.append("Security bootstrap diagnostics:\n");
    sb.append(" - mode = ").append(mode).append('\n');
    if (services.isEmpty()) {
      sb.append(" - services: (none)\n");
    } else {
      sb.append(" - services:\n");
      for (RegisteredJSentinelService s : services) {
        sb.append("    * ").append(s.spi().getSimpleName())
            .append(": ").append(s.impl().getName())
            .append(" (").append(s.source());
        if (s.defaulted()) {
          sb.append(", default");
        }
        sb.append(")\n");
      }
    }
    sb.append(" - Warnings: ").append(warnings.size()).append('\n');
    for (JSentinelBootstrapWarning w : warnings) {
      sb.append("    * [").append(w.severity()).append("] ")
          .append(w.code()).append(": ").append(w.message()).append('\n');
    }
    return sb.toString();
  }
}
