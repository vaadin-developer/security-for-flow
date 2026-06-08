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
 */
@ExperimentalSecurityApi
public record SecurityRuntime(
    List<RegisteredSecurityService> services,
    List<SecurityBootstrapWarning> warnings,
    SecurityBootstrapMode mode) {

  public SecurityRuntime {
    Objects.requireNonNull(services, "services");
    Objects.requireNonNull(warnings, "warnings");
    Objects.requireNonNull(mode, "mode");
    services = List.copyOf(services);
    warnings = List.copyOf(warnings);
  }
}
