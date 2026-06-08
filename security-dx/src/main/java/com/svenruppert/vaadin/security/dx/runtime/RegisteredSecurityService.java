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
 * One service registered through the V00.72 fluent bootstrap or discovered
 * by {@code SecurityDiagnostics}.
 *
 * @param spi       the SPI contract this implementation satisfies
 * @param impl      the concrete implementation class
 * @param source    where the registration came from: {@code "bootstrap-explicit"},
 *                  {@code "bootstrap-default"}, {@code "@SecurityAutoService"},
 *                  {@code "manual"}, etc. Free-form but should use stable strings.
 * @param defaulted {@code true} if this entry was applied as a default
 *                  by the bootstrap (not requested explicitly)
 *
 * @since 00.72.00
 */
@ExperimentalSecurityApi
public record RegisteredSecurityService(
    Class<?> spi,
    Class<?> impl,
    String source,
    boolean defaulted) {

  public RegisteredSecurityService {
    Objects.requireNonNull(spi, "spi");
    Objects.requireNonNull(impl, "impl");
    Objects.requireNonNull(source, "source");
  }
}
