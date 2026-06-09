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
package com.svenruppert.jsentinel.dx.diagnostics;


import java.util.Objects;

/**
 * A single SPI implementation discovered by
 * {@link JSentinelDiagnostics#inspect()}.
 *
 * @param spi         the SPI contract
 * @param impl        the discovered implementation class
 * @param classLoader the loader's {@code toString()} for traceability
 *
 * @since 00.72.00
 */
public record DiscoveredService(Class<?> spi, Class<?> impl, String classLoader) {

  public DiscoveredService {
    Objects.requireNonNull(spi, "spi");
    Objects.requireNonNull(impl, "impl");
    Objects.requireNonNull(classLoader, "classLoader");
  }
}
