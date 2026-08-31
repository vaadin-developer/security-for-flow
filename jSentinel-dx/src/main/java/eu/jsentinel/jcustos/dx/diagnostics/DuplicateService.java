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
package eu.jsentinel.jcustos.dx.diagnostics;


import java.util.List;
import java.util.Objects;

/**
 * Multiple implementations registered for the same SPI without an
 * explicit selection.
 *
 * @since 00.72.00
 */
public record DuplicateService(Class<?> spi, List<Class<?>> impls) {

  public DuplicateService {
    Objects.requireNonNull(spi, "spi");
    Objects.requireNonNull(impls, "impls");
    impls = List.copyOf(impls);
  }
}
