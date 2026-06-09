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
package com.svenruppert.vaadin.security.autoservice.api;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Compile-time marker that triggers {@code security-autoservice-processor}
 * to generate the corresponding {@code META-INF/services/<spi-fqn>}
 * entries for the annotated class.
 * <p>
 * <strong>Retention:</strong> {@link RetentionPolicy#SOURCE}. The
 * annotation leaves no class-file or runtime trace.
 * <p>
 * <strong>Wiring:</strong> add this module as a regular compile
 * dependency, and add {@code security-autoservice-processor} to the
 * {@code maven-compiler-plugin}'s {@code <annotationProcessorPaths>}.
 *
 * <h2>Example</h2>
 * <pre>{@code
 *   @JSentinelAutoService(AuthenticationService.class)
 *   public final class DemoAuthenticationService
 *       implements AuthenticationService<Credentials, DemoUser> {
 *     // ...
 *   }
 * }</pre>
 *
 * @since 00.72.00
 */
@Retention(RetentionPolicy.SOURCE)
@Target(ElementType.TYPE)
public @interface JSentinelAutoService {

  /**
   * One or more SPI contracts that the annotated class implements.
   *
   * @return the SPI types this implementation registers under
   */
  Class<?>[] value();
}
