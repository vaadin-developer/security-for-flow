/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package com.svenruppert.jsentinel.dx.rest.bootstrap;

import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Static holder that publishes the active
 * {@link RestCorsConfiguration} for downstream REST glue (a servlet
 * filter, embedded server, etc.) to consume. Single-use bootstrap
 * → a second {@code publish(...)} replaces the previous value.
 *
 * @since 00.74.00
 */
public final class RestCorsContext {

  private static final AtomicReference<RestCorsConfiguration> CONFIG = new AtomicReference<>();

  private RestCorsContext() {
    throw new AssertionError("no instances");
  }

  /**
   * Publishes the active CORS configuration.
   *
   * @param config the configuration; non-null
   */
  public static void publish(RestCorsConfiguration config) {
    CONFIG.set(Objects.requireNonNull(config, "config"));
  }

  /** @return the active CORS configuration, if any */
  public static Optional<RestCorsConfiguration> configuration() {
    return Optional.ofNullable(CONFIG.get());
  }

  /** Test helper: resets the holder. */
  public static void reset() {
    CONFIG.set(null);
  }
}
