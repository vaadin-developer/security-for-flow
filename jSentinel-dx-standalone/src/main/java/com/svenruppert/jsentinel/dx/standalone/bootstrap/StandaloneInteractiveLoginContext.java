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
package com.svenruppert.jsentinel.dx.standalone.bootstrap;

import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Static holder that publishes the active
 * {@link InteractiveLoginConfiguration}. CLI / desktop applications
 * consume it to drive their own login loop with the configured
 * prompt and attempt cap.
 *
 * @since 00.74.00
 */
public final class StandaloneInteractiveLoginContext {

  private static final AtomicReference<InteractiveLoginConfiguration> CONFIG = new AtomicReference<>();

  private StandaloneInteractiveLoginContext() {
    throw new AssertionError("no instances");
  }

  /**
   * Publishes the active configuration.
   *
   * <p>R06 (V00.76.10): this holder is <strong>process-global</strong> (one per
   * JVM). Re-publishing an equal configuration is idempotent; publishing a
   * different one while one is already active throws rather than silently
   * overwriting (the multi-app-in-one-JVM hazard). Run one bootstrap per JVM or
   * call {@link #reset()} between intentional re-inits.
   *
   * @param configuration non-null configuration
   * @throws IllegalStateException if a different configuration is already published
   */
  public static void publish(InteractiveLoginConfiguration configuration) {
    Objects.requireNonNull(configuration, "configuration");
    InteractiveLoginConfiguration existing = CONFIG.get();
    if (existing != null && !existing.equals(configuration)) {
      throw new IllegalStateException(
          "StandaloneInteractiveLoginContext already holds a different configuration. "
              + "This holder is process-global (one per JVM); use one bootstrap per "
              + "JVM, or call reset() between intentional re-inits.");
    }
    CONFIG.set(configuration);
  }

  /** @return the active configuration, if any */
  public static Optional<InteractiveLoginConfiguration> configuration() {
    return Optional.ofNullable(CONFIG.get());
  }

  /** Test helper: clears the holder. */
  public static void reset() {
    CONFIG.set(null);
  }
}
