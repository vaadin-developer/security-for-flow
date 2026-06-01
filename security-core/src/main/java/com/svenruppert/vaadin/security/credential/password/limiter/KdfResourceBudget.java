/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * http://ec.europa.eu/idabc/eupl5
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */
package com.svenruppert.vaadin.security.credential.password.limiter;

import java.time.Duration;
import java.util.Objects;

/**
 * Resource budget for the {@link KdfExecutionLimiter}.
 *
 * <p>Phase 1a only spends the {@code maxConcurrent} and {@code maxWait}
 * fields; memory-hard providers (Phase 1b) consume the same budget to
 * enforce process-wide concurrency limits for Argon2id / scrypt.</p>
 *
 * @param maxConcurrent  cap on parallel KDF invocations
 * @param maxWait        how long a caller blocks waiting for a permit
 *                       before the limiter rejects
 */
public record KdfResourceBudget(int maxConcurrent, Duration maxWait) {

  public KdfResourceBudget {
    Objects.requireNonNull(maxWait, "maxWait");
    if (maxConcurrent < 1) {
      throw new IllegalArgumentException("maxConcurrent must be >= 1");
    }
    if (maxWait.isNegative()) {
      throw new IllegalArgumentException("maxWait must not be negative");
    }
  }

  /**
   * Sensible default for Phase 1a: 16 concurrent verifications, with up
   * to 250&nbsp;ms blocking on a permit before the limiter rejects.
   */
  public static KdfResourceBudget defaults() {
    return new KdfResourceBudget(16, Duration.ofMillis(250));
  }
}
