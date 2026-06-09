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
package com.svenruppert.jsentinel.credential.password.limiter;

import java.util.Optional;

/**
 * Bounds the number of KDF invocations that may run concurrently.
 *
 * <p>The limiter applies uniformly to the real and dummy verification
 * paths. Rejection is observable internally (as
 * {@code VERIFICATION_REJECTED_KDF_LIMIT}) but never as a separate
 * public signal &mdash; the verification pipeline maps it to the
 * generic {@code INVALID_CREDENTIALS} response (CWE-203, CWE-400).</p>
 */
public interface KdfExecutionLimiter {

  /**
   * Tries to acquire a KDF permit. Blocks up to
   * {@link KdfResourceBudget#maxWait()} before giving up.
   *
   * @return an {@link Lease} that must be released, or
   *         {@link Optional#empty()} when the limiter refused
   */
  Optional<Lease> acquire();

  /**
   * Permit handle. Always closed with try-with-resources.
   */
  interface Lease extends AutoCloseable {
    @Override
    void close();
  }
}
