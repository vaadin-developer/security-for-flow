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
package com.svenruppert.vaadin.security.credential.password.provider;

/**
 * Coarse resource estimate produced by a {@link PasswordHashProvider}
 * for a given parameter set.
 *
 * <p>Phase-1a providers may return zeros; the type becomes meaningful
 * with the Phase-1b memory-hard algorithms (Argon2id, scrypt) where the
 * KDF execution limiter uses the estimate to enforce a process-wide
 * resource budget (CWE-400).</p>
 *
 * @param estimatedCpuTimeMicros approximate wall time the verification
 *                               will spend in the KDF
 * @param estimatedMemoryBytes   approximate peak memory the KDF holds
 *                               at once
 */
public record ResourceEstimate(
    long estimatedCpuTimeMicros,
    long estimatedMemoryBytes
) {

  public static final ResourceEstimate UNKNOWN = new ResourceEstimate(0L, 0L);

  public ResourceEstimate {
    if (estimatedCpuTimeMicros < 0L) {
      throw new IllegalArgumentException(
          "estimatedCpuTimeMicros must be >= 0");
    }
    if (estimatedMemoryBytes < 0L) {
      throw new IllegalArgumentException(
          "estimatedMemoryBytes must be >= 0");
    }
  }
}
