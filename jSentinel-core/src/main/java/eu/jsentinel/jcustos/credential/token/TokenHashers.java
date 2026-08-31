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
package eu.jsentinel.jcustos.credential.token;

import eu.jsentinel.jcustos.authentication.PasswordHasher;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;

import java.util.Objects;

/**
 * Factory helpers for {@link TokenHasher}.
 *
 * @since 00.75.10
 */
@ExperimentalJSentinelApi
public final class TokenHashers {

  private static final char[] DETERMINISM_PROBE =
      "jSentinel-token-hasher-determinism-probe".toCharArray();

  private TokenHashers() {
  }

  /**
   * Adapts a legacy {@link PasswordHasher} to a {@link TokenHasher} for the
   * deprecated constructor paths, guarding against the dangerous mistake that
   * motivated {@code TokenHasher}: the adapter hashes a fixed probe twice at
   * construction and rejects any hasher whose output is non-deterministic (a
   * random-salt KDF), which could never be looked up by value.
   *
   * @param delegate a deterministic password hasher (e.g. a SHA-256 token
   *                 hasher); a salted KDF is rejected
   * @return a {@link TokenHasher} delegating to {@code delegate}
   * @throws IllegalArgumentException if {@code delegate.hash(...)} is
   *                                  non-deterministic
   */
  public static TokenHasher fromPasswordHasher(PasswordHasher delegate) {
    Objects.requireNonNull(delegate, "delegate must not be null");
    String first = delegate.hash(DETERMINISM_PROBE.clone());
    String second = delegate.hash(DETERMINISM_PROBE.clone());
    if (!Objects.equals(first, second)) {
      throw new IllegalArgumentException(
          "A token service requires a deterministic hasher, but the supplied "
              + delegate.getClass().getSimpleName() + " is salted (its hash() is "
              + "non-deterministic) and cannot be looked up by value. Use a "
              + "TokenHasher such as Sha256TokenHasher.");
    }
    return delegate::hash;
  }
}
