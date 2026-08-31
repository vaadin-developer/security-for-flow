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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;

/**
 * Deterministic digest for high-entropy tokens (refresh / reset /
 * email-verification / API-key tokens) that are stored hashed and later looked
 * up by that hash.
 *
 * <p>Same input <strong>must</strong> produce the same output — there is
 * <strong>no</strong> per-call salt. A random-salt password KDF (e.g.
 * {@code Pbkdf2PasswordHasher}, Argon2id) produces a different hash on every
 * call, so it cannot be looked up by value and <strong>must not</strong>
 * implement this contract (CWE-208 / CWE-640). This is the type-level
 * counterpart to the comment-only guarantee the token services relied on before
 * V00.75.10.
 *
 * <p>{@link Sha256TokenHasher} is the shipped default. The token itself carries
 * the entropy ({@code SecureRandom}, ≥ 32 bytes), so a plain unkeyed digest is
 * unforgeable without the token.
 *
 * @since 00.75.10
 */
@ExperimentalJSentinelApi
public interface TokenHasher {

  /**
   * Hashes a high-entropy token deterministically.
   *
   * @param token the raw token characters; the implementation must not retain
   *              them
   * @return a stable, lookup-safe digest of the token
   */
  String hash(char[] token);
}
