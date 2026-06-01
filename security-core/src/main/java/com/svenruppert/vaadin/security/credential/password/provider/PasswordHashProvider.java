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

import com.svenruppert.vaadin.security.credential.password.PasswordHashResult;
import com.svenruppert.vaadin.security.credential.password.ProviderVerificationResult;
import com.svenruppert.vaadin.security.credential.password.envelope.PasswordHashEnvelope;
import com.svenruppert.vaadin.security.credential.password.policy.PasswordHashPolicy;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Service-provider contract for a concrete password hashing
 * implementation.
 *
 * <p>Providers are discovered through Java's {@link java.util.ServiceLoader}
 * or registered explicitly by the bootstrap layer. Phase 1a ships a
 * single PBKDF2 provider in {@code security-core}; the optional
 * {@code security-crypto-bc} module adds Argon2id, bcrypt and scrypt.</p>
 *
 * <p>Providers must <strong>not</strong>:</p>
 * <ul>
 *   <li>change the global JCA provider order through
 *       {@code Security.insertProviderAt} or equivalent;</li>
 *   <li>log password material, derived key material or secret salts;</li>
 *   <li>throw on a genuine credential mismatch &mdash; return
 *       {@link ProviderVerificationResult.NotMatched} instead.</li>
 * </ul>
 *
 * <p>Pepper material is threaded through as an {@link Optional} byte
 * array; Phase 1a always supplies {@link Optional#empty()} (the
 * {@code NoOpPepperService}).</p>
 */
public interface PasswordHashProvider {

  /**
   * Logical provider identifier, stable across releases. Stored in the
   * envelope so that verification can resolve the same implementation
   * regardless of the active policy.
   */
  String providerId();

  /**
   * Canonical algorithm identifier this provider handles by default.
   */
  String algorithm();

  /**
   * Returns whether this provider can serve the given combination. The
   * default implementation requires an exact match on both identifiers;
   * providers that handle multiple algorithms or migration aliases
   * override this.
   */
  default boolean supports(String providerId, String algorithm) {
    Objects.requireNonNull(providerId, "providerId");
    Objects.requireNonNull(algorithm, "algorithm");
    return providerId().equals(providerId) && algorithm().equals(algorithm);
  }

  /**
   * Derives a fresh hash for the supplied password under the active
   * policy.
   *
   * @param password      caller-owned character array; the provider
   *                      must <em>not</em> zero or modify it
   * @param policy        active policy from which to read parameters
   * @param pepperSecret  pepper material to mix in post-KDF; Phase 1a
   *                      supplies {@link Optional#empty()}
   */
  PasswordHashResult hash(
      char[] password,
      PasswordHashPolicy policy,
      Optional<byte[]> pepperSecret);

  /**
   * Verifies the supplied password against the parsed envelope.
   *
   * <p>Implementations must use a constant-time comparison and must
   * never throw on a genuine mismatch. Provider-level failures (missing
   * JCA service, unsupported parameter combination) collapse onto
   * {@link ProviderVerificationResult.ProviderError} so the pipeline can
   * keep public messaging generic.</p>
   */
  ProviderVerificationResult verify(
      char[] password,
      PasswordHashEnvelope envelope,
      Optional<byte[]> pepperSecret);

  /**
   * Optional resource estimate for the supplied parameter map. Default:
   * {@link ResourceEstimate#UNKNOWN}.
   */
  default ResourceEstimate resourceEstimate(Map<String, String> parameters) {
    Objects.requireNonNull(parameters, "parameters");
    return ResourceEstimate.UNKNOWN;
  }
}
