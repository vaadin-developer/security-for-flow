/*-
 * #%L
 * Security Core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or – as soon they will be
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

package eu.jsentinel.jcustos.credential.password;


import eu.jsentinel.jcustos.credential.CredentialType;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable result of a password-hashing operation.
 *
 * <p>Carries everything required to round-trip the produced credential
 * back through the verification pipeline without further policy lookups:
 * the encoded envelope plus the discriminating metadata that was used to
 * build it.</p>
 *
 * <p>The {@link #toString()} implementation never exposes
 * {@link #encodedHash()} or any KDF parameter values; only the
 * non-sensitive shape is printed. The encoded envelope itself contains
 * salt and inner hash material and must be treated as a credential
 * derivative.</p>
 *
 * @param encodedHash     self-describing envelope, never {@code null} or blank
 * @param credentialType  credential discriminator, always
 *                        {@link CredentialType#PASSWORD} in Phase 1a
 * @param formatVersion   envelope format version that produced this result
 * @param algorithm       canonical algorithm identifier, e.g.
 *                        {@code "PBKDF2WithHmacSHA256"}
 * @param providerId      logical provider identifier, e.g. {@code "pbkdf2-jdk"}
 * @param policyVersion   policy version in force when the hash was produced
 * @param pepperKeyId     optional pepper-key identifier; absent for the
 *                        Phase-1a {@code NoOpPepperService}
 * @param parameters      defensive copy of the algorithm parameters that
 *                        were applied (e.g. iteration count, salt length);
 *                        never {@code null}, may be empty
 */
public record PasswordHashResult(
    String encodedHash,
    CredentialType credentialType,
    int formatVersion,
    String algorithm,
    String providerId,
    int policyVersion,
    Optional<String> pepperKeyId,
    Map<String, String> parameters
) {

  public PasswordHashResult {
    Objects.requireNonNull(encodedHash, "encodedHash");
    if (encodedHash.isBlank()) {
      throw new IllegalArgumentException("encodedHash must not be blank");
    }
    Objects.requireNonNull(credentialType, "credentialType");
    if (formatVersion < 1) {
      throw new IllegalArgumentException("formatVersion must be >= 1");
    }
    Objects.requireNonNull(algorithm, "algorithm");
    if (algorithm.isBlank()) {
      throw new IllegalArgumentException("algorithm must not be blank");
    }
    Objects.requireNonNull(providerId, "providerId");
    if (providerId.isBlank()) {
      throw new IllegalArgumentException("providerId must not be blank");
    }
    if (policyVersion < 1) {
      throw new IllegalArgumentException("policyVersion must be >= 1");
    }
    Objects.requireNonNull(pepperKeyId, "pepperKeyId");
    Objects.requireNonNull(parameters, "parameters");
    parameters = Collections.unmodifiableMap(new LinkedHashMap<>(parameters));
  }

  @Override
  public String toString() {
    return "PasswordHashResult["
        + "credentialType=" + credentialType
        + ", formatVersion=" + formatVersion
        + ", algorithm=" + algorithm
        + ", providerId=" + providerId
        + ", policyVersion=" + policyVersion
        + ", pepperKeyId=" + (pepperKeyId.isPresent() ? "<present>" : "<absent>")
        + ", parameterKeys=" + parameters.keySet()
        + ", encodedHash=<redacted>"
        + "]";
  }
}
