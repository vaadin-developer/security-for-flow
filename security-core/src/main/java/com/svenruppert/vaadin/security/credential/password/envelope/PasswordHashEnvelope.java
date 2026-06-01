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
package com.svenruppert.vaadin.security.credential.password.envelope;

import com.svenruppert.vaadin.security.credential.CredentialType;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Parsed view of a self-describing password-hash envelope.
 *
 * <p>The record carries only metadata required to round-trip a stored
 * credential back through the verification pipeline: the format and
 * policy versions, the credential type discriminator, the algorithm and
 * provider identifiers, the optional pepper key id, the algorithm
 * parameters and the inner-hash payload.</p>
 *
 * <p>This type performs <em>no</em> cryptographic work, no policy
 * validation, no algorithm strength assessment and no provider
 * resolution. Those concerns live in later Phase-1a layers.</p>
 *
 * <p>The {@link #toString()} implementation deliberately omits the
 * inner-hash payload and every parameter value; only the structural
 * skeleton is printed.</p>
 *
 * @param formatVersion  envelope wire format
 * @param credentialType always {@link CredentialType#PASSWORD} in Phase 1a
 * @param algorithm      canonical algorithm identifier, e.g.
 *                       {@code "PBKDF2WithHmacSHA256"}
 * @param providerId     logical provider identifier, e.g.
 *                       {@code "pbkdf2-jdk"}
 * @param policyVersion  policy version recorded at encode time
 * @param pepperKeyId    optional pepper key identifier; absent for the
 *                       Phase-1a {@code NoOpPepperService}
 * @param parameters     defensive copy of algorithm-specific parameter
 *                       names and values (e.g. {@code i}, {@code s})
 * @param innerHash      opaque payload produced by the provider, never
 *                       interpreted by the codec
 */
public record PasswordHashEnvelope(
    PasswordHashFormatVersion formatVersion,
    CredentialType credentialType,
    String algorithm,
    String providerId,
    int policyVersion,
    Optional<String> pepperKeyId,
    Map<String, String> parameters,
    String innerHash
) {

  public PasswordHashEnvelope {
    Objects.requireNonNull(formatVersion, "formatVersion");
    Objects.requireNonNull(credentialType, "credentialType");
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
    Objects.requireNonNull(innerHash, "innerHash");
    if (innerHash.isBlank()) {
      throw new IllegalArgumentException("innerHash must not be blank");
    }
  }

  @Override
  public String toString() {
    return "PasswordHashEnvelope["
        + "formatVersion=" + formatVersion
        + ", credentialType=" + credentialType
        + ", algorithm=" + algorithm
        + ", providerId=" + providerId
        + ", policyVersion=" + policyVersion
        + ", pepperKeyId=" + (pepperKeyId.isPresent() ? "<present>" : "<absent>")
        + ", parameterKeys=" + parameters.keySet()
        + ", innerHash=<redacted>"
        + "]";
  }
}
