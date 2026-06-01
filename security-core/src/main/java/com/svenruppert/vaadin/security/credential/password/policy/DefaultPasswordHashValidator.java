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
package com.svenruppert.vaadin.security.credential.password.policy;

import com.svenruppert.vaadin.security.credential.CredentialType;
import com.svenruppert.vaadin.security.credential.password.envelope.PasswordHashEnvelope;
import com.svenruppert.vaadin.security.credential.password.envelope.PasswordHashFormatVersion;

import java.util.Map;
import java.util.Objects;

/**
 * Reference {@link PasswordHashValidator}.
 *
 * <p>Performs the generic, adapter-neutral envelope checks (credential
 * type, format version, algorithm and provider acceptance), then
 * delegates to the algorithm-specific
 * {@link PasswordHashParameterValidator} for parameter bounds.</p>
 */
public final class DefaultPasswordHashValidator implements PasswordHashValidator {

  private final PasswordHashParameterValidatorRegistry registry;

  public DefaultPasswordHashValidator(
      PasswordHashParameterValidatorRegistry registry) {
    this.registry = Objects.requireNonNull(registry, "registry");
  }

  @Override
  public ValidatedPasswordHash validate(
      PasswordHashEnvelope envelope,
      PasswordHashPolicy policy) {
    Objects.requireNonNull(envelope, "envelope");
    Objects.requireNonNull(policy, "policy");

    if (envelope.credentialType() != CredentialType.PASSWORD) {
      throw new PasswordHashValidationException(
          "credential type not supported in Phase 1a");
    }

    PasswordHashFormatVersion preferred = policy.preferredFormatVersion();
    if (envelope.formatVersion().wireValue() > preferred.wireValue()) {
      throw new PasswordHashValidationException(
          "envelope format version is newer than the active policy supports");
    }

    if (!policy.isAlgorithmAcceptable(envelope.algorithm())) {
      throw new PasswordHashValidationException(
          "algorithm is not acceptable under the active policy");
    }
    // Provider acceptability is NOT a verification gate: an old envelope
    // pinned to a provider that is still registered must remain
    // verifiable so the user can log in and the pipeline can rehash to
    // the active policy's preferred provider. Whether the provider is
    // still preferred is decided by the rehash engine, not here.
    if (envelope.policyVersion() > policy.policyVersion()) {
      throw new PasswordHashValidationException(
          "envelope policy version is newer than the active policy");
    }

    PasswordHashParameterValidator paramValidator = registry
        .lookup(envelope.algorithm())
        .orElseThrow(() -> new PasswordHashValidationException(
            "no parameter validator registered for algorithm"));

    Map<String, String> min = policy.minimumParameters(envelope.algorithm());
    Map<String, String> max = policy.maximumParameters(envelope.algorithm());
    paramValidator.validate(envelope.parameters(), min, max);

    return new ValidatedPasswordHash(envelope, policy);
  }
}
