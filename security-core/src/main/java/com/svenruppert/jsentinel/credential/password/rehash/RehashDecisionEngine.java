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
package com.svenruppert.jsentinel.credential.password.rehash;

import com.svenruppert.jsentinel.credential.password.RehashDecision;
import com.svenruppert.jsentinel.credential.password.RehashReason;
import com.svenruppert.jsentinel.credential.password.envelope.PasswordHashEnvelope;
import com.svenruppert.jsentinel.credential.password.policy.PasswordHashPolicy;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Computes whether a successfully verified envelope must be
 * transparently rehashed under the active policy.
 *
 * <p>Reasons are evaluated in a deterministic precedence so two
 * verifications of the same envelope under the same policy always
 * yield the same {@link RehashReason}.</p>
 */
public final class RehashDecisionEngine {

  public RehashDecisionEngine() {
    // intentionally trivial
  }

  /**
   * Legacy two-argument overload that ignores pepper rotation.
   * Equivalent to calling {@link #decide(PasswordHashEnvelope,
   * PasswordHashPolicy, Optional)} with {@link Optional#empty()}.
   */
  public RehashDecision decide(
      PasswordHashEnvelope envelope, PasswordHashPolicy policy) {
    return decide(envelope, policy, Optional.empty());
  }

  /**
   * @param envelope            parsed envelope that the provider just
   *                            verified
   * @param policy              active policy
   * @param activePepperKeyId   currently active pepper key id, or
   *                            {@link Optional#empty()} when peppering
   *                            is disabled. A mismatch with the
   *                            envelope's pepper key id triggers
   *                            {@link RehashReason#PEPPER_KEY_ROTATED}.
   */
  public RehashDecision decide(
      PasswordHashEnvelope envelope,
      PasswordHashPolicy policy,
      Optional<String> activePepperKeyId) {
    Objects.requireNonNull(envelope, "envelope");
    Objects.requireNonNull(policy, "policy");
    Objects.requireNonNull(activePepperKeyId, "activePepperKeyId");

    if (!envelope.algorithm().equals(policy.preferredAlgorithm())) {
      return new RehashDecision.Required(
          RehashReason.ALGORITHM_DEPRECATED, policy.policyVersion());
    }
    if (!envelope.providerId().equals(policy.preferredProviderId())) {
      return new RehashDecision.Required(
          RehashReason.PROVIDER_DEPRECATED, policy.policyVersion());
    }
    if (envelope.formatVersion().wireValue()
        < policy.preferredFormatVersion().wireValue()) {
      return new RehashDecision.Required(
          RehashReason.FORMAT_VERSION_OUTDATED, policy.policyVersion());
    }
    if (envelope.policyVersion() < policy.policyVersion()) {
      return new RehashDecision.Required(
          RehashReason.POLICY_VERSION_OUTDATED, policy.policyVersion());
    }
    if (parametersBelowDefaults(envelope, policy)) {
      return new RehashDecision.Required(
          RehashReason.PARAMETERS_OUTDATED, policy.policyVersion());
    }
    if (!envelope.pepperKeyId().equals(activePepperKeyId)) {
      return new RehashDecision.Required(
          RehashReason.PEPPER_KEY_ROTATED, policy.policyVersion());
    }
    return RehashDecision.NotRequired.INSTANCE;
  }

  private static boolean parametersBelowDefaults(
      PasswordHashEnvelope envelope, PasswordHashPolicy policy) {
    Map<String, String> defaults;
    try {
      defaults = policy.defaultParameters(envelope.algorithm());
    } catch (RuntimeException e) {
      return false;
    }
    for (Map.Entry<String, String> e : defaults.entrySet()) {
      String envValue = envelope.parameters().get(e.getKey());
      if (envValue == null) {
        return true;
      }
      Integer defaultInt = tryInt(e.getValue());
      Integer envInt = tryInt(envValue);
      if (defaultInt != null && envInt != null && envInt < defaultInt) {
        return true;
      }
    }
    return false;
  }

  private static Integer tryInt(String raw) {
    if (raw == null) {
      return null;
    }
    try {
      return Integer.parseInt(raw);
    } catch (NumberFormatException e) {
      return null;
    }
  }
}
