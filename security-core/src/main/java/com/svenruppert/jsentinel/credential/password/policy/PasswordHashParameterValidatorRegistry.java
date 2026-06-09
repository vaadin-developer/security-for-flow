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
package com.svenruppert.jsentinel.credential.password.policy;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Lookup of {@link PasswordHashParameterValidator}s by algorithm
 * identifier.
 *
 * <p>The registry is mutable on construction (via the constructor that
 * takes a pre-assembled list) and immutable thereafter. Phase 1a uses a
 * deterministic, ServiceLoader-free wiring: callers register the
 * PBKDF2 validator explicitly. Later phases may replace this with a
 * ServiceLoader-backed implementation.</p>
 */
public final class PasswordHashParameterValidatorRegistry {

  private final Map<String, PasswordHashParameterValidator> byAlgorithm;

  public PasswordHashParameterValidatorRegistry(
      Collection<? extends PasswordHashParameterValidator> validators) {
    Objects.requireNonNull(validators, "validators");
    Map<String, PasswordHashParameterValidator> map = new LinkedHashMap<>();
    for (PasswordHashParameterValidator v : validators) {
      Objects.requireNonNull(v, "validator");
      Objects.requireNonNull(v.algorithm(), "validator.algorithm()");
      if (v.algorithm().isBlank()) {
        throw new IllegalArgumentException(
            "validator algorithm must not be blank");
      }
      if (map.put(v.algorithm(), v) != null) {
        throw new IllegalArgumentException(
            "duplicate parameter validator for algorithm");
      }
    }
    this.byAlgorithm = Collections.unmodifiableMap(map);
  }

  /**
   * Looks up the validator that handles the given algorithm identifier.
   */
  public Optional<PasswordHashParameterValidator> lookup(String algorithm) {
    Objects.requireNonNull(algorithm, "algorithm");
    return Optional.ofNullable(byAlgorithm.get(algorithm));
  }

  /**
   * Returns the algorithm identifiers known to this registry.
   */
  public java.util.Set<String> knownAlgorithms() {
    return byAlgorithm.keySet();
  }
}
