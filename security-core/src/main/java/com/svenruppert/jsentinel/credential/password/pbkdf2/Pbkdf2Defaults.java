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
package com.svenruppert.jsentinel.credential.password.pbkdf2;

import com.svenruppert.jsentinel.credential.password.policy.DefaultPasswordHashPolicy;
import com.svenruppert.jsentinel.credential.password.policy.PasswordHashPolicy;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Phase-1a reference parameters for the PBKDF2 password hashing path.
 *
 * <p>The defaults follow the OWASP 2023 guidance for
 * {@code PBKDF2-HMAC-SHA256}: 600&nbsp;000 iterations, 16 random bytes
 * of salt and a 32-byte derived key. The upper bounds are deliberately
 * generous so that operators can ramp iterations over time, but small
 * enough to keep a single verification under one second on commodity
 * hardware (CWE-400).</p>
 */
public final class Pbkdf2Defaults {

  /** Phase-1a default iteration count. */
  public static final int DEFAULT_ITERATIONS = 600_000;

  /** Phase-1a default salt length in bytes. */
  public static final int DEFAULT_SALT_LENGTH = 16;

  /** Phase-1a default derived-key length in bytes. */
  public static final int DEFAULT_KEY_LENGTH = 32;

  /** Minimum acceptable iteration count for stored hashes. */
  public static final int MIN_ITERATIONS = 210_000;

  /** Maximum iteration count accepted by the validator. */
  public static final int MAX_ITERATIONS = 10_000_000;

  /** Minimum salt length in bytes. */
  public static final int MIN_SALT_LENGTH = 12;

  /** Maximum salt length in bytes. */
  public static final int MAX_SALT_LENGTH = 64;

  /** Minimum derived-key length in bytes. */
  public static final int MIN_KEY_LENGTH = 32;

  /** Maximum derived-key length in bytes. */
  public static final int MAX_KEY_LENGTH = 64;

  private Pbkdf2Defaults() { }

  /**
   * Default parameter map for new PBKDF2 envelopes. The {@code s}
   * parameter is filled in by the provider when a random salt is drawn.
   */
  public static Map<String, String> defaultParameters() {
    Map<String, String> m = new LinkedHashMap<>();
    m.put(Pbkdf2ParameterNames.ITERATIONS, Integer.toString(DEFAULT_ITERATIONS));
    m.put(Pbkdf2ParameterNames.KEY_LENGTH, Integer.toString(DEFAULT_KEY_LENGTH));
    return m;
  }

  /**
   * Minimum-bound parameter map.
   */
  public static Map<String, String> minimumParameters() {
    Map<String, String> m = new LinkedHashMap<>();
    m.put(Pbkdf2ParameterNames.ITERATIONS, Integer.toString(MIN_ITERATIONS));
    m.put(Pbkdf2ParameterNames.KEY_LENGTH, Integer.toString(MIN_KEY_LENGTH));
    m.put(Pbkdf2ParameterNames.SALT_LENGTH, Integer.toString(MIN_SALT_LENGTH));
    return m;
  }

  /**
   * Maximum-bound parameter map.
   */
  public static Map<String, String> maximumParameters() {
    Map<String, String> m = new LinkedHashMap<>();
    m.put(Pbkdf2ParameterNames.ITERATIONS, Integer.toString(MAX_ITERATIONS));
    m.put(Pbkdf2ParameterNames.KEY_LENGTH, Integer.toString(MAX_KEY_LENGTH));
    m.put(Pbkdf2ParameterNames.SALT_LENGTH, Integer.toString(MAX_SALT_LENGTH));
    return m;
  }

  /**
   * Convenience: build a single-algorithm reference policy that emits
   * PBKDF2 envelopes with the Phase-1a defaults.
   */
  public static PasswordHashPolicy referencePolicy() {
    return DefaultPasswordHashPolicy.builder()
        .policyVersion(1)
        .preferredAlgorithm(Pbkdf2ParameterNames.ALGORITHM)
        .preferredProviderId(Pbkdf2ParameterNames.PROVIDER_ID)
        .defaultParameters(Pbkdf2ParameterNames.ALGORITHM, defaultParameters())
        .minimumParameters(Pbkdf2ParameterNames.ALGORITHM, minimumParameters())
        .maximumParameters(Pbkdf2ParameterNames.ALGORITHM, maximumParameters())
        .build();
  }
}
