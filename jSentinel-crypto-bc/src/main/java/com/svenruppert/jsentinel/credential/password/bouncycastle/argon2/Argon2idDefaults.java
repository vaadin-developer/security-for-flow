/*-
 * #%L
 * Security Crypto — BouncyCastle
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
package com.svenruppert.jsentinel.credential.password.bouncycastle.argon2;

import com.svenruppert.jsentinel.credential.password.policy.DefaultPasswordHashPolicy;
import com.svenruppert.jsentinel.credential.password.policy.PasswordHashPolicy;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Reference parameters for the Phase-1b Argon2id password hashing path.
 *
 * <p>Defaults follow OWASP 2023 / RFC&nbsp;9106 guidance for
 * interactive logins:</p>
 * <ul>
 *   <li>{@code t} = 3 iterations</li>
 *   <li>{@code m} = 65&nbsp;536 KiB (64&nbsp;MiB)</li>
 *   <li>{@code p} = 1 lane</li>
 *   <li>{@code l} = 32-byte derived key</li>
 *   <li>16-byte random salt</li>
 * </ul>
 *
 * <p>Upper bounds are deliberately tight on memory (max 1&nbsp;GiB) so
 * a single verification cannot exhaust process memory (CWE-400 /
 * CWE-770).</p>
 */
public final class Argon2idDefaults {

  public static final int DEFAULT_ITERATIONS = 3;
  public static final int DEFAULT_MEMORY_KIB = 65_536;
  public static final int DEFAULT_PARALLELISM = 1;
  public static final int DEFAULT_HASH_LENGTH = 32;
  public static final int DEFAULT_SALT_LENGTH = 16;

  public static final int MIN_ITERATIONS = 1;
  public static final int MAX_ITERATIONS = 10;
  public static final int MIN_MEMORY_KIB = 8_192;     //  8 MiB
  public static final int MAX_MEMORY_KIB = 1_048_576; //  1 GiB
  public static final int MIN_PARALLELISM = 1;
  public static final int MAX_PARALLELISM = 8;
  public static final int MIN_HASH_LENGTH = 16;
  public static final int MAX_HASH_LENGTH = 64;
  public static final int MIN_SALT_LENGTH = 12;
  public static final int MAX_SALT_LENGTH = 64;

  private Argon2idDefaults() { }

  public static Map<String, String> defaultParameters() {
    Map<String, String> m = new LinkedHashMap<>();
    m.put(Argon2idParameterNames.ITERATIONS, Integer.toString(DEFAULT_ITERATIONS));
    m.put(Argon2idParameterNames.MEMORY_KIB, Integer.toString(DEFAULT_MEMORY_KIB));
    m.put(Argon2idParameterNames.PARALLELISM, Integer.toString(DEFAULT_PARALLELISM));
    m.put(Argon2idParameterNames.HASH_LENGTH, Integer.toString(DEFAULT_HASH_LENGTH));
    return m;
  }

  public static Map<String, String> minimumParameters() {
    Map<String, String> m = new LinkedHashMap<>();
    m.put(Argon2idParameterNames.ITERATIONS, Integer.toString(MIN_ITERATIONS));
    m.put(Argon2idParameterNames.MEMORY_KIB, Integer.toString(MIN_MEMORY_KIB));
    m.put(Argon2idParameterNames.PARALLELISM, Integer.toString(MIN_PARALLELISM));
    m.put(Argon2idParameterNames.HASH_LENGTH, Integer.toString(MIN_HASH_LENGTH));
    m.put(Argon2idParameterNames.SALT_LENGTH, Integer.toString(MIN_SALT_LENGTH));
    return m;
  }

  public static Map<String, String> maximumParameters() {
    Map<String, String> m = new LinkedHashMap<>();
    m.put(Argon2idParameterNames.ITERATIONS, Integer.toString(MAX_ITERATIONS));
    m.put(Argon2idParameterNames.MEMORY_KIB, Integer.toString(MAX_MEMORY_KIB));
    m.put(Argon2idParameterNames.PARALLELISM, Integer.toString(MAX_PARALLELISM));
    m.put(Argon2idParameterNames.HASH_LENGTH, Integer.toString(MAX_HASH_LENGTH));
    m.put(Argon2idParameterNames.SALT_LENGTH, Integer.toString(MAX_SALT_LENGTH));
    return m;
  }

  /**
   * Single-algorithm reference policy that emits Argon2id envelopes
   * under the Phase-1b defaults.
   */
  public static PasswordHashPolicy referencePolicy() {
    return DefaultPasswordHashPolicy.builder()
        .policyVersion(1)
        .preferredAlgorithm(Argon2idParameterNames.ALGORITHM)
        .preferredProviderId(Argon2idParameterNames.PROVIDER_ID)
        .defaultParameters(Argon2idParameterNames.ALGORITHM, defaultParameters())
        .minimumParameters(Argon2idParameterNames.ALGORITHM, minimumParameters())
        .maximumParameters(Argon2idParameterNames.ALGORITHM, maximumParameters())
        .build();
  }
}
