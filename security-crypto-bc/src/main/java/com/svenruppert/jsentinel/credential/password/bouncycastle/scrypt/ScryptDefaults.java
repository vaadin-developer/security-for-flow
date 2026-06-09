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
package com.svenruppert.jsentinel.credential.password.bouncycastle.scrypt;

import com.svenruppert.jsentinel.credential.password.policy.DefaultPasswordHashPolicy;
import com.svenruppert.jsentinel.credential.password.policy.PasswordHashPolicy;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Phase-1b reference parameters for the scrypt password hashing path.
 *
 * <p>Defaults follow OWASP 2023 guidance for interactive logins:</p>
 * <ul>
 *   <li>N = 2^15 = 32&nbsp;768 (CPU/memory cost)</li>
 *   <li>r = 8 (block size; standard)</li>
 *   <li>p = 1 (parallelism)</li>
 *   <li>l = 32-byte derived key</li>
 *   <li>16-byte random salt</li>
 * </ul>
 *
 * <p>Memory consumed by a single verification is approximately
 * {@code 128 * r * N} bytes &mdash; 32&nbsp;MiB at the defaults. The
 * upper bound (N=2^20, r=16) is deliberately tight at ≈ 2&nbsp;GiB so
 * a misconfiguration cannot trigger arbitrary memory allocation
 * (CWE-400 / CWE-770).</p>
 */
public final class ScryptDefaults {

  public static final int DEFAULT_N = 32_768;          // 2^15
  public static final int DEFAULT_R = 8;
  public static final int DEFAULT_P = 1;
  public static final int DEFAULT_HASH_LENGTH = 32;
  public static final int DEFAULT_SALT_LENGTH = 16;

  public static final int MIN_N = 16_384;              // 2^14
  public static final int MAX_N = 1_048_576;           // 2^20
  public static final int MIN_R = 4;
  public static final int MAX_R = 16;
  public static final int MIN_P = 1;
  public static final int MAX_P = 8;
  public static final int MIN_HASH_LENGTH = 32;
  public static final int MAX_HASH_LENGTH = 64;
  public static final int MIN_SALT_LENGTH = 12;
  public static final int MAX_SALT_LENGTH = 64;

  private ScryptDefaults() { }

  public static Map<String, String> defaultParameters() {
    Map<String, String> m = new LinkedHashMap<>();
    m.put(ScryptParameterNames.N, Integer.toString(DEFAULT_N));
    m.put(ScryptParameterNames.R, Integer.toString(DEFAULT_R));
    m.put(ScryptParameterNames.P, Integer.toString(DEFAULT_P));
    m.put(ScryptParameterNames.HASH_LENGTH, Integer.toString(DEFAULT_HASH_LENGTH));
    return m;
  }

  public static Map<String, String> minimumParameters() {
    Map<String, String> m = new LinkedHashMap<>();
    m.put(ScryptParameterNames.N, Integer.toString(MIN_N));
    m.put(ScryptParameterNames.R, Integer.toString(MIN_R));
    m.put(ScryptParameterNames.P, Integer.toString(MIN_P));
    m.put(ScryptParameterNames.HASH_LENGTH, Integer.toString(MIN_HASH_LENGTH));
    m.put(ScryptParameterNames.SALT_LENGTH, Integer.toString(MIN_SALT_LENGTH));
    return m;
  }

  public static Map<String, String> maximumParameters() {
    Map<String, String> m = new LinkedHashMap<>();
    m.put(ScryptParameterNames.N, Integer.toString(MAX_N));
    m.put(ScryptParameterNames.R, Integer.toString(MAX_R));
    m.put(ScryptParameterNames.P, Integer.toString(MAX_P));
    m.put(ScryptParameterNames.HASH_LENGTH, Integer.toString(MAX_HASH_LENGTH));
    m.put(ScryptParameterNames.SALT_LENGTH, Integer.toString(MAX_SALT_LENGTH));
    return m;
  }

  public static PasswordHashPolicy referencePolicy() {
    return DefaultPasswordHashPolicy.builder()
        .policyVersion(1)
        .preferredAlgorithm(ScryptParameterNames.ALGORITHM)
        .preferredProviderId(ScryptParameterNames.PROVIDER_ID)
        .defaultParameters(ScryptParameterNames.ALGORITHM, defaultParameters())
        .minimumParameters(ScryptParameterNames.ALGORITHM, minimumParameters())
        .maximumParameters(ScryptParameterNames.ALGORITHM, maximumParameters())
        .build();
  }
}
