/*-
 * #%L
 * Security Crypto — BouncyCastle
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */
package eu.jsentinel.jcustos.credential.password.bouncycastle.scrypt;

import eu.jsentinel.jcustos.credential.password.policy.DefaultPasswordHashPolicy;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashPolicy;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Phase-1b reference parameters for the scrypt password hashing path.
 *
 * <p>Defaults follow the OWASP Password Storage Cheat Sheet minimum for
 * interactive logins (R044):</p>
 * <ul>
 *   <li>N = 2^17 = 131&nbsp;072 (CPU/memory cost; OWASP minimum)</li>
 *   <li>r = 8 (block size; standard)</li>
 *   <li>p = 1 (parallelism)</li>
 *   <li>l = 32-byte derived key</li>
 *   <li>16-byte random salt</li>
 * </ul>
 *
 * <p>Memory consumed by a single verification is approximately
 * {@code 128 * r * N} bytes &mdash; 128&nbsp;MiB at the defaults. The
 * upper bound (N=2^20, r=16) is deliberately tight at ≈ 2&nbsp;GiB so
 * a misconfiguration cannot trigger arbitrary memory allocation
 * (CWE-400 / CWE-770).</p>
 */
public final class ScryptDefaults {

  public static final int DEFAULT_N = 131_072;         // 2^17 (OWASP minimum)
  public static final int DEFAULT_R = 8;
  public static final int DEFAULT_P = 1;
  public static final int DEFAULT_HASH_LENGTH = 32;
  public static final int DEFAULT_SALT_LENGTH = 16;

  // R044: OWASP scrypt minimum is N=2^17 (131072) with r=8, p=1. The previous
  // 2^14 floor (and 2^15 default) were below that; both are raised to 2^17.
  // Below-floor stored hashes are rehashed on the next successful verify.
  public static final int MIN_N = 131_072;             // 2^17 (OWASP minimum)
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
