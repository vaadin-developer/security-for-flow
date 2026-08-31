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
package eu.jsentinel.jcustos.credential.password.bouncycastle.scrypt;

import eu.jsentinel.jcustos.credential.password.bouncycastle.BouncyCastleModuleInfo;

/**
 * Stable wire-format parameter names for the scrypt envelope.
 *
 * <p>Wire keys are intentionally short and follow the RFC&nbsp;7914
 * letters: {@code n} (CPU/memory cost, stored as the raw decimal
 * value &mdash; not as the {@code log2} exponent), {@code r} (block
 * size), {@code p} (parallelism), {@code l} (derived-key length in
 * bytes), {@code s} (base64 salt), {@code sl} (salt length in bytes,
 * only used by the min/max bounds).</p>
 */
public final class ScryptParameterNames {

  public static final String ALGORITHM = BouncyCastleModuleInfo.SCRYPT_ALGORITHM;
  public static final String PROVIDER_ID = BouncyCastleModuleInfo.SCRYPT_PROVIDER_ID;

  /** CPU/memory cost; must be a power of two greater than 1. */
  public static final String N = "n";

  /** Block size. */
  public static final String R = "r";

  /** Parallelism. */
  public static final String P = "p";

  /** Output hash length in bytes. */
  public static final String HASH_LENGTH = "l";

  /** Base64-encoded salt. */
  public static final String SALT = "s";

  /** Salt length in bytes; only used by the min/max bounds. */
  public static final String SALT_LENGTH = "sl";

  private ScryptParameterNames() { }
}
