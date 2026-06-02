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
package com.svenruppert.vaadin.security.credential.password.bouncycastle.argon2;

import com.svenruppert.vaadin.security.credential.password.bouncycastle.BouncyCastleModuleInfo;

/**
 * Stable wire-format parameter names for the Argon2id envelope.
 *
 * <p>The names match the RFC&nbsp;9106 short forms so the encoded
 * envelope stays readable: {@code t} (time cost / iterations),
 * {@code m} (memory in KiB), {@code p} (parallelism / lanes),
 * {@code l} (derived hash length in bytes), {@code s} (base64 salt),
 * {@code sl} (salt length in bytes, used only for min/max bounds).</p>
 */
public final class Argon2idParameterNames {

  public static final String ALGORITHM = BouncyCastleModuleInfo.ARGON2ID_ALGORITHM;
  public static final String PROVIDER_ID = BouncyCastleModuleInfo.ARGON2ID_PROVIDER_ID;

  /** Iteration count (time cost). */
  public static final String ITERATIONS = "t";

  /** Memory cost in KiB. */
  public static final String MEMORY_KIB = "m";

  /** Parallelism (lanes). */
  public static final String PARALLELISM = "p";

  /** Output hash length in bytes. */
  public static final String HASH_LENGTH = "l";

  /** Base64-encoded salt. */
  public static final String SALT = "s";

  /** Salt length in bytes; only used by the min/max bounds. */
  public static final String SALT_LENGTH = "sl";

  private Argon2idParameterNames() { }
}
