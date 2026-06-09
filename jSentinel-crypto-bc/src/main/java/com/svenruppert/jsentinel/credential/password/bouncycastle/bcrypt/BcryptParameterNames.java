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
package com.svenruppert.jsentinel.credential.password.bouncycastle.bcrypt;

import com.svenruppert.jsentinel.credential.password.bouncycastle.BouncyCastleModuleInfo;

/**
 * Stable wire-format parameter names for the bcrypt envelope.
 *
 * <p>Phase-1b stores the bcrypt salt and derived bytes as base64 inside
 * the standard Phase-1a envelope rather than wrapping the OpenBSD MCF
 * string verbatim — the MCF format uses {@code $} as a field separator,
 * which collides with the Phase-1a envelope separator.</p>
 */
public final class BcryptParameterNames {

  public static final String ALGORITHM = BouncyCastleModuleInfo.BCRYPT_ALGORITHM;
  public static final String PROVIDER_ID = BouncyCastleModuleInfo.BCRYPT_PROVIDER_ID;

  /** bcrypt cost factor (log2 of the number of rounds). */
  public static final String COST = "c";

  /** Base64-encoded 16-byte salt. */
  public static final String SALT = "s";

  /**
   * bcrypt's hard 72-byte input limit on the UTF-8 representation of the
   * password. Inputs longer than this are silently truncated by the
   * bcrypt algorithm itself; this provider rejects them explicitly.
   */
  public static final int MAX_PASSWORD_BYTES = 72;

  /** Fixed bcrypt salt length in bytes. */
  public static final int SALT_BYTES = 16;

  /** Fixed bcrypt derived-key length in bytes. */
  public static final int DERIVED_BYTES = 24;

  private BcryptParameterNames() { }
}
