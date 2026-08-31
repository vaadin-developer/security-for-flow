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
package eu.jsentinel.jcustos.credential.password.bouncycastle;

/**
 * Module identity surface for {@code security-crypto-bc}.
 *
 * <p>Used by tests and operator tooling to verify that the optional
 * BouncyCastle module is on the classpath without depending on any
 * specific provider implementation. Concrete providers (Argon2id,
 * bcrypt, scrypt) arrive with Prompts 010, 011 and 012 and register
 * themselves through {@code META-INF/services}.</p>
 */
public final class BouncyCastleModuleInfo {

  /**
   * Stable identifier reported by this module.
   */
  public static final String MODULE_ID = "security-crypto-bc";

  /**
   * Provider id values reserved for the Phase-1b providers. Listed
   * here so the modern-profile wiring helper in this module can refer
   * to them before the concrete provider classes are introduced in
   * later prompts.
   */
  public static final String ARGON2ID_PROVIDER_ID = "argon2id-bc";
  public static final String BCRYPT_PROVIDER_ID = "bcrypt-bc";
  public static final String SCRYPT_PROVIDER_ID = "scrypt-bc";

  /**
   * Canonical algorithm identifiers reserved for the Phase-1b
   * providers. Used by the policy validator and codec round-trip.
   */
  public static final String ARGON2ID_ALGORITHM = "Argon2id";
  public static final String BCRYPT_ALGORITHM = "bcrypt";
  public static final String SCRYPT_ALGORITHM = "scrypt";

  private BouncyCastleModuleInfo() {
  }
}
