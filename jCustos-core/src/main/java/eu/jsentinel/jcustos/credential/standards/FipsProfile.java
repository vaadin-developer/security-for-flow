/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
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
package eu.jsentinel.jcustos.credential.standards;

/**
 * Operator-declared FIPS operating profile.
 *
 * <p>This is an <strong>advisory</strong> configuration record. The
 * framework does not auto-detect FIPS mode, does not switch providers,
 * and does not change algorithm selection based on this value. Its
 * purpose is to give operators one explicit place to declare the
 * intent of the deployment, suitable for inclusion in audit logs and
 * static configuration checks.</p>
 *
 * <p>See {@code docs/security/credentials/standards/fips-profile.md}
 * for the position statement and the operator checklist that this
 * record is paired with.</p>
 *
 * @param strictMode             if {@code true}, only FIPS-acceptable
 *                               algorithms are permitted at the
 *                               operator's decision boundary
 * @param allowsArgon2           Argon2id (BouncyCastle) — never
 *                               FIPS-validated as of FIPS 140-3
 * @param allowsBcrypt           bcrypt (BouncyCastle) — never
 *                               FIPS-validated
 * @param allowsScrypt           scrypt (BouncyCastle) — never
 *                               FIPS-validated
 * @param allowsHibpSha1Prefix   the HIBP k-anonymity protocol
 *                               computes a SHA-1 digest of the
 *                               candidate; SHA-1 is deprecated in
 *                               FIPS 180-4 §6 for hashing — set
 *                               {@code false} in strict deployments
 */
public record FipsProfile(
    boolean strictMode,
    boolean allowsArgon2,
    boolean allowsBcrypt,
    boolean allowsScrypt,
    boolean allowsHibpSha1Prefix) {

  /**
   * Permissive default: no FIPS claims. All algorithm modules
   * are allowed; the deployment makes no statement about FIPS
   * mode at all.
   */
  public static FipsProfile permissive() {
    return new FipsProfile(false, true, true, true, true);
  }

  /**
   * Strict default: only FIPS-acceptable algorithms are allowed.
   * Argon2, bcrypt, scrypt and HIBP SHA-1 prefix are forbidden.
   * The JDK distribution and {@code java.security} configuration
   * still have to be operator-verified — this record does not
   * verify them.
   */
  public static FipsProfile strict() {
    return new FipsProfile(true, false, false, false, false);
  }
}
