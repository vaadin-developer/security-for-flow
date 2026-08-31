/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package eu.jsentinel.jcustos.jwt.api;

import java.security.PrivateKey;
import java.util.Objects;
import java.util.Optional;

/**
 * A private signing key plus the JWS algorithm to use with it (V00.77, B2).
 *
 * <p>{@link JwsAlgorithm} is asymmetric-only (RS/PS/ES/EdDSA) — the same
 * allow-listed family the V00.76 validator accepts — so this type cannot carry
 * an {@code alg:none} or an HMAC algorithm. The optional {@code keyId} becomes
 * the {@code kid} JOSE header when present (so a relying party can publish a
 * matching JWKS entry).
 *
 * @param privateKey the asymmetric private key; never logged or serialized
 * @param algorithm  the JWS algorithm (must match the key family)
 * @param keyId      optional {@code kid} header value
 * @since 00.77.00
 */
public record JwtSigningKey(PrivateKey privateKey, JwsAlgorithm algorithm, Optional<String> keyId) {

  public JwtSigningKey {
    Objects.requireNonNull(privateKey, "privateKey");
    Objects.requireNonNull(algorithm, "algorithm");
    Objects.requireNonNull(keyId, "keyId");
  }

  /** Convenience: a signing key without a {@code kid}. */
  public static JwtSigningKey of(PrivateKey privateKey, JwsAlgorithm algorithm) {
    return new JwtSigningKey(privateKey, algorithm, Optional.empty());
  }

  /** Convenience: a signing key with a {@code kid}. */
  public static JwtSigningKey of(PrivateKey privateKey, JwsAlgorithm algorithm, String keyId) {
    return new JwtSigningKey(privateKey, algorithm, Optional.of(keyId));
  }

  /** Never expose the key material. */
  @Override
  public String toString() {
    return "JwtSigningKey[algorithm=" + algorithm
        + ", keyId=" + keyId.orElse("<none>") + ", privateKey=***]";
  }
}
