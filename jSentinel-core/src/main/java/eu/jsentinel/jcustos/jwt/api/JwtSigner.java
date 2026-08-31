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

import java.util.Map;

/**
 * Signs a JWS (V00.77, B2) — the counterpart to the V00.76 {@code JwtValidator}.
 *
 * <p>The framework needs JWT <em>signing</em> for OAuth2 {@code private_key_jwt}
 * client authentication (RFC 7523): a client proves its identity to the token
 * endpoint with a short-lived, asymmetrically-signed assertion. V00.76 shipped
 * only validation; this SPI adds the signing seam. It is JOSE-free (the Nimbus
 * implementation lives in {@code jCustos-jwt} and is discovered via
 * {@code ServiceLoader} / {@code @JCustosAutoService}), so callers in
 * {@code jCustos-oauth2} depend only on this contract.
 *
 * <p>Implementations sign only with the asymmetric, allow-listed algorithm
 * families ({@link JwsAlgorithm}); {@code alg:none} and HMAC are impossible by
 * construction. The key material is never logged.
 *
 * @since 00.77.00
 */
public interface JwtSigner {

  /**
   * Signs {@code claims} into a compact JWS using {@code key}.
   *
   * <p>The {@code alg} (and {@code kid} when {@link JwtSigningKey#keyId()} is
   * present) JOSE header is set from {@code key}; {@code typ} is set to
   * {@code "JWT"}. The caller supplies the full claim set (for a client
   * assertion: {@code iss}, {@code sub}, {@code aud}, {@code exp}, {@code iat},
   * {@code jti}). Numeric date claims must be epoch-seconds {@code Long}s.
   *
   * @param claims the JWT claims to sign; non-null, non-empty
   * @param key    the signing key + algorithm
   * @return the compact serialized JWS ({@code header.payload.signature})
   * @throws JwtSigningException if the key/algorithm is unusable or signing fails
   */
  String sign(Map<String, Object> claims, JwtSigningKey key);
}
