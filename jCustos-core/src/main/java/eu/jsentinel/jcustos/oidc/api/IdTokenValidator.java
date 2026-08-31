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
package eu.jsentinel.jcustos.oidc.api;

import com.svenruppert.functional.result.Result;

/**
 * Validates an OIDC ID token (V00.78). Runs the JWT-standard validation (signature
 * via the V00.76 {@code JwtValidator} SPI, plus exp / iss / aud) and then the
 * OIDC-specific checks (nonce, azp, at_hash, c_hash, auth_time/max_age, acr) per
 * OIDC Core §3.1.3.7. The implementation lives in {@code jCustos-identity-oidc}
 * and <em>composes</em> a {@code JwtValidator} (it does not subtype the Nimbus
 * validator). JOSE-free contract.
 *
 * @since 00.78.00
 */
public interface IdTokenValidator {

  /**
   * Validates {@code compactIdToken} against {@code expectations}.
   *
   * @param compactIdToken the compact-serialized ID token (never logged)
   * @param expectations   the issuer / audience / nonce / hash / acr expectations
   * @return the validated ID token, or a non-secret {@link IdTokenValidationError}
   */
  Result<ValidatedIdToken, IdTokenValidationError> validate(
      String compactIdToken, IdTokenExpectations expectations);
}
