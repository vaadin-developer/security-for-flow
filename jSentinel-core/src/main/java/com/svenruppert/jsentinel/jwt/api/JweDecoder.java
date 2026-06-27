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
package com.svenruppert.jsentinel.jwt.api;

import com.svenruppert.functional.result.Result;
import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;

import java.security.PrivateKey;

/**
 * Decrypts a compact JWE ({@code JWE(JWS(payload))}) to its inner compact JWS so the
 * existing {@link JwtValidator} can verify it (V00.79, RFC 7516). Some IdPs (e.g. Entra
 * Conditional Access) deliver encrypted ID tokens. The decoder enforces a
 * {@link JweAlgorithmAllowList} on the {@code alg}/{@code enc} header BEFORE attempting
 * decryption, so a downgrade ({@code RSA1_5} / {@code dir}) is rejected outright.
 * Failures are returned as {@link JweDecodingError}, never thrown, and never echo the
 * ciphertext or key.
 *
 * @since 00.79.20
 */
@ExperimentalJSentinelApi
public interface JweDecoder {

  /**
   * Decrypts {@code jweCompact} with {@code decryptionKey} and returns the inner compact
   * JWS, or a {@link JweDecodingError}.
   */
  Result<String, JweDecodingError> decode(String jweCompact, PrivateKey decryptionKey);
}
