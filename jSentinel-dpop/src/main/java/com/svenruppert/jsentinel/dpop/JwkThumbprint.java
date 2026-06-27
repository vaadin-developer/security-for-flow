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
package com.svenruppert.jsentinel.dpop;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;

import java.util.Objects;

/**
 * A JWK SHA-256 thumbprint (RFC 7638), base64url-encoded without padding (V00.79).
 * This is the value carried in a DPoP-bound access token's {@code cnf.jkt} claim
 * (RFC 9449 §6) and recomputed from the DPoP proof's embedded public key during
 * validation; the two MUST match for the proof to bind to the token.
 *
 * @since 00.79.10
 */
@ExperimentalJSentinelApi
public record JwkThumbprint(String value) {

  public JwkThumbprint {
    Objects.requireNonNull(value, "value");
    if (value.isBlank()) {
      throw new IllegalArgumentException("thumbprint value must not be blank");
    }
  }
}
