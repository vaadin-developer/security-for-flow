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

import java.net.URI;
import java.time.Instant;
import java.util.Objects;

/**
 * The result of a successful DPoP-proof validation (V00.79): the key thumbprint the
 * proof is signed with (compare against the access token's {@code cnf.jkt}), the bound
 * HTTP method + URI, the single-use {@code jti}, and the proof's issue time.
 *
 * @since 00.79.10
 */
@ExperimentalJSentinelApi
public record ValidatedDpopProof(
    JwkThumbprint thumbprint,
    String httpMethod,
    URI httpUri,
    String jti,
    Instant issuedAt) {

  public ValidatedDpopProof {
    Objects.requireNonNull(thumbprint, "thumbprint");
    Objects.requireNonNull(httpMethod, "httpMethod");
    Objects.requireNonNull(httpUri, "httpUri");
    Objects.requireNonNull(jti, "jti");
    Objects.requireNonNull(issuedAt, "issuedAt");
  }

  /**
   * True if this proof binds to an access token whose confirmation thumbprint
   * ({@code cnf.jkt}) equals this proof's key thumbprint (RFC 9449 §6.1).
   */
  public boolean confirms(JwkThumbprint accessTokenCnfJkt) {
    return thumbprint.equals(accessTokenCnfJkt);
  }
}
