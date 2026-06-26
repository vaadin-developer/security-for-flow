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
package com.svenruppert.jsentinel.oauth2.api;

import com.svenruppert.functional.result.Result;
import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;

/**
 * Token revocation (RFC 7009, V00.77) — the RP explicitly invalidates one of its
 * own tokens (logout cleanup, theft recovery). JOSE-free; the HTTP implementation
 * lives in {@code jSentinel-oauth2}.
 *
 * @since 00.77.00
 */
@ExperimentalJSentinelApi
public interface RevocationClient {

  /**
   * Revokes {@code token}. RFC 7009 mandates a {@code 200} for an unknown token
   * too, so success means "the server accepted the revocation request".
   *
   * @param token the token to revoke (never logged)
   * @param hint  the token-type hint
   * @return success, or a non-secret {@link OAuth2Error}
   */
  Result<Boolean, OAuth2Error> revoke(String token, TokenTypeHint hint);
}
