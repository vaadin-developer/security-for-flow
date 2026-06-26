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

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;

import java.util.Objects;

/**
 * A PKCE code challenge (RFC 7636) sent on the authorization request (V00.77).
 * jSentinel only emits {@code S256} — {@code plain} is deliberately unsupported.
 *
 * @param codeChallenge the {@code code_challenge} value
 * @param method        always {@code "S256"}
 * @since 00.77.00
 */
@ExperimentalJSentinelApi
public record PkceChallenge(String codeChallenge, String method) {

  public PkceChallenge {
    Objects.requireNonNull(codeChallenge, "codeChallenge");
    if (!"S256".equals(method)) {
      throw new IllegalArgumentException("only the S256 PKCE method is supported, got: " + method);
    }
  }
}
