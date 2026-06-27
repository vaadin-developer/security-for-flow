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

import java.time.Duration;
import java.util.Objects;

/**
 * The successful result of a Pushed Authorization Request (V00.79, RFC 9126 §2.2): the
 * opaque {@code request_uri} (a {@code urn:ietf:params:oauth:request_uri:…}) the client
 * then puts on the authorization-endpoint redirect, plus its lifetime.
 *
 * @since 00.79.20
 */
@ExperimentalJSentinelApi
public record PushedAuthorizationResponse(String requestUri, Duration expiresIn) {

  public PushedAuthorizationResponse {
    Objects.requireNonNull(requestUri, "requestUri");
    Objects.requireNonNull(expiresIn, "expiresIn");
    if (requestUri.isBlank()) {
      throw new IllegalArgumentException("requestUri must not be blank");
    }
  }
}
