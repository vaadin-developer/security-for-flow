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

import java.util.Map;

/**
 * Pushes an authorization request to the provider's
 * {@code pushed_authorization_request_endpoint} (V00.79, RFC 9126). The full set of
 * authorization-request parameters is POSTed (with client authentication) to the PAR
 * endpoint; the response is a short-lived {@code request_uri} the client then sends on
 * the browser redirect — so the parameters never appear in the browser URL / history and
 * cannot be tampered with in transit.
 *
 * @since 00.79.20
 */
@ExperimentalJSentinelApi
public interface PushedAuthorizationRequestClient {

  Result<PushedAuthorizationResponse, OAuth2Error> push(Map<String, String> authorizationRequestParams);
}
