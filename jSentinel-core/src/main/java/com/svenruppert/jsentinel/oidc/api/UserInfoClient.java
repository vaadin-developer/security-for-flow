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
package com.svenruppert.jsentinel.oidc.api;

import com.svenruppert.functional.result.Result;
import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.oauth2.api.OAuth2Error;

/**
 * Pulls claims from the OIDC UserInfo endpoint with the access token (OIDC Core
 * §5.3, V00.78). The HTTP implementation ({@code jSentinel-identity-oidc}) sends a
 * Bearer-authenticated GET, optionally validates a signed-JWT UserInfo response via
 * the {@code JwtValidator}, and may cache by access-token hash. JOSE-free contract;
 * reuses the OAuth2 transport error type.
 *
 * @since 00.78.00
 */
@ExperimentalJSentinelApi
public interface UserInfoClient {

  /**
   * Fetches the UserInfo claims for {@code accessToken}.
   *
   * @param accessToken the OAuth2 access token (never logged)
   * @return the UserInfo claims, or a non-secret {@link OAuth2Error}
   */
  Result<UserInfoResponse, OAuth2Error> fetch(String accessToken);
}
