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

/**
 * Validates an OIDC Back-Channel Logout token (V00.79). Validates the JWT (signature,
 * issuer, audience, iat), confirms the {@code events} back-channel-logout member,
 * requires {@code sub} and/or {@code sid}, rejects a present {@code nonce}, and enforces
 * single-use of {@code jti}. Failures are returned, never thrown.
 *
 * @since 00.79.10
 */
@ExperimentalJSentinelApi
public interface LogoutTokenValidator {

  Result<BackChannelLogoutToken, LogoutTokenValidationError> validate(String compactLogoutToken);
}
