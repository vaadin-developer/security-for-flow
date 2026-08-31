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

import java.net.URI;

/**
 * Builds the OIDC RP-Initiated Logout 1.0 redirect URL (V00.78): the
 * {@code end_session_endpoint} with {@code id_token_hint} +
 * {@code post_logout_redirect_uri} + {@code state}. Pure URL construction — no
 * network call; the adapter performs the browser redirect. The implementation
 * lives in {@code jCustos-identity-oidc}.
 *
 * @since 00.78.00
 */
public interface LogoutInitiator {

  /**
   * Builds the logout redirect URL.
   *
   * @param endSessionEndpoint the OP {@code end_session_endpoint}
   * @param request            the logout parameters
   * @return the absolute redirect URL the browser should be sent to
   */
  URI buildLogoutUri(URI endSessionEndpoint, LogoutRequest request);
}
